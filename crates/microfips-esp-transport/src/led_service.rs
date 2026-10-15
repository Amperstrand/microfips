//! The bench showcase service: remote single-pixel LED control over the
//! mesh. `GET /led` reports state; `POST /led` with body `on` flashes the
//! ONE center pixel (brightness-capped, 2 s auto-off — see `matrix.rs`).
//! Any other body turns it off.

use microfips_service::{
    ContentType, ServiceHandler, ServiceMethod, ServiceReply, ServiceRequest, ServiceStatus,
};

use crate::matrix::{MatrixPixel, FLASH_MS, MAX_CHANNEL};

pub struct LedService<'d> {
    pixel: MatrixPixel<'d>,
}

impl<'d> LedService<'d> {
    pub fn new(pixel: MatrixPixel<'d>) -> Self {
        Self { pixel }
    }

    /// Called from the node handler tick so the hardware auto-off runs
    /// even when no further requests arrive.
    pub fn poll(&mut self) {
        self.pixel.poll();
    }

    fn status_json(&self, buf: &mut [u8]) -> usize {
        let (on, remaining) = (self.pixel.is_on(), self.pixel.remaining_ms());
        let mut n = 0;
        fn push(buf: &mut [u8], n: &mut usize, s: &str) {
            let b = s.as_bytes();
            let take = b.len().min(buf.len().saturating_sub(*n));
            buf[*n..*n + take].copy_from_slice(&b[..take]);
            *n += take;
        }
        fn push_u64(buf: &mut [u8], n: &mut usize, mut v: u64) {
            let mut tmp = [0u8; 20];
            let mut i = tmp.len();
            loop {
                i -= 1;
                tmp[i] = b'0' + (v % 10) as u8;
                v /= 10;
                if v == 0 {
                    break;
                }
            }
            push(buf, n, core::str::from_utf8(&tmp[i..]).unwrap_or("0"));
        }
        push(buf, &mut n, "{\"on\":");
        push(buf, &mut n, if on { "true" } else { "false" });
        push(buf, &mut n, ",\"remaining_ms\":");
        push_u64(buf, &mut n, remaining);
        push(buf, &mut n, ",\"cap\":");
        push_u64(buf, &mut n, MAX_CHANNEL as u64);
        push(buf, &mut n, ",\"flash_ms\":");
        push_u64(buf, &mut n, FLASH_MS);
        push(
            buf,
            &mut n,
            ",\"note\":\"single pixel, brightness-capped, auto-off enforced\"}",
        );
        n
    }
}

impl<'d> ServiceHandler for LedService<'d> {
    fn handle(
        &mut self,
        request: ServiceRequest<'_>,
        response: &mut [u8],
    ) -> Result<ServiceReply, microfips_service::ServiceError> {
        match (request.method, request.route) {
            (ServiceMethod::Get, "/led") => Ok(ServiceReply {
                status: ServiceStatus::OK,
                content_type: ContentType::Json,
                body_len: self.status_json(response),
            }),
            (ServiceMethod::Post, "/led") => {
                if request.payload.eq_ignore_ascii_case(b"on") {
                    self.pixel.flash();
                } else {
                    self.pixel.off();
                }
                Ok(ServiceReply {
                    status: ServiceStatus::OK,
                    content_type: ContentType::Json,
                    body_len: self.status_json(response),
                })
            }
            _ => Ok(ServiceReply {
                status: ServiceStatus::NOT_FOUND,
                content_type: ContentType::Text,
                body_len: 0,
            }),
        }
    }
}
