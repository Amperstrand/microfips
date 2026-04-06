#![no_std]

extern crate alloc;

use core::str;

use microfips_core::fsp::FSP_MSG_DATA;
use microfips_protocol::fsp_handler::{FspAppHandler, FspAppResult};

pub const SERVICE_VERSION: u8 = 1;
pub const SERVICE_KIND_REQUEST: u8 = 1;
pub const SERVICE_KIND_RESPONSE: u8 = 2;
pub const SERVICE_REQUEST_HEADER_LEN: usize = 8;
pub const SERVICE_RESPONSE_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ServiceMethod {
    Get = 1,
    Post = 2,
    Put = 3,
    Delete = 4,
}

impl ServiceMethod {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Get),
            2 => Some(Self::Post),
            3 => Some(Self::Put),
            4 => Some(Self::Delete),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    Binary = 0,
    Json = 1,
    Text = 2,
}

impl ContentType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Binary),
            1 => Some(Self::Json),
            2 => Some(Self::Text),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceStatus(u16);

impl ServiceStatus {
    pub const OK: Self = Self(200);
    pub const CREATED: Self = Self(201);
    pub const BAD_REQUEST: Self = Self(400);
    pub const NOT_FOUND: Self = Self(404);
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    pub const PAYLOAD_TOO_LARGE: Self = Self(413);
    pub const INTERNAL_ERROR: Self = Self(500);

    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceRequest<'a> {
    pub method: ServiceMethod,
    pub route: &'a str,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceResponse<'a> {
    pub status: ServiceStatus,
    pub content_type: ContentType,
    pub body: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceReply {
    pub status: ServiceStatus,
    pub content_type: ContentType,
    pub body_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceError {
    BufferTooSmall,
    InvalidEnvelope,
    InvalidVersion,
    InvalidKind,
    InvalidMethod,
    InvalidUtf8,
    NotFound,
    MethodNotAllowed,
}

impl ServiceError {
    pub fn status(self) -> ServiceStatus {
        match self {
            Self::BufferTooSmall => ServiceStatus::PAYLOAD_TOO_LARGE,
            Self::InvalidEnvelope
            | Self::InvalidVersion
            | Self::InvalidKind
            | Self::InvalidMethod
            | Self::InvalidUtf8 => ServiceStatus::BAD_REQUEST,
            Self::NotFound => ServiceStatus::NOT_FOUND,
            Self::MethodNotAllowed => ServiceStatus::METHOD_NOT_ALLOWED,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::BufferTooSmall => "response buffer too small",
            Self::InvalidEnvelope => "invalid service envelope",
            Self::InvalidVersion => "unsupported service envelope version",
            Self::InvalidKind => "unexpected service envelope kind",
            Self::InvalidMethod => "invalid service method",
            Self::InvalidUtf8 => "route is not valid utf-8",
            Self::NotFound => "route not found",
            Self::MethodNotAllowed => "method not allowed",
        }
    }
}

pub trait ServiceHandler {
    fn handle(
        &mut self,
        request: ServiceRequest<'_>,
        response: &mut [u8],
    ) -> Result<ServiceReply, ServiceError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMatch {
    Exact(&'static str),
    Prefix(&'static str),
}

impl RouteMatch {
    fn matches(self, route: &str) -> bool {
        match self {
            Self::Exact(expected) => route == expected,
            Self::Prefix(prefix) => route.starts_with(prefix),
        }
    }
}

pub type RouteHandler = fn(ServiceRequest<'_>, &mut [u8]) -> Result<ServiceReply, ServiceError>;

#[derive(Debug, Clone, Copy)]
pub struct Route {
    pub method: ServiceMethod,
    pub matcher: RouteMatch,
    pub handler: RouteHandler,
}

#[derive(Debug, Clone, Copy)]
pub struct Router<'a> {
    routes: &'a [Route],
}

impl<'a> Router<'a> {
    pub const fn new(routes: &'a [Route]) -> Self {
        Self { routes }
    }
}

impl ServiceHandler for Router<'_> {
    fn handle(
        &mut self,
        request: ServiceRequest<'_>,
        response: &mut [u8],
    ) -> Result<ServiceReply, ServiceError> {
        let mut method_seen = false;
        for route in self.routes {
            if route.matcher.matches(request.route) {
                if route.method == request.method {
                    return (route.handler)(request, response);
                }
                method_seen = true;
            }
        }

        if method_seen {
            Err(ServiceError::MethodNotAllowed)
        } else {
            Err(ServiceError::NotFound)
        }
    }
}

pub fn encode_request(
    method: ServiceMethod,
    route: &str,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, ServiceError> {
    let route_bytes = route.as_bytes();
    let total = SERVICE_REQUEST_HEADER_LEN + route_bytes.len() + payload.len();
    if out.len() < total
        || route_bytes.len() > u16::MAX as usize
        || payload.len() > u16::MAX as usize
    {
        return Err(ServiceError::BufferTooSmall);
    }

    out[0] = SERVICE_VERSION;
    out[1] = SERVICE_KIND_REQUEST;
    out[2] = method.as_u8();
    out[3] = 0;
    out[4..6].copy_from_slice(&(route_bytes.len() as u16).to_le_bytes());
    out[6..8].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    out[SERVICE_REQUEST_HEADER_LEN..SERVICE_REQUEST_HEADER_LEN + route_bytes.len()]
        .copy_from_slice(route_bytes);
    out[SERVICE_REQUEST_HEADER_LEN + route_bytes.len()..total].copy_from_slice(payload);
    Ok(total)
}

pub fn decode_request(data: &[u8]) -> Result<ServiceRequest<'_>, ServiceError> {
    if data.len() < SERVICE_REQUEST_HEADER_LEN {
        return Err(ServiceError::InvalidEnvelope);
    }
    if data[0] != SERVICE_VERSION {
        return Err(ServiceError::InvalidVersion);
    }
    if data[1] != SERVICE_KIND_REQUEST {
        return Err(ServiceError::InvalidKind);
    }
    let method = ServiceMethod::from_u8(data[2]).ok_or(ServiceError::InvalidMethod)?;
    let route_len = u16::from_le_bytes([data[4], data[5]]) as usize;
    let payload_len = u16::from_le_bytes([data[6], data[7]]) as usize;
    let total = SERVICE_REQUEST_HEADER_LEN + route_len + payload_len;
    if data.len() < total {
        return Err(ServiceError::InvalidEnvelope);
    }
    let route_bytes = &data[SERVICE_REQUEST_HEADER_LEN..SERVICE_REQUEST_HEADER_LEN + route_len];
    let route = str::from_utf8(route_bytes).map_err(|_| ServiceError::InvalidUtf8)?;
    let payload = &data[SERVICE_REQUEST_HEADER_LEN + route_len..total];
    Ok(ServiceRequest {
        method,
        route,
        payload,
    })
}

pub fn encode_response(
    status: ServiceStatus,
    content_type: ContentType,
    body: &[u8],
    out: &mut [u8],
) -> Result<usize, ServiceError> {
    let total = SERVICE_RESPONSE_HEADER_LEN + body.len();
    if out.len() < total || body.len() > u16::MAX as usize {
        return Err(ServiceError::BufferTooSmall);
    }

    out[0] = SERVICE_VERSION;
    out[1] = SERVICE_KIND_RESPONSE;
    out[2..4].copy_from_slice(&status.as_u16().to_le_bytes());
    out[4] = content_type.as_u8();
    out[5] = 0;
    out[6..8].copy_from_slice(&(body.len() as u16).to_le_bytes());
    out[SERVICE_RESPONSE_HEADER_LEN..total].copy_from_slice(body);
    Ok(total)
}

pub fn decode_response(data: &[u8]) -> Result<ServiceResponse<'_>, ServiceError> {
    if data.len() < SERVICE_RESPONSE_HEADER_LEN {
        return Err(ServiceError::InvalidEnvelope);
    }
    if data[0] != SERVICE_VERSION {
        return Err(ServiceError::InvalidVersion);
    }
    if data[1] != SERVICE_KIND_RESPONSE {
        return Err(ServiceError::InvalidKind);
    }
    let status = ServiceStatus(u16::from_le_bytes([data[2], data[3]]));
    let content_type = ContentType::from_u8(data[4]).ok_or(ServiceError::InvalidEnvelope)?;
    let body_len = u16::from_le_bytes([data[6], data[7]]) as usize;
    let total = SERVICE_RESPONSE_HEADER_LEN + body_len;
    if data.len() < total {
        return Err(ServiceError::InvalidEnvelope);
    }
    Ok(ServiceResponse {
        status,
        content_type,
        body: &data[SERVICE_RESPONSE_HEADER_LEN..total],
    })
}

pub fn dispatch_request<H: ServiceHandler>(
    handler: &mut H,
    request_bytes: &[u8],
    response_bytes: &mut [u8],
) -> Result<usize, ServiceError> {
    let request = decode_request(request_bytes)?;
    if response_bytes.len() < SERVICE_RESPONSE_HEADER_LEN {
        return Err(ServiceError::BufferTooSmall);
    }
    let (header_buf, body_buf) = response_bytes.split_at_mut(SERVICE_RESPONSE_HEADER_LEN);
    match handler.handle(request, body_buf) {
        Ok(reply) => {
            if reply.body_len > body_buf.len() || reply.body_len > u16::MAX as usize {
                return Err(ServiceError::BufferTooSmall);
            }
            header_buf[0] = SERVICE_VERSION;
            header_buf[1] = SERVICE_KIND_RESPONSE;
            header_buf[2..4].copy_from_slice(&reply.status.as_u16().to_le_bytes());
            header_buf[4] = reply.content_type.as_u8();
            header_buf[5] = 0;
            header_buf[6..8].copy_from_slice(&(reply.body_len as u16).to_le_bytes());
            Ok(SERVICE_RESPONSE_HEADER_LEN + reply.body_len)
        }
        Err(err) => encode_response(
            err.status(),
            ContentType::Text,
            err.message().as_bytes(),
            response_bytes,
        ),
    }
}

pub struct FspServiceAdapter<H> {
    inner: H,
}

impl<H> FspServiceAdapter<H> {
    pub fn new(inner: H) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &H {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut H {
        &mut self.inner
    }
}

impl<H: ServiceHandler> FspAppHandler for FspServiceAdapter<H> {
    fn on_fsp_message(
        &mut self,
        msg_type: u8,
        payload: &[u8],
        response: &mut [u8],
    ) -> FspAppResult {
        if msg_type != FSP_MSG_DATA {
            return FspAppResult::None;
        }

        match dispatch_request(&mut self.inner, payload, response) {
            Ok(len) => FspAppResult::Reply {
                msg_type: FSP_MSG_DATA,
                len,
            },
            Err(err) => match encode_response(
                err.status(),
                ContentType::Text,
                err.message().as_bytes(),
                response,
            ) {
                Ok(len) => FspAppResult::Reply {
                    msg_type: FSP_MSG_DATA,
                    len,
                },
                Err(_) => FspAppResult::Disconnect,
            },
        }
    }
}

pub fn route_suffix<'a>(route: &'a str, prefix: &str) -> Option<&'a str> {
    route.strip_prefix(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use microfips_core::fmp;
    use microfips_core::fsp::{
        build_fsp_data_message, build_session_datagram_body, FspInitiatorSession,
        FspInitiatorState, SESSION_DATAGRAM_BODY_SIZE,
    };
    use microfips_core::identity::NodeAddr;
    use microfips_core::noise::{aead_decrypt, ecdh_pubkey, parity_normalize};
    use microfips_protocol::fsp_handler::FspDualHandler;
    use microfips_protocol::node::{HandleResult, NodeHandler};

    fn health_handler(
        _request: ServiceRequest<'_>,
        response: &mut [u8],
    ) -> Result<ServiceReply, ServiceError> {
        let body = br#"{"ok":true}"#;
        response[..body.len()].copy_from_slice(body);
        Ok(ServiceReply {
            status: ServiceStatus::OK,
            content_type: ContentType::Json,
            body_len: body.len(),
        })
    }

    #[test]
    fn request_round_trip() {
        let mut buf = [0u8; 128];
        let len = encode_request(ServiceMethod::Get, "/health", b"", &mut buf).unwrap();
        let req = decode_request(&buf[..len]).unwrap();
        assert_eq!(req.method, ServiceMethod::Get);
        assert_eq!(req.route, "/health");
        assert!(req.payload.is_empty());
    }

    #[test]
    fn router_dispatches_exact_and_prefix_routes() {
        fn prefix_handler(
            request: ServiceRequest<'_>,
            response: &mut [u8],
        ) -> Result<ServiceReply, ServiceError> {
            let suffix = route_suffix(request.route, "/rpc/").unwrap_or("");
            response[..suffix.len()].copy_from_slice(suffix.as_bytes());
            Ok(ServiceReply {
                status: ServiceStatus::OK,
                content_type: ContentType::Text,
                body_len: suffix.len(),
            })
        }

        let routes = [
            Route {
                method: ServiceMethod::Get,
                matcher: RouteMatch::Exact("/health"),
                handler: health_handler,
            },
            Route {
                method: ServiceMethod::Post,
                matcher: RouteMatch::Prefix("/rpc/"),
                handler: prefix_handler,
            },
        ];
        let mut router = Router::new(&routes);
        let mut body = [0u8; 64];
        let reply = router
            .handle(
                ServiceRequest {
                    method: ServiceMethod::Post,
                    route: "/rpc/ping",
                    payload: b"",
                },
                &mut body,
            )
            .unwrap();
        assert_eq!(reply.status, ServiceStatus::OK);
        assert_eq!(&body[..reply.body_len], b"ping");
    }

    #[test]
    fn dispatch_writes_error_response() {
        let routes = [Route {
            method: ServiceMethod::Get,
            matcher: RouteMatch::Exact("/health"),
            handler: health_handler,
        }];
        let mut router = Router::new(&routes);
        let mut req = [0u8; 64];
        let req_len = encode_request(ServiceMethod::Get, "/missing", b"", &mut req).unwrap();
        let mut resp = [0u8; 128];
        let resp_len = dispatch_request(&mut router, &req[..req_len], &mut resp).unwrap();
        let decoded = decode_response(&resp[..resp_len]).unwrap();
        assert_eq!(decoded.status, ServiceStatus::NOT_FOUND);
        assert_eq!(decoded.body, b"route not found");
    }

    #[test]
    fn service_round_trip_over_fsp_established_data() {
        let init_secret = [0x11; 32];
        let resp_secret = [0x22; 32];
        let init_pub = ecdh_pubkey(&init_secret).unwrap();
        let resp_pub = ecdh_pubkey(&resp_secret).unwrap();
        let init_addr =
            NodeAddr::from_pubkey_x(&parity_normalize(&init_pub)[1..].try_into().unwrap());
        let resp_addr =
            NodeAddr::from_pubkey_x(&parity_normalize(&resp_pub)[1..].try_into().unwrap());

        let routes = [Route {
            method: ServiceMethod::Get,
            matcher: RouteMatch::Exact("/health"),
            handler: health_handler,
        }];
        let mut responder: FspDualHandler<_, 256> = FspDualHandler::new_responder(
            resp_secret,
            [0x33; 32],
            FspServiceAdapter::new(Router::new(&routes)),
        );
        let mut initiator = FspInitiatorSession::new(&init_secret, &[0x44; 32], &resp_pub).unwrap();

        let mut setup = [0u8; 512];
        let setup_len = initiator
            .build_setup(init_addr.as_bytes(), resp_addr.as_bytes(), &mut setup)
            .unwrap();
        let mut setup_payload = [0u8; 512];
        setup_payload[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&build_session_datagram_body(
            init_addr.as_bytes(),
            resp_addr.as_bytes(),
        ));
        setup_payload[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + setup_len]
            .copy_from_slice(&setup[..setup_len]);

        let mut ack = [0u8; 512];
        let ack_len = match responder.on_message(
            fmp::MSG_SESSION_DATAGRAM,
            &setup_payload[..SESSION_DATAGRAM_BODY_SIZE + setup_len],
            &mut ack,
        ) {
            HandleResult::SendDatagram(len) => len,
            other => panic!("expected SessionAck, got {other:?}"),
        };
        initiator
            .handle_ack(&ack[SESSION_DATAGRAM_BODY_SIZE..ack_len])
            .unwrap();

        let mut msg3 = [0u8; 512];
        let msg3_len = initiator
            .build_msg3(&[0x02, 0, 0, 0, 0, 0, 0, 0], &mut msg3)
            .unwrap();
        let mut msg3_payload = [0u8; 512];
        msg3_payload[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&build_session_datagram_body(
            init_addr.as_bytes(),
            resp_addr.as_bytes(),
        ));
        msg3_payload[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + msg3_len]
            .copy_from_slice(&msg3[..msg3_len]);
        assert_eq!(
            responder.on_message(
                fmp::MSG_SESSION_DATAGRAM,
                &msg3_payload[..SESSION_DATAGRAM_BODY_SIZE + msg3_len],
                &mut ack,
            ),
            HandleResult::None
        );
        assert_eq!(initiator.state(), FspInitiatorState::Established);

        let (k_recv_i, k_send_i) = initiator.session_keys().unwrap();
        let mut service_request = [0u8; 128];
        let req_len =
            encode_request(ServiceMethod::Get, "/health", b"", &mut service_request).unwrap();
        let mut fsp_packet = [0u8; 256];
        let fsp_len = build_fsp_data_message(
            0,
            0,
            &service_request[..req_len],
            &k_send_i,
            &mut fsp_packet,
        )
        .unwrap();
        let mut request_payload = [0u8; 512];
        request_payload[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(
            &build_session_datagram_body(init_addr.as_bytes(), resp_addr.as_bytes()),
        );
        request_payload[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + fsp_len]
            .copy_from_slice(&fsp_packet[..fsp_len]);

        let mut response_payload = [0u8; 512];
        let response_len = match responder.on_message(
            fmp::MSG_SESSION_DATAGRAM,
            &request_payload[..SESSION_DATAGRAM_BODY_SIZE + fsp_len],
            &mut response_payload,
        ) {
            HandleResult::SendDatagram(len) => len,
            other => panic!("expected service reply, got {other:?}"),
        };

        let reply_fsp = &response_payload[SESSION_DATAGRAM_BODY_SIZE..response_len];
        let (_flags, counter, header, encrypted) =
            microfips_core::fsp::parse_fsp_encrypted_header(reply_fsp).unwrap();
        let mut decrypted = [0u8; 256];
        let decrypted_len =
            aead_decrypt(&k_recv_i, counter, header, encrypted, &mut decrypted).unwrap();
        let (_ts, msg_type, _flags, inner_payload) =
            microfips_core::fsp::fsp_strip_inner_header(&decrypted[..decrypted_len]).unwrap();
        assert_eq!(msg_type, FSP_MSG_DATA);
        let response = decode_response(inner_payload).unwrap();
        assert_eq!(response.status, ServiceStatus::OK);
        assert_eq!(response.body, br#"{"ok":true}"#);
    }
}
