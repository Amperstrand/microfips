#![no_std]

use microfips_service::{
    route_suffix, ContentType, Route, RouteMatch, Router, ServiceError, ServiceHandler,
    ServiceMethod, ServiceReply, ServiceRequest, ServiceStatus,
};

const HEALTH_JSON: &[u8] = br#"{"ok":true,"transport":"fips","adapter":"service"}"#;
const INFO_JSON: &[u8] =
    br#"{"name":"microfips-http-demo","protocol":"microfips-service","http":"optional"}"#;
const KEYS_JSON: &[u8] =
    br#"{"keysets":[{"id":"demo-keyset","unit":"sat","keys":{"1":"02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]}"#;
const KEYSETS_JSON: &[u8] = br#"{"keysets":[{"id":"demo-keyset","unit":"sat","active":true}]}"#;
const MINT_QUOTE_JSON: &[u8] =
    br#"{"quote":"mint-quote-demo","request":"lnbc1demo","paid":false,"expiry":1735689600}"#;
const MELT_QUOTE_JSON: &[u8] =
    br#"{"quote":"melt-quote-demo","amount":21,"fee_reserve":1,"paid":false,"expiry":1735689600}"#;
const MINT_RESULT_JSON: &[u8] = br#"{"signatures":[],"quote":"mint-quote-demo","paid":true}"#;
const MELT_RESULT_JSON: &[u8] = br#"{"paid":true,"preimage":"demo-preimage","change":[]}"#;
const SWAP_RESULT_JSON: &[u8] = br#"{"signatures":[]}"#;

pub fn demo_routes() -> &'static [Route] {
    &[
        Route {
            method: ServiceMethod::Get,
            matcher: RouteMatch::Exact("/health"),
            handler: health,
        },
        Route {
            method: ServiceMethod::Get,
            matcher: RouteMatch::Exact("/info"),
            handler: info,
        },
        Route {
            method: ServiceMethod::Post,
            matcher: RouteMatch::Exact("/echo"),
            handler: echo,
        },
        Route {
            method: ServiceMethod::Post,
            matcher: RouteMatch::Prefix("/rpc/"),
            handler: rpc,
        },
        Route {
            method: ServiceMethod::Get,
            matcher: RouteMatch::Exact("/v1/info"),
            handler: cashu_info,
        },
        Route {
            method: ServiceMethod::Get,
            matcher: RouteMatch::Exact("/v1/keys"),
            handler: cashu_keys,
        },
        Route {
            method: ServiceMethod::Get,
            matcher: RouteMatch::Exact("/v1/keysets"),
            handler: cashu_keysets,
        },
        Route {
            method: ServiceMethod::Post,
            matcher: RouteMatch::Exact("/v1/mint/quote/bolt11"),
            handler: mint_quote_create,
        },
        Route {
            method: ServiceMethod::Get,
            matcher: RouteMatch::Prefix("/v1/mint/quote/bolt11/"),
            handler: mint_quote_get,
        },
        Route {
            method: ServiceMethod::Post,
            matcher: RouteMatch::Exact("/v1/mint/bolt11"),
            handler: mint_tokens,
        },
        Route {
            method: ServiceMethod::Post,
            matcher: RouteMatch::Exact("/v1/melt/quote/bolt11"),
            handler: melt_quote_create,
        },
        Route {
            method: ServiceMethod::Get,
            matcher: RouteMatch::Prefix("/v1/melt/quote/bolt11/"),
            handler: melt_quote_get,
        },
        Route {
            method: ServiceMethod::Post,
            matcher: RouteMatch::Exact("/v1/melt/bolt11"),
            handler: melt_tokens,
        },
        Route {
            method: ServiceMethod::Post,
            matcher: RouteMatch::Exact("/v1/swap"),
            handler: swap_tokens,
        },
    ]
}

pub struct DemoService {
    router: Router<'static>,
}

impl DemoService {
    pub fn new() -> Self {
        Self {
            router: Router::new(demo_routes()),
        }
    }
}

impl Default for DemoService {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceHandler for DemoService {
    fn handle(
        &mut self,
        request: ServiceRequest<'_>,
        response: &mut [u8],
    ) -> Result<ServiceReply, ServiceError> {
        self.router.handle(request, response)
    }
}

fn copy_response(
    response: &mut [u8],
    body: &[u8],
    status: ServiceStatus,
    content_type: ContentType,
) -> Result<ServiceReply, ServiceError> {
    if response.len() < body.len() {
        return Err(ServiceError::BufferTooSmall);
    }
    response[..body.len()].copy_from_slice(body);
    Ok(ServiceReply {
        status,
        content_type,
        body_len: body.len(),
    })
}

fn health(_request: ServiceRequest<'_>, response: &mut [u8]) -> Result<ServiceReply, ServiceError> {
    copy_response(response, HEALTH_JSON, ServiceStatus::OK, ContentType::Json)
}

fn info(_request: ServiceRequest<'_>, response: &mut [u8]) -> Result<ServiceReply, ServiceError> {
    copy_response(response, INFO_JSON, ServiceStatus::OK, ContentType::Json)
}

fn echo(request: ServiceRequest<'_>, response: &mut [u8]) -> Result<ServiceReply, ServiceError> {
    copy_response(
        response,
        request.payload,
        ServiceStatus::OK,
        ContentType::Binary,
    )
}

fn rpc(request: ServiceRequest<'_>, response: &mut [u8]) -> Result<ServiceReply, ServiceError> {
    let method = route_suffix(request.route, "/rpc/").unwrap_or("");
    let body = match method {
        "ping" => br#"{"method":"ping","result":"pong"}"#.as_slice(),
        "health" => HEALTH_JSON,
        "info" => INFO_JSON,
        _ => return Err(ServiceError::NotFound),
    };
    copy_response(response, body, ServiceStatus::OK, ContentType::Json)
}

fn cashu_info(
    _request: ServiceRequest<'_>,
    response: &mut [u8],
) -> Result<ServiceReply, ServiceError> {
    // NUT-06: mint info
    // Demo note: transported over FIPS + HTTP demo adapter, not a production public mint.
    copy_response(
        response,
        br#"{"name":"microfips demo mint","pubkey":"demo","version":"0.1","nuts":{"4":{"methods":["bolt11"]},"6":{"supported":true}}}"#,
        ServiceStatus::OK,
        ContentType::Json,
    )
}

fn cashu_keys(
    _request: ServiceRequest<'_>,
    response: &mut [u8],
) -> Result<ServiceReply, ServiceError> {
    // NUT-01: mint public keys
    // Demo note: transported over FIPS + HTTP demo adapter, not a production public mint.
    copy_response(response, KEYS_JSON, ServiceStatus::OK, ContentType::Json)
}

fn cashu_keysets(
    _request: ServiceRequest<'_>,
    response: &mut [u8],
) -> Result<ServiceReply, ServiceError> {
    // NUT-02: keyset discovery
    // Demo note: transported over FIPS + HTTP demo adapter, not a production public mint.
    copy_response(response, KEYSETS_JSON, ServiceStatus::OK, ContentType::Json)
}

fn mint_quote_create(
    _request: ServiceRequest<'_>,
    response: &mut [u8],
) -> Result<ServiceReply, ServiceError> {
    // NUT-04: mint quote request/response
    // Demo note: transported over FIPS + HTTP demo adapter, not a production public mint.
    copy_response(
        response,
        MINT_QUOTE_JSON,
        ServiceStatus::OK,
        ContentType::Json,
    )
}

fn mint_quote_get(
    request: ServiceRequest<'_>,
    response: &mut [u8],
) -> Result<ServiceReply, ServiceError> {
    // NUT-04: mint quote request/response
    // Demo note: transported over FIPS + HTTP demo adapter, not a production public mint.
    let quote_id = route_suffix(request.route, "/v1/mint/quote/bolt11/").unwrap_or("unknown");
    let pre = br#"{"quote":""#;
    let suf = br#"","paid":false,"request":"lnbc1demo","expiry":1735689600}"#;
    let total = pre.len() + quote_id.len() + suf.len();
    if response.len() < total {
        return Err(ServiceError::BufferTooSmall);
    }
    let mut pos = 0;
    response[pos..pos + pre.len()].copy_from_slice(pre);
    pos += pre.len();
    response[pos..pos + quote_id.len()].copy_from_slice(quote_id.as_bytes());
    pos += quote_id.len();
    response[pos..pos + suf.len()].copy_from_slice(suf);
    pos += suf.len();
    Ok(ServiceReply {
        status: ServiceStatus::OK,
        content_type: ContentType::Json,
        body_len: pos,
    })
}

fn mint_tokens(
    _request: ServiceRequest<'_>,
    response: &mut [u8],
) -> Result<ServiceReply, ServiceError> {
    // NUT-04: mint quote settlement
    // Demo note: transported over FIPS + HTTP demo adapter, not a production public mint.
    copy_response(
        response,
        MINT_RESULT_JSON,
        ServiceStatus::OK,
        ContentType::Json,
    )
}

fn melt_quote_create(
    _request: ServiceRequest<'_>,
    response: &mut [u8],
) -> Result<ServiceReply, ServiceError> {
    // NUT-05: melt quote request/response
    // Demo note: transported over FIPS + HTTP demo adapter, not a production public mint.
    copy_response(
        response,
        MELT_QUOTE_JSON,
        ServiceStatus::OK,
        ContentType::Json,
    )
}

fn melt_quote_get(
    request: ServiceRequest<'_>,
    response: &mut [u8],
) -> Result<ServiceReply, ServiceError> {
    // NUT-05: melt quote request/response
    // Demo note: transported over FIPS + HTTP demo adapter, not a production public mint.
    let quote_id = route_suffix(request.route, "/v1/melt/quote/bolt11/").unwrap_or("unknown");
    let pre = br#"{"quote":""#;
    let suf = br#"","paid":false,"fee_reserve":1,"amount":21}"#;
    let total = pre.len() + quote_id.len() + suf.len();
    if response.len() < total {
        return Err(ServiceError::BufferTooSmall);
    }
    let mut pos = 0;
    response[pos..pos + pre.len()].copy_from_slice(pre);
    pos += pre.len();
    response[pos..pos + quote_id.len()].copy_from_slice(quote_id.as_bytes());
    pos += quote_id.len();
    response[pos..pos + suf.len()].copy_from_slice(suf);
    pos += suf.len();
    Ok(ServiceReply {
        status: ServiceStatus::OK,
        content_type: ContentType::Json,
        body_len: pos,
    })
}

fn melt_tokens(
    _request: ServiceRequest<'_>,
    response: &mut [u8],
) -> Result<ServiceReply, ServiceError> {
    // NUT-05: melt settlement
    // Demo note: transported over FIPS + HTTP demo adapter, not a production public mint.
    copy_response(
        response,
        MELT_RESULT_JSON,
        ServiceStatus::OK,
        ContentType::Json,
    )
}

fn swap_tokens(
    _request: ServiceRequest<'_>,
    response: &mut [u8],
) -> Result<ServiceReply, ServiceError> {
    // NUT-03: token swap
    // Demo note: transported over FIPS + HTTP demo adapter, not a production public mint.
    copy_response(
        response,
        SWAP_RESULT_JSON,
        ServiceStatus::OK,
        ContentType::Json,
    )
}

#[cfg(feature = "http")]
pub mod http {
    extern crate std;

    use alloc::{format, string::String, sync::Arc, vec, vec::Vec};
    use std::sync::Mutex;

    use microfips_service::{
        decode_response, dispatch_request, encode_request, ContentType, ServiceError,
        ServiceHandler, ServiceMethod,
    };
    use picoserve::response::{Content, IntoResponse, Response, StatusCode};
    use picoserve::routing::{get, parse_path_segment, post};

    pub struct OwnedServiceResponse {
        pub status: u16,
        pub content_type: ContentType,
        pub body: Vec<u8>,
    }

    pub struct LocalServiceClient<H> {
        handler: H,
        pub request_buffer_size: usize,
        pub response_buffer_size: usize,
    }

    impl<H> LocalServiceClient<H> {
        pub fn new(handler: H, request_buffer_size: usize, response_buffer_size: usize) -> Self {
            Self {
                handler,
                request_buffer_size,
                response_buffer_size,
            }
        }
    }

    pub trait ServiceClient {
        fn call(
            &mut self,
            method: ServiceMethod,
            route: &str,
            payload: &[u8],
        ) -> Result<OwnedServiceResponse, ServiceError>;
    }

    impl<H: ServiceHandler> ServiceClient for LocalServiceClient<H> {
        fn call(
            &mut self,
            method: ServiceMethod,
            route: &str,
            payload: &[u8],
        ) -> Result<OwnedServiceResponse, ServiceError> {
            let mut request = vec![
                0u8;
                self.request_buffer_size
                    .max(payload.len() + route.len() + 16)
            ];
            let request_len = encode_request(method, route, payload, &mut request)?;
            let mut response = vec![0u8; self.response_buffer_size];
            let response_len =
                dispatch_request(&mut self.handler, &request[..request_len], &mut response)?;
            let decoded = decode_response(&response[..response_len])?;
            Ok(OwnedServiceResponse {
                status: decoded.status.as_u16(),
                content_type: decoded.content_type,
                body: decoded.body.to_vec(),
            })
        }
    }

    fn content_type_name(content_type: ContentType) -> &'static str {
        match content_type {
            ContentType::Binary => "application/octet-stream",
            ContentType::Json => "application/json",
            ContentType::Text => "text/plain; charset=utf-8",
        }
    }

    pub struct HttpResponse {
        pub status: u16,
        pub content_type: &'static str,
        pub body: Vec<u8>,
    }

    struct TypedBody {
        content_type: &'static str,
        body: Vec<u8>,
    }

    impl Content for TypedBody {
        fn content_type(&self) -> &'static str {
            self.content_type
        }

        fn content_length(&self) -> usize {
            self.body.len()
        }

        async fn write_content<W: picoserve::io::Write>(
            self,
            mut writer: W,
        ) -> Result<(), W::Error> {
            writer.write_all(&self.body).await
        }
    }

    impl IntoResponse for HttpResponse {
        async fn write_to<
            R: picoserve::io::Read,
            W: picoserve::response::ResponseWriter<Error = R::Error>,
        >(
            self,
            connection: picoserve::response::Connection<'_, R>,
            response_writer: W,
        ) -> Result<picoserve::ResponseSent, W::Error> {
            response_writer
                .write_response(
                    connection,
                    Response::new(
                        StatusCode::new(self.status),
                        TypedBody {
                            content_type: self.content_type,
                            body: self.body,
                        },
                    ),
                )
                .await
        }
    }

    fn call_backend<B: ServiceClient>(
        backend: &Arc<Mutex<B>>,
        method: ServiceMethod,
        route: &str,
        payload: &[u8],
    ) -> HttpResponse {
        match backend.lock().unwrap().call(method, route, payload) {
            Ok(response) => HttpResponse {
                status: response.status,
                content_type: content_type_name(response.content_type),
                body: response.body,
            },
            Err(err) => HttpResponse {
                status: err.status().as_u16(),
                content_type: "text/plain; charset=utf-8",
                body: err.message().as_bytes().to_vec(),
            },
        }
    }

    macro_rules! demo_router {
        ($backend:expr) => {{
            picoserve::Router::new()
                .route(
                    "/health",
                    {
                        let backend = $backend.clone();
                        get(move || {
                            let backend = backend.clone();
                            async move { call_backend(&backend, ServiceMethod::Get, "/health", b"") }
                        })
                    },
                )
                .route(
                    "/info",
                    {
                        let backend = $backend.clone();
                        get(move || {
                            let backend = backend.clone();
                            async move { call_backend(&backend, ServiceMethod::Get, "/info", b"") }
                        })
                    },
                )
                .route(
                    "/echo",
                    {
                        let backend = $backend.clone();
                        post(move |body: Vec<u8>| {
                            let backend = backend.clone();
                            async move { call_backend(&backend, ServiceMethod::Post, "/echo", &body) }
                        })
                    },
                )
                .route(
                    ("/rpc", parse_path_segment::<String>()),
                    {
                        let backend = $backend.clone();
                        post(move |method: String, body: Vec<u8>| {
                            let backend = backend.clone();
                            async move {
                                let route = format!("/rpc/{method}");
                                call_backend(&backend, ServiceMethod::Post, &route, &body)
                            }
                        })
                    },
                )
                .route(
                    "/v1/info",
                    {
                        let backend = $backend.clone();
                        get(move || {
                            let backend = backend.clone();
                            async move { call_backend(&backend, ServiceMethod::Get, "/v1/info", b"") }
                        })
                    },
                )
                .route(
                    "/v1/keys",
                    {
                        let backend = $backend.clone();
                        get(move || {
                            let backend = backend.clone();
                            async move { call_backend(&backend, ServiceMethod::Get, "/v1/keys", b"") }
                        })
                    },
                )
                .route(
                    "/v1/keysets",
                    {
                        let backend = $backend.clone();
                        get(move || {
                            let backend = backend.clone();
                            async move { call_backend(&backend, ServiceMethod::Get, "/v1/keysets", b"") }
                        })
                    },
                )
                .route(
                    "/v1/mint/quote/bolt11",
                    {
                        let backend = $backend.clone();
                        post(move |body: Vec<u8>| {
                            let backend = backend.clone();
                            async move {
                                call_backend(&backend, ServiceMethod::Post, "/v1/mint/quote/bolt11", &body)
                            }
                        })
                    },
                )
                .route(
                    ("/v1/mint/quote/bolt11", parse_path_segment::<String>()),
                    {
                        let backend = $backend.clone();
                        get(move |quote_id: String| {
                            let backend = backend.clone();
                            async move {
                                let route = format!("/v1/mint/quote/bolt11/{quote_id}");
                                call_backend(&backend, ServiceMethod::Get, &route, b"")
                            }
                        })
                    },
                )
                .route(
                    "/v1/mint/bolt11",
                    {
                        let backend = $backend.clone();
                        post(move |body: Vec<u8>| {
                            let backend = backend.clone();
                            async move {
                                call_backend(&backend, ServiceMethod::Post, "/v1/mint/bolt11", &body)
                            }
                        })
                    },
                )
                .route(
                    "/v1/melt/quote/bolt11",
                    {
                        let backend = $backend.clone();
                        post(move |body: Vec<u8>| {
                            let backend = backend.clone();
                            async move {
                                call_backend(&backend, ServiceMethod::Post, "/v1/melt/quote/bolt11", &body)
                            }
                        })
                    },
                )
                .route(
                    ("/v1/melt/quote/bolt11", parse_path_segment::<String>()),
                    {
                        let backend = $backend.clone();
                        get(move |quote_id: String| {
                            let backend = backend.clone();
                            async move {
                                let route = format!("/v1/melt/quote/bolt11/{quote_id}");
                                call_backend(&backend, ServiceMethod::Get, &route, b"")
                            }
                        })
                    },
                )
                .route(
                    "/v1/melt/bolt11",
                    {
                        let backend = $backend.clone();
                        post(move |body: Vec<u8>| {
                            let backend = backend.clone();
                            async move {
                                call_backend(&backend, ServiceMethod::Post, "/v1/melt/bolt11", &body)
                            }
                        })
                    },
                )
                .route(
                    "/v1/swap",
                    {
                        let backend = $backend.clone();
                        post(move |body: Vec<u8>| {
                            let backend = backend.clone();
                            async move { call_backend(&backend, ServiceMethod::Post, "/v1/swap", &body) }
                        })
                    },
                )
        }};
    }

    pub async fn run_local_demo(bind_addr: &str) -> std::io::Result<()> {
        let backend = Arc::new(Mutex::new(LocalServiceClient::new(
            super::DemoService::new(),
            2048,
            4096,
        )));
        let app = Arc::new(demo_router!(backend));
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        loop {
            let (stream, _) = listener.accept().await?;
            let app = app.clone();
            tokio::task::spawn_local(async move {
                static CONFIG: picoserve::Config =
                    picoserve::Config::const_default().keep_connection_alive();
                let _ = picoserve::Server::new_tokio(&app, &CONFIG, &mut [0u8; 4096])
                    .serve(stream)
                    .await;
            });
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use alloc::string::ToString;
        use std::io::{Read, Write};

        async fn with_server<F, Fut>(f: F)
        where
            F: FnOnce(String) -> Fut,
            Fut: core::future::Future<Output = ()>,
        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let backend = Arc::new(Mutex::new(LocalServiceClient::new(
                crate::DemoService::new(),
                2048,
                4096,
            )));
            let app = Arc::new(demo_router!(backend));
            let accept_task = tokio::task::spawn_local(async move {
                let (stream, _) = listener.accept().await.unwrap();
                static CONFIG: picoserve::Config = picoserve::Config::const_default();
                let _ = picoserve::Server::new_tokio(&app, &CONFIG, &mut [0u8; 4096])
                    .serve(stream)
                    .await;
            });
            f(addr.to_string()).await;
            accept_task.await.unwrap();
        }

        fn http_request(addr: &str, raw: &str) -> String {
            let mut stream = std::net::TcpStream::connect(addr).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            stream.write_all(raw.as_bytes()).unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            let mut response = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => response.extend_from_slice(&buf[..n]),
                    Err(err)
                        if matches!(
                            err.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        break
                    }
                    Err(err) => panic!("http read failed: {err}"),
                }
            }
            String::from_utf8(response).unwrap()
        }

        async fn http_request_async(addr: String, raw: &'static str) -> String {
            tokio::task::spawn_blocking(move || http_request(&addr, raw))
                .await
                .unwrap()
        }

        #[tokio::test(flavor = "current_thread")]
        async fn get_health_route_works() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    with_server(|addr| async move {
                        let response = http_request_async(
                            addr,
                            "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                        assert!(response.starts_with("HTTP/1.1 200 "));
                        assert!(response.contains("\"ok\":true"));
                    })
                    .await;
                })
                .await;
        }

        #[tokio::test(flavor = "current_thread")]
        async fn post_rpc_route_reaches_service_layer() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    with_server(|addr| async move {
                        let response = http_request_async(
                            addr,
                            "POST /rpc/ping HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                        assert!(response.starts_with("HTTP/1.1 200 "));
                        assert!(response.contains("\"pong\""));
                    })
                    .await;
                })
                .await;
        }
    }
}

#[cfg(test)]
mod service_tests {
    use super::*;

    #[test]
    fn demo_service_supports_info_echo_and_ping() {
        let mut service = DemoService::new();
        let mut buf = [0u8; 256];

        let info = service
            .handle(
                ServiceRequest {
                    method: ServiceMethod::Get,
                    route: "/info",
                    payload: b"",
                },
                &mut buf,
            )
            .unwrap();
        assert_eq!(info.status, ServiceStatus::OK);
        assert!(core::str::from_utf8(&buf[..info.body_len])
            .unwrap()
            .contains("microfips-http-demo"));

        let echo = service
            .handle(
                ServiceRequest {
                    method: ServiceMethod::Post,
                    route: "/echo",
                    payload: b"hello",
                },
                &mut buf,
            )
            .unwrap();
        assert_eq!(&buf[..echo.body_len], b"hello");

        let ping = service
            .handle(
                ServiceRequest {
                    method: ServiceMethod::Post,
                    route: "/rpc/ping",
                    payload: b"",
                },
                &mut buf,
            )
            .unwrap();
        assert_eq!(ping.status, ServiceStatus::OK);
        assert!(core::str::from_utf8(&buf[..ping.body_len])
            .unwrap()
            .contains("pong"));
    }

    #[test]
    fn demo_service_returns_structured_not_found() {
        let mut service = DemoService::new();
        let mut buf = [0u8; 64];
        let err = service
            .handle(
                ServiceRequest {
                    method: ServiceMethod::Get,
                    route: "/missing",
                    payload: b"",
                },
                &mut buf,
            )
            .unwrap_err();
        assert_eq!(err, ServiceError::NotFound);
        assert_eq!(err.status(), ServiceStatus::NOT_FOUND);
    }
}
