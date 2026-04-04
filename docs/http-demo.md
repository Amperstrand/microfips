# HTTP demo over microfips service

## Layout

- `crates/microfips-core`: cryptographic/session primitives only.
- `crates/microfips-protocol`: transport, framing, node runtime, FSP orchestration.
- `crates/microfips-service`: compact request/response envelope, router, status codes, FSP app adapter.
- `crates/microfips-http-demo`: optional demo application + optional `picoserve` HTTP adapter.
- board/example binaries (`microfips`, `microfips-esp32`, `microfips-sim`, `microfips-http-test`): thin composition roots.

## Why HTTP is optional

The reusable boundary is `microfips-service`, not HTTP. Applications exchange compact service requests and responses over FSP payloads. `picoserve` lives only in `microfips-http-demo` behind the `http` feature, so downstream users can keep non-HTTP transports and application protocols.

## Service boundary

`microfips-service` provides:

- `ServiceRequest` / `ServiceResponse`
- `ServiceMethod`
- `ServiceStatus`
- `Router`
- `ServiceHandler`
- `FspServiceAdapter`

The adapter lets an application handle established FSP payloads without coupling `microfips-core` or `microfips-protocol` to HTTP.

## Demo routes

The demo service exposes:

- `GET /health`
- `GET /info`
- `POST /echo`
- `POST /rpc/:method`
- Cashu-shaped demo routes under `/v1/*`

Cashu-shaped handlers are mocked and include NUT comments in source. They demonstrate shape and layering only.
Here NUT means Cashu "Notation, Usage, and Terminology" specification documents.

## Build and run

### Run service/FSP-oriented host checks

```sh
cargo test -p microfips-service
cargo test -p microfips-protocol --features std -- --test-threads=1
```

### Run the optional HTTP demo locally

```sh
cargo run -p microfips-http-demo --features http
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/info
curl -X POST http://127.0.0.1:8080/echo -d 'hello'
curl -X POST http://127.0.0.1:8080/rpc/ping
curl http://127.0.0.1:8080/v1/info
```

### Run HTTP adapter tests

```sh
cargo test -p microfips-http-demo --features http
```

### Run the host FSP demo client

```sh
cargo run -p microfips-http-test -- 127.0.0.1:31338
```

This sends a service request over the existing FSP path and prints the service response.

## Micronuts reuse

Micronuts should depend on the reusable service boundary, not the HTTP demo crate:

- implement `ServiceHandler` for wallet/mint RPC
- reuse `Router` and envelope types
- plug the handler into `FspServiceAdapter`
- optionally add a separate HTTP/CBOR/binary adapter crate

## Current limitations

- responses are buffered in memory; buffer sizes are intentionally configurable but still fixed-size at each composition root
- Cashu endpoints are demo/static responses, not a real mint
- the host `picoserve` demo proves layering, not production deployment hardening
- firmware binaries now serve the demo service over FSP, but they do not embed an HTTP listener
