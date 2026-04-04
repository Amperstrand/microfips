#[cfg(feature = "http")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    println!("microfips HTTP demo listening on 127.0.0.1:8080");
    tokio::task::LocalSet::new()
        .run_until(microfips_http_demo::http::run_local_demo("127.0.0.1:8080"))
        .await
}

#[cfg(not(feature = "http"))]
fn main() {}
