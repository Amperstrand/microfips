#![no_std]

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod error;
pub mod framing;
pub mod fsp_handler;
pub mod node;
pub mod peer_policy;
pub mod transport;

#[cfg(feature = "mmp")]
pub mod mmp;

#[cfg(test)]
pub mod test_helpers {
    use embassy_executor::Executor;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    pub fn block_on<F: std::future::Future + Send + 'static>(f: F) -> F::Output
    where
        F::Output: Send + 'static,
    {
        use embassy_executor::task;
        use std::boxed::Box;

        let executor: &'static mut Executor = Box::leak(Box::new(Executor::new()));

        let result: Arc<Mutex<Option<F::Output>>> = Arc::new(Mutex::new(None));
        let result_clone = result.clone();
        let done = Arc::new(AtomicBool::new(false));
        let done_clone = done.clone();
        let boxed: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
            Box::pin(async move {
                let output = f.await;
                *result_clone.lock().unwrap() = Some(output);
                done_clone.store(true, Ordering::Relaxed);
            });

        #[task(pool_size = 64)]
        async fn run_boxed(fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
            fut.await
        }

        let done_check = done.clone();

        executor.run_until(
            |spawner| {
                spawner.spawn(run_boxed(boxed).unwrap());
            },
            move || done_check.load(Ordering::Relaxed),
        );

        let output = result.lock().unwrap().take().unwrap();
        output
    }
}
