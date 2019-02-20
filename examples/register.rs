extern crate env_logger;
extern crate libmdns;
extern crate tokio;
extern crate futures;

use futures::{Future, future};
use std::time::Duration;
use tokio::timer::Timeout;
use tokio::runtime::current_thread::Runtime;

pub fn main() {
    env_logger::init();

    let (responder, responder_task) = libmdns::Responder::new().unwrap();
    let svc = responder.register(
        "_http._tcp".to_owned(),
        "Web Server".to_owned(),
        80,
        &["path=/"]);

    drop(responder);
    let never = 
        future::empty()
        .then(|_: Result<(), ()>| -> Result<(), ()> {
            let _svc = svc;
            Ok(())
        });

    let timeout =
        Timeout::new(never, Duration::from_secs(10))
        .map_err(|e| {
            eprintln!("Error: {:?}", e);
            ()
        });
    let mut rt = Runtime::new().unwrap();
    rt.spawn(timeout);
    rt.block_on(responder_task.map_err(|e| eprintln!("Error: {:?}", e) )).unwrap();
}
