use std::time::Duration;
use futures::FutureExt;
use tokio::time;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    env_logger::init();

    let (responder, responder_task) = libmdns::Responder::new().unwrap();
    let svc = responder.register(
        "_http._tcp".to_owned(),
        "Web Server".to_owned(),
        80,
        &["path=/"])?;

    let timeout = time::sleep(Duration::from_secs(10));
    tokio::select! {
        _ = timeout => {
            println!("Timeout");
        }
        result = responder_task => {
            println!("Responder returned: {:?}", result);
        }
    };
    Ok(())
}
