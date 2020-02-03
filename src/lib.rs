#[macro_use(quick_error)] extern crate quick_error;

#[macro_use] extern crate log;

extern crate byteorder;
extern crate futures;
extern crate libc;
extern crate multimap;
extern crate net2;
extern crate nix;
extern crate rand;
extern crate tokio;

use futures::Future;
use futures::sync::mpsc;
use std::io;
use std::sync::{Arc, RwLock};
use std::cell::RefCell;
use tokio::reactor::Handle;

mod dns_parser;
use dns_parser::Name;

mod address_family;
mod fsm;
mod services;
#[cfg(windows)]
#[path = "netwin.rs"]
mod net;
#[cfg(not(windows))]
mod net;

use address_family::{Inet, Inet6};
use services::{ServicesInner, Services, ServiceData};
use fsm::{Command, FSM};

const DEFAULT_TTL : u32 = 60;
const MDNS_PORT : u16 = 5353;

pub struct Responder {
    services: Services,
    commands: RefCell<CommandSender>,
    shutdown: Arc<Shutdown>,
}

pub struct Service {
    id: usize,
    services: Services,
    commands: CommandSender,
    _shutdown: Arc<Shutdown>,
}

type ResponderTask = Box<dyn Future<Item=(), Error=io::Error> + Send>;

impl Responder {
    pub fn new() -> io::Result<(Responder, ResponderTask)> {
        Responder::with_handle(&Handle::default())
    }

    pub fn with_handle(handle: &Handle) -> io::Result<(Responder, ResponderTask)> {
        info!("Responder::with_handle()");
        let mut hostname = net::gethostname()?;
        if !hostname.ends_with(".local") {
            hostname.push_str(".local");
        }

        let services = Arc::new(RwLock::new(ServicesInner::new(hostname)));

        let v4 = FSM::<Inet>::new(handle, &services);
        let v6 = FSM::<Inet6>::new(handle, &services);

        let (task, commands) : (ResponderTask, _) = match (v4, v6) {
            (Ok((v4_task, v4_command)), Ok((v6_task, v6_command))) => {
                let task = v4_task.join(v6_task).map(|((),())| ());
                let task = Box::new(task);
                let commands = vec![v4_command, v6_command];
                (task, commands)
            }

            (Ok((v4_task, v4_command)), Err(err)) => {
                warn!("Failed to register IPv6 receiver: {:?}", err);
                (Box::new(v4_task), vec![v4_command])
            }

            (Err(err), _) => return Err(err),
        };

        let commands = CommandSender(commands);
        let responder = Responder {
            services: services,
            commands: RefCell::new(commands.clone()),
            shutdown: Arc::new(Shutdown(commands)),
        };

        Ok((responder, task))
    }
}

fn into_io_error<E>(e: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, e)
}

impl Responder {
    pub fn register(&self, svc_type: String, svc_name: String, port: u16, txt: &[&str]) -> Result<Service, io::Error> {
        let txt = if txt.is_empty() {
            vec![0]
        } else {
            for s in txt {
                if s.len() > 255 {
                    return Err(into_io_error(format!("{:?} is too long for a TXT record", s)));
                }
            }
            txt.into_iter().flat_map(|entry| {
                let entry = entry.as_bytes();
                std::iter::once(entry.len() as u8).chain(entry.into_iter().cloned())
            }).collect()
        };

        let svc = ServiceData {
            typ: Name::from_str(format!("{}.local", svc_type)).map_err(into_io_error)?,
            name: Name::from_str(format!("{}.{}.local", svc_name, svc_type)).map_err(into_io_error)?,
            port: port,
            txt: txt,
        };

        self.commands.borrow_mut()
            .send_unsolicited(svc.clone(), DEFAULT_TTL, true);

        let id = self.services
            .write().unwrap()
            .register(svc);

        Ok(Service {
            id: id,
            commands: self.commands.borrow().clone(),
            services: self.services.clone(),
            _shutdown: self.shutdown.clone(),
        })
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        info!("mDNS service was dropped");
        let svc = self.services
            .write().unwrap()
            .unregister(self.id);
        self.commands.send_unsolicited(svc, 0, false);
    }
}

struct Shutdown(CommandSender);
impl Drop for Shutdown {
    fn drop(&mut self) {
        self.0.send_shutdown();
        // TODO wait for tasks to shutdown
    }
}

#[derive(Clone)]
struct CommandSender(Vec<mpsc::UnboundedSender<Command>>);

impl CommandSender {
    fn send(&mut self, cmd: Command) {
        for tx in self.0.iter_mut() {
            if let Err(e) = tx.unbounded_send(cmd.clone()) {
                error!("CommandSender::send(): {:?}", e)
            }
        }
    }

    fn send_unsolicited(&mut self, svc: ServiceData, ttl: u32, include_ip: bool) {
        self.send(Command::SendUnsolicited {
            svc: svc,
            ttl: ttl,
            include_ip: include_ip,
        });
    }

    fn send_shutdown(&mut self) {
        self.send(Command::Shutdown);
    }
}
