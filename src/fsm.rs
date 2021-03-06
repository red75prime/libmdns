use dns_parser::{self, QueryClass, QueryType, Name, RRData};
use log;
use std::collections::VecDeque;
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use futures::{Poll, Async, Future, Stream};
use futures::sync::mpsc;
use tokio::net::UdpSocket;
use tokio::reactor::Handle;

use super::{DEFAULT_TTL, MDNS_PORT};
use address_family::AddressFamily;
use net;
use services::{Services, ServiceData};

pub type AnswerBuilder = dns_parser::Builder<dns_parser::Answers>;

#[derive(Clone, Debug)]
pub enum Command {
    SendUnsolicited {
        svc: ServiceData,
        ttl: u32,
        include_ip: bool
    },
    Shutdown,
}

pub struct FSM<AF: AddressFamily> {
    socket: UdpSocket,
    services: Services,
    //hostname: String,
    commands: mpsc::UnboundedReceiver<Command>,
    outgoing: VecDeque<(Vec<u8>, SocketAddr)>,
    _af: PhantomData<AF>,
}

impl <AF: AddressFamily> FSM<AF> {
    pub fn new(handle: &Handle, services: &Services)
        -> io::Result<(FSM<AF>, mpsc::UnboundedSender<Command>)>
    {
        info!("Binding socket");
        let std_socket = AF::bind()?;
        info!("Creating async socket");
        let socket = UdpSocket::from_std(std_socket, handle)?;
        let (tx, rx) = mpsc::unbounded();

        let fsm = FSM {
            socket: socket,
            services: services.clone(),
            commands: rx,
            outgoing: VecDeque::new(),
            _af: PhantomData,
        };

        Ok((fsm, tx))
    }

    fn handle_packet(&mut self, buffer: &[u8], addr: SocketAddr) {
        trace!("received packet from {:?}", addr);

        let packet = match dns_parser::Packet::parse(buffer) {
            Ok(packet) => {
                trace!("packet: {}", packet);
                packet
            },
            Err(error) => {
                warn!("couldn't parse packet from {:?}: {}", addr, error);
                return;
            }
        };

        if !packet.header.query {
            trace!("received packet from {:?} with no query", addr);
            return;
        }

        if packet.header.truncated {
            warn!("dropping truncated packet from {:?}", addr);
            return;
        }

        let mut unicast_builder = dns_parser::Builder::new_response(packet.header.id, false, true).move_to::<dns_parser::Answers>();
        let mut multicast_builder = dns_parser::Builder::new_response(packet.header.id, false, true).move_to::<dns_parser::Answers>();
        unicast_builder.set_max_size(None);
        multicast_builder.set_max_size(None);

        for question in packet.questions {
            if question.qclass == QueryClass::IN || question.qclass == QueryClass::Any {
                if question.qu {
                    unicast_builder = self.handle_question(&question, unicast_builder);
                } else {
                    multicast_builder = self.handle_question(&question, multicast_builder);
                }
            }
        }

        if !multicast_builder.is_empty() {
            let response = multicast_builder.build().unwrap_or_else(|x| x);
            if log::max_level() == log::LevelFilter::Trace {
                use dns_parser::Packet;
                match Packet::parse(&response) {
                    Ok(packet) => {
                        trace!("Sending multicast {}", packet);
                    }
                    Err(e) => {
                        error!("Error parsing outgoing multicast packet {:?}", e);
                    }
                }
            }
            let addr = SocketAddr::new(AF::mdns_group(), MDNS_PORT);
            self.outgoing.push_back((response, addr));
        }

        if !unicast_builder.is_empty() {
            let response = unicast_builder.build().unwrap_or_else(|x| x);
            if log::max_level() == log::LevelFilter::Trace {
                use dns_parser::Packet;
                match Packet::parse(&response) {
                    Ok(packet) => {
                        trace!("Sending unicast {}", packet);
                    }
                    Err(e) => {
                        error!("Error parsing outgoing unicast packet {:?}", e);
                    }
                }
            }
            self.outgoing.push_back((response, addr));
        }
    }

    fn handle_question(&self, question: &dns_parser::Question, mut builder: AnswerBuilder) -> AnswerBuilder {
        let services = self.services.read().unwrap();

        match question.qtype {
            QueryType::A |
            QueryType::AAAA |
            QueryType::All if question.qname == *services.get_hostname() => {
                builder = self.add_ip_rr(services.get_hostname(), builder, DEFAULT_TTL);
            }
            QueryType::PTR => {
                let mut found = false;
                if question.qname == Name::from_str("_services._dns-sd._udp.local").unwrap() {
                    for t in services.types_iter() {
                        builder = builder.add_answer(&question.qname, QueryClass::IN, DEFAULT_TTL, &RRData::PTR(t.clone()))
                    }
                } else {
                    for svc in services.find_by_type(&question.qname) {
                        builder = svc.add_ptr_rr(builder, DEFAULT_TTL);
                        builder = svc.add_srv_rr(services.get_hostname(), builder, DEFAULT_TTL);
                        builder = svc.add_txt_rr(builder, DEFAULT_TTL);
                        builder = self.add_ip_rr(services.get_hostname(), builder, DEFAULT_TTL);
                        found = true;
                    }
                    if !found {
                        trace!("Not found. IN PTR {}", &question.qname);
                    }
                }
            }
            QueryType::SRV => {
                if let Some(svc) = services.find_by_name(&question.qname) {
                    builder = svc.add_srv_rr(services.get_hostname(), builder, DEFAULT_TTL);
                    builder = self.add_ip_rr(services.get_hostname(), builder, DEFAULT_TTL);
                }
            }
            QueryType::TXT => {
                if let Some(svc) = services.find_by_name(&question.qname) {
                    builder = svc.add_txt_rr(builder, DEFAULT_TTL);
                }
            }
            _ => ()
        }

        builder
    }

    fn add_ip_rr(&self, hostname: &Name, mut builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        for iface in net::getifaddrs() {
            if iface.is_loopback() {
                continue;
            }

            match iface.ip() {
                Some(IpAddr::V4(ip)) if !AF::v6() => {
                    builder = builder.add_answer(hostname, QueryClass::IN, ttl, &RRData::A(ip))
                }
                Some(IpAddr::V6(ip)) if AF::v6() => {
                    builder = builder.add_answer(hostname, QueryClass::IN, ttl, &RRData::AAAA(ip))
                }
                _ => ()
            }
        }

        builder
    }

    fn send_unsolicited(&mut self, svc: &ServiceData, ttl: u32, include_ip: bool) {
        let mut builder = dns_parser::Builder::new_response(0, false, true).move_to::<dns_parser::Answers>();
        builder.set_max_size(None);

        let services = self.services.read().unwrap();

        builder = svc.add_ptr_rr(builder, ttl);
        builder = svc.add_srv_rr(services.get_hostname(), builder, ttl);
        builder = svc.add_txt_rr(builder, ttl);
        if include_ip {
            builder = self.add_ip_rr(services.get_hostname(), builder, ttl);
        }

        if !builder.is_empty() {
            let response = builder.build().unwrap_or_else(|x| x);
            let addr = SocketAddr::new(AF::mdns_group(), MDNS_PORT);
            self.outgoing.push_back((response, addr));
        }
    }
}

impl <AF: AddressFamily> Future for FSM<AF> {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<(), io::Error> {
        while let Async::Ready(cmd) = self.commands.poll().unwrap() {
            match cmd {
                Some(Command::Shutdown) => return Ok(Async::Ready(())),
                Some(Command::SendUnsolicited { svc, ttl, include_ip }) => {
                    self.send_unsolicited(&svc, ttl, include_ip);
                }
                None => {
                    warn!("responder disconnected without shutdown");
                    return Ok(Async::Ready(()));
                }
            }
        }

        let mut buf = [0u8; 4096];
        while let Async::Ready((bytes, addr)) = self.socket.poll_recv_from(&mut buf)? {
            if bytes >= buf.len() {
                warn!("buffer too small for packet from {:?}", addr);
                continue;
            }
            self.handle_packet(&buf[..bytes], addr);
        }

        // non-lexical borrow checker is required for while let loop
        #[allow(clippy::while_let_loop)]
        loop {
            if let Some(&(ref response, ref addr)) = self.outgoing.front() {
                trace!("sending packet to {:?}", addr);

                match self.socket.poll_send_to(response, addr) {
                    Ok(Async::Ready(_)) => (),
                    Ok(Async::NotReady) => break,
                    Err(err) => warn!("error sending packet {:?}", err),
                }
            } else {
                break;
            }

            self.outgoing.pop_front();
        }

        Ok(Async::NotReady)
    }
}
