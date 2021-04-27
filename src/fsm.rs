use crate::dns_parser::{self, QueryClass, QueryType, Name, RRData};
use log;
use std::collections::VecDeque;
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use futures::{Future, Stream};
use futures::channel::mpsc;
use pin_project::pin_project;
use tokio::pin;
use tokio::net::UdpSocket;
use tokio::runtime::Handle;

use super::{DEFAULT_TTL, MDNS_PORT};
use crate::address_family::AddressFamily;
use crate::net;
use crate::services::{Services, ServiceData};

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

struct FSMState<AF> {
    services: Services,
    outgoing: VecDeque<(Vec<u8>, SocketAddr)>,
    _af: PhantomData<AF>,
}

impl<AF: AddressFamily> FSMState<AF> {
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
                use crate::dns_parser::Packet;
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
                use crate::dns_parser::Packet;
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

#[pin_project]
pub struct FSM<AF> {
    socket: UdpSocket,
    buffer: Vec<u8>,
    #[pin]
    commands: mpsc::UnboundedReceiver<Command>,
    state: FSMState<AF>,
}

impl <AF: AddressFamily> FSM<AF> {
    pub fn new(handle: &Handle, services: &Services)
        -> io::Result<(FSM<AF>, mpsc::UnboundedSender<Command>)>
    {
        info!("Binding socket");
        let std_socket = AF::bind()?;
        info!("Setting socket as nonblocking");
        std_socket.set_nonblocking(true)?;
        info!("Creating async socket");
        let _rt_guard = handle.enter();
        let socket = UdpSocket::from_std(std_socket)?;
        let (tx, rx) = mpsc::unbounded();

        let fsm = FSM {
            socket: socket,
            buffer: vec![0; AF::MAX_PACKET_SIZE],
            commands: rx,
            state: FSMState {
                services: services.clone(),
                outgoing: VecDeque::new(),
                _af: PhantomData,
            },
        };

        Ok((fsm, tx))
    }

    fn commands<'a>(self: &'a mut Pin<&mut Self>) -> Pin<&'a mut mpsc::UnboundedReceiver<Command>>  {
        self.as_mut().project().commands
    }

    fn state<'a>(self: &'a mut Pin<&mut Self>) -> &'a mut FSMState<AF>  {
        self.as_mut().project().state
    }
}



impl <AF: AddressFamily> Future for FSM<AF> {
    type Output = Result<(), io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        trace!("FSM poll");
        while let Poll::Ready(cmd) = self.commands().poll_next(&mut *cx) {
            match cmd {
                Some(Command::Shutdown) => return Poll::Ready(Ok(())),
                Some(Command::SendUnsolicited { svc, ttl, include_ip }) => {
                    self.state().send_unsolicited(&svc, ttl, include_ip);
                }
                None => {
                    warn!("responder disconnected without shutdown");
                    return Poll::Ready(Ok(()));
                }
            }
        }

        loop {
            trace!("FSM packet recieve loop");
            let this = self.as_mut().project();
            let buf = &mut this.buffer[..];
            let mut buf = tokio::io::ReadBuf::new(buf);
            // We use maximum UDP packet size for buf
            // So there's no need to handle different ways that different platforms use to signal insufficient buffer size
            let addr = match this.socket.poll_recv_from(&mut *cx, &mut buf)? {
                Poll::Pending => {
                    // No more incoming packets, proceed to sending
                    break;
                }
                Poll::Ready(addr) => {
                    addr
                }
            };
            this.state.handle_packet(buf.filled(), addr);
        }

        // non-lexical borrow checker is required for while let loop
        #[allow(clippy::while_let_loop)]
        let this = self.project();
        while let Some((response, addr)) = this.state.outgoing.front() {
            trace!("sending packet to {:?}", addr);

            match this.socket.poll_send_to(&mut *cx, response, *addr) {
                Poll::Pending => { break }
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => { warn!("error sending packet {:?}", err) }
            }
            this.state.outgoing.pop_front();
        }

        // It's OK to return Pending here, some of the polls above registered wake interest
        Poll::Pending
    }
}
