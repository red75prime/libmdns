use super::{QueryType, QueryClass, Name, Class, Header, RRData};


/// Parsed DNS packet
#[derive(Debug)]
pub struct Packet<'a> {
    pub header: Header,
    pub questions: Vec<Question<'a>>,
    pub answers: Vec<ResourceRecord<'a>>,
    pub nameservers: Vec<ResourceRecord<'a>>,
    pub additional: Vec<ResourceRecord<'a>>,
}

/// A parsed chunk of data in the Query section of the packet
#[derive(Debug)]
pub struct Question<'a> {
    pub qname: Name<'a>,
    pub qtype: QueryType,
    pub qclass: QueryClass,
    pub qu: bool,
}

/// A single DNS record
///
/// We aim to provide whole range of DNS records available. But as time is
/// limited we have some types of packets which are parsed and other provided
/// as unparsed slice of bytes.
#[derive(Debug)]
pub struct ResourceRecord<'a> {
    pub name: Name<'a>,
    pub cls: Class,
    pub ttl: u32,
    pub data: RRData<'a>,
}

impl<'a> ::std::fmt::Display for Packet<'a> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        writeln!(fmt, "{:?}", self.header)?;
        writeln!(fmt, "Questions")?;
        for q in &self.questions {
            writeln!(fmt, "  {}", q)?;
        }
        writeln!(fmt, "Answers")?;
        for a in &self.answers {
            writeln!(fmt, "  {}", a)?;
        }
        writeln!(fmt, "Nameservers")?;
        for n in &self.nameservers {
            writeln!(fmt, "  {}", n)?;
        }
        writeln!(fmt, "Additional")?;
        for a in &self.additional {
            writeln!(fmt, "  {}", a)?;
        }
        Ok(())
    }
}

impl<'a> ::std::fmt::Display for Question<'a> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(fmt, "{} {:?} {:?}{}", self.qname, self.qtype, self.qclass, if self.qu {" unicast"} else {""})
    }
}

impl<'a> ::std::fmt::Display for ResourceRecord<'a> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(fmt, "{} {:?} {} {}", self.name, self.cls, self.ttl, self.data)
    }
}
