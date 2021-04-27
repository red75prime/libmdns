use quick_error::quick_error;

quick_error! {
    /// Error parsing DNS packet
    #[derive(Debug)]
    #[allow(dead_code)]
    pub enum Error {
        HeaderTooShort {
            display("packet is smaller than header size")
        }
        UnexpectedEOF {
            display("packet is has incomplete data")
        }
        WrongRdataLength {
            display("wrong (too short or too long) size of RDATA")
        }
        ReservedBitsAreNonZero {
            display("packet has non-zero reserved bits")
        }
        UnknownLabelFormat {
            display("label in domain name has unknown label format")
        }
        InvalidQueryType(code: u16) {
            display("query type {} is invalid", code)
        }
        InvalidQueryClass(code: u16) {
            display("query class {} is invalid", code)
        }
        InvalidType(code: u16) {
            display("type {} is invalid", code)
        }
        InvalidClass(code: u16) {
            display("class {} is invalid", code)
        }
        LabelIsNotAscii {
            display("invalid characters encountered while reading label")
        }
        WrongState {
            display("parser is in the wrong state")
        }
        PartTooLong {
            display("label in domain name is too long")
        }
    }
}
