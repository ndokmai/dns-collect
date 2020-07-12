#[derive(Debug)]
pub enum RDataParseError {
    UnsupportedType(trust_dns_proto::rr::RecordType),
    InvalidIpAddr(std::net::AddrParseError),
}

#[derive(Debug)]
pub enum RecordParseError {
    NotEnoughArguments,
    InvalidDomainName(trust_dns_proto::error::ProtoError),
    InvalidTtl(std::num::ParseIntError),
    InvalidRecord(trust_dns_proto::error::ProtoError),
    InvalidRData(RDataParseError),
}

#[derive(Debug)]
pub enum QueryError {
    CommandError(std::io::Error),
    StringConvertError(std::string::FromUtf8Error),
    TrustDnsProtoError(trust_dns_proto::error::ProtoError),
    RecordParseError(RecordParseError),
}
