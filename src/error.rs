#[derive(Debug)]
pub enum RDataParseError {
    InvalidIpAddr(std::net::AddrParseError),
    InvalidName(
        trust_dns_proto::rr::RecordType,
        trust_dns_proto::error::ProtoError,
    ),
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
