use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use trust_dns_proto::rr::Record;
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

#[derive(Clone, Eq)]
pub struct RecordWrapper(Record);

impl RecordWrapper {
    pub fn new(r: Record) -> Self {
        Self(r)
    }

    pub fn unwrap(self) -> Record {
        self.0
    }
}

impl std::hash::Hash for RecordWrapper {
    fn hash<H>(&self, hasher: &mut H)
    where
        H: std::hash::Hasher,
    {
        self.0.name().hash(hasher);
        self.0.record_type().hash(hasher);
        self.0.dns_class().hash(hasher);
        // skip TTL
        self.0
            .rdata()
            .to_ip_addr()
            .expect("Not an IP address")
            .hash(hasher);
    }
}

impl PartialEq for RecordWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.0.name() == other.0.name() &&
            self.0.record_type() == other.0.record_type() &&
            self.0.dns_class() == other.0.dns_class() &&
            // skip TTL
            self.0.rdata() == other.0.rdata()
    }
}

impl std::fmt::Debug for RecordWrapper {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.0.name().to_string().fmt(formatter)?;
        formatter.write_str("\t")?;
        self.0.record_type().fmt(formatter)?;
        formatter.write_str("\t")?;
        self.0.dns_class().fmt(formatter)?;
        formatter.write_str("\t")?;
        self.0.ttl().fmt(formatter)?;
        formatter.write_str("\t")?;
        //self.0.rdata().as_a().unwrap().fmt(formatter)?;
        self.0
            .rdata()
            .to_ip_addr()
            .expect("Not an IP address")
            .to_string()
            .fmt(formatter)?;
        Ok(())
    }
}

impl Serialize for RecordWrapper {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.to_bytes().unwrap();
        s.serialize_bytes(bytes.as_slice())
    }
}

struct Bytes;

impl<'de> Visitor<'de> for Bytes {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "Invalid format")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(v.to_owned())
    }
}

impl<'de> Deserialize<'de> for RecordWrapper {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let buf = d.deserialize_bytes(Bytes)?;
        let inner = Record::from_bytes(buf.as_slice()).unwrap();
        Ok(Self::new(inner))
    }
}
