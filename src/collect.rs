use crate::error::*;
use crate::record_wrapper::RecordWrapper;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;
use trust_dns_proto::rr::{Name, RData, Record, RecordType};

pub type AllDomains = HashMap<Name, HashMap<RecordWrapper, DomainStat>>;

#[derive(Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainStat {
    pub counts: usize,
    pub ttls: HashSet<u32>,
}

impl std::fmt::Debug for DomainStat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        formatter.write_str(&format!(
            "DomainStat {{counts: {:?}, ttls: {:?}}}",
            self.counts, self.ttls
        ))
    }
}

pub fn collect(
    name_server: &str,
    domain_names: &[String],
    record_type: RecordType,
    repeat: usize,
    all_domains_counts: &mut AllDomains,
) {
    for _ in 0..repeat {
        let response = query(name_server, domain_names, record_type);
        if let Ok(response) = response {
            response
                .into_iter()
                .filter(|v| v.is_ok())
                .map(|v| v.unwrap())
                .filter(|v| v.record_type().is_ip_addr())
                .for_each(|v| {
                    let name = v.name().clone();
                    let ttl = v.ttl();
                    let record_counts = all_domains_counts
                        .entry(name.clone())
                        .or_insert_with(HashMap::new);
                    let stat = record_counts
                        .entry(RecordWrapper::new(v))
                        .or_insert_with(DomainStat::default);
                    stat.counts += 1;
                    stat.ttls.insert(ttl);
                });
        } else {
            break;
        }
    }
}

pub fn query(
    name_server: &str,
    domain_names: &[String],
    record_type: RecordType,
) -> Result<Vec<Result<Record, RecordParseError>>, QueryError> {
    let domain_names_result = domain_names
        .iter()
        .map(|name| Name::from_str_relaxed(name).map_err(|e| QueryError::TrustDnsProtoError(e)))
        .collect::<Vec<_>>();
    let mut domain_names = Vec::new();
    for name in domain_names_result.into_iter() {
        domain_names.push(name?.to_utf8());
    }

    let output = Command::new("dig")
        .args(&["+noall", "+answer", "+norecurse"])
        .arg(format!("@{}", name_server))
        .args(domain_names.as_slice())
        .arg(format!("{}", record_type))
        .output()
        .map_err(|e| QueryError::CommandError(e))?;
    let result = String::from_utf8(output.stdout).map_err(|e| QueryError::StringConvertError(e))?;
    let records_result = result
        .lines()
        .map(|l| {
            let line = l.split_ascii_whitespace().collect::<Vec<_>>();
            if line.len() != 5 {
                Err(RecordParseError::NotEnoughArguments)
            } else {
                let domain_name = Name::from_str_relaxed(&line[0])
                    .map_err(|e| RecordParseError::InvalidDomainName(e))?;
                let ttl = line[1]
                    .parse::<u32>()
                    .map_err(|e| RecordParseError::InvalidTtl(e))?;
                let record_type: RecordType =
                    FromStr::from_str(&line[3]).map_err(|e| RecordParseError::InvalidRecord(e))?;
                let rdata = parse_record_data(&line[4], record_type)?;
                let record = Record::from_rdata(domain_name, ttl, rdata);
                Ok(record)
            }
        })
        .collect::<Vec<_>>();
    Ok(records_result)
}

pub fn parse_record_data(rdata: &str, record_type: RecordType) -> Result<RData, RecordParseError> {
    match record_type {
        RecordType::A | RecordType::AAAA => {
            let ip_addr = IpAddr::from_str(rdata)
                .map_err(|e| RecordParseError::InvalidRData(RDataParseError::InvalidIpAddr(e)))?;
            Ok(match ip_addr {
                IpAddr::V4(ip) => RData::A(ip),
                IpAddr::V6(ip) => RData::AAAA(ip),
            })
        }
        t => Err(RecordParseError::InvalidRData(
            RDataParseError::UnsupportedType(t),
        )),
    }
}
