use crate::error::*;
use crate::name_server::NameServer;
use crate::record_wrapper::RecordWrapper;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;
use trust_dns_proto::rr::rdata::NULL;
use trust_dns_proto::rr::{Name, RData, Record, RecordType};

const ERROR_LOG_NAME: &str = "error_log.txt";

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

#[derive(Default, Debug, Clone)]
pub struct CollectMetadata {
    pub in_queries: usize,
    pub not_in_queries: usize,
    pub repeat_count: usize,
    pub repeat_valid: usize,
    pub response_count: usize,
    pub response_valid: usize,
}

pub fn collect(
    name_server: &NameServer,
    domain_names: &[String],
    record_type: RecordType,
    repeat: usize,
    all_domains_counts: &mut AllDomains,
) -> CollectMetadata {
    let domain_membership_test = domain_names
        .iter()
        .map(|v| Name::from_str(v))
        .filter(|v| v.is_ok())
        .map(|v| {
            let mut v = v.unwrap();
            v.set_fqdn(true);
            v
        })
        .collect::<HashSet<Name>>();
    let mut error_log = OpenOptions::new().append(true).open(ERROR_LOG_NAME);
    let mut meta = CollectMetadata::default();
    for _ in 0..repeat {
        meta.repeat_count += 1;
        let response = query(&name_server.host, domain_names, record_type);
        if let Ok(response) = response {
            meta.repeat_valid += 1;
            meta.response_count += response.len();
            response
                .into_iter()
                .filter(|v| {
                    if v.is_err() {
                        if let Ok(error_log) = error_log.as_mut() {
                            let _ = writeln!(
                                error_log,
                                "{}: {:?}",
                                chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                                v
                            );
                        }
                    }
                    v.is_ok()
                })
                .map(|v| v.unwrap())
                .for_each(|v| {
                    meta.response_valid += 1;
                    let name = v.name().clone();
                    if domain_membership_test.contains(&name) {
                        meta.in_queries += 1;
                    } else {
                        meta.not_in_queries += 1;
                    }
                    let ttl = v.ttl();
                    let record_counts = all_domains_counts.entry(name).or_insert_with(HashMap::new);
                    let stat = record_counts
                        .entry(RecordWrapper::new(v))
                        .or_insert_with(DomainStat::default);
                    stat.counts += 1;
                    stat.ttls.insert(ttl);
                });
        } else if let Ok(error_log) = error_log.as_mut() {
            let _ = writeln!(
                error_log,
                "{}: {:?}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                response
            );
        }
    }
    meta
}

pub fn query(
    name_server: &str,
    domain_names: &[String],
    record_type: RecordType,
) -> Result<Vec<Result<Record, RecordParseError>>, QueryError> {
    let domain_names_result = domain_names
        .iter()
        .map(|name| Name::from_str(name).map_err(QueryError::TrustDnsProtoError))
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
        .map_err(QueryError::CommandError)?;
    let result = String::from_utf8(output.stdout).map_err(QueryError::StringConvertError)?;
    let records_result = result
        .lines()
        .map(|l| {
            let line = l.split_ascii_whitespace().collect::<Vec<_>>();
            if line.len() != 5 {
                Err(RecordParseError::NotEnoughArguments)
            } else {
                let domain_name =
                    Name::from_str(&line[0]).map_err(RecordParseError::InvalidDomainName)?;
                let ttl = line[1]
                    .parse::<u32>()
                    .map_err(RecordParseError::InvalidTtl)?;
                let record_type: RecordType =
                    FromStr::from_str(&line[3]).map_err(RecordParseError::InvalidRecord)?;
                let rdata = parse_record_data(&line[4], record_type)
                    .map_err(RecordParseError::InvalidRData)?;
                let record = Record::from_rdata(domain_name, ttl, rdata);
                Ok(record)
            }
        })
        .collect::<Vec<_>>();
    Ok(records_result)
}

pub fn parse_record_data(rdata: &str, record_type: RecordType) -> Result<RData, RDataParseError> {
    match record_type {
        RecordType::A | RecordType::AAAA => {
            let ip_addr = IpAddr::from_str(rdata).map_err(RDataParseError::InvalidIpAddr)?;
            Ok(match ip_addr {
                IpAddr::V4(ip) => RData::A(ip),
                IpAddr::V6(ip) => RData::AAAA(ip),
            })
        }
        RecordType::ANAME => {
            Ok(RData::ANAME(Name::from_str(rdata).map_err(|e| {
                RDataParseError::InvalidName(record_type, e)
            })?))
        }
        RecordType::CNAME => {
            Ok(RData::CNAME(Name::from_str(rdata).map_err(|e| {
                RDataParseError::InvalidName(record_type, e)
            })?))
        }
        RecordType::NS => {
            Ok(RData::NS(Name::from_str(rdata).map_err(|e| {
                RDataParseError::InvalidName(record_type, e)
            })?))
        }
        RecordType::PTR => {
            Ok(RData::PTR(Name::from_str(rdata).map_err(|e| {
                RDataParseError::InvalidName(record_type, e)
            })?))
        }
        RecordType::NULL => Ok(RData::NULL(NULL::with(rdata.as_bytes().to_owned()))),
        RecordType::Unknown(code) => Ok(RData::Unknown {
            code,
            rdata: NULL::with(rdata.as_bytes().to_owned()),
        }),
        _ => Ok(RData::Unknown {
            code: record_type.into(),
            rdata: NULL::with(rdata.as_bytes().to_owned()),
        }),
    }
}
