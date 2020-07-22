use dns_collect::collect::AllDomains;
use dns_collect::record_wrapper::RecordWrapper;
use std::collections::HashSet;
use std::fmt::Write;
use std::fs::{read_dir, File};
use std::path::Path;
use std::str::FromStr;
use trust_dns_proto::rr::Name;

#[derive(Eq, Clone)]
struct DnsAnswers<'a>(pub HashSet<&'a RecordWrapper>);

impl<'a> PartialEq for DnsAnswers<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.0.intersection(&other.0).count() > 0
    }
}

impl<'a> std::hash::Hash for DnsAnswers<'a> {
    fn hash<H>(&self, hasher: &mut H)
    where
        H: std::hash::Hasher,
    {
        for i in &self.0 {
            i.hash(hasher);
        }
    }

}

fn print_usage(this: &str) {
    eprintln!("usage: {} <source_dir> <cisco-top-1m.csv>", this);
}

fn read_from_dir(dir: &Path) -> AllDomains {
    let mut all_domains = AllDomains::new();
    if dir.is_dir() {
        for entry in read_dir(dir).unwrap() {
            let mut file = File::open(entry.unwrap().path()).unwrap();
            let domains: AllDomains = bincode::deserialize_from(&mut file).unwrap();
            all_domains.extend(domains.into_iter());
        }
    } else {
        panic!("{} is not a directory", dir.display());
    }
    all_domains
}

fn take_n(
    n: usize,
    record_iter: &mut impl Iterator<Item = csv::Result<csv::StringRecord>>,
) -> Vec<String> {
    let mut domain_names = Vec::new();
    for _ in 0..n {
        match record_iter.next() {
            Some(line) => {
                let domain_name = line.unwrap().get(1).unwrap().to_owned();
                domain_names.push(domain_name);
            }
            None => {
                break;
            }
        }
    }
    domain_names
}

fn print_dist(file_path: &str, all_ns: &[(String, AllDomains)]) {
    let top_domains_reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(file_path)
        .expect("Top websites file not found");

    let mut top_domains_reader = top_domains_reader.into_records();
    let top_k_domains = take_n(100000, &mut top_domains_reader);

    let bin_size = 100;

    let mut buf = String::new();
    for (ns, _) in all_ns.iter() {
        write!(&mut buf, "{},", ns).unwrap();
    }
    buf.pop();
    println!("{}", buf);
    for bin in top_k_domains.chunks(bin_size) {
        let top_domain_counts = all_ns
            .iter()
            .map(|(_, v)| {
                bin.iter()
                    .filter(|domain_str| {
                        let mut domain = Name::from_str(domain_str).unwrap();
                        domain.set_fqdn(true);
                        let b = v.contains_key(&domain);
                        //if !b {
                        //println!("{:?}", domain_str);
                        //}
                        b
                    })
                    .count()
            })
            .collect::<Vec<usize>>();
        let mut buf = String::new();
        for count in top_domain_counts {
            write!(&mut buf, "{},", count).unwrap();
        }
        buf.pop();
        println!("{}", buf);
    }
}

fn print_overlaps(all_ns: &[(String, AllDomains)]) {
    for (ns, v) in all_ns.iter() {
        println!("|{}| = {}", ns, v.len());
    }
    let all_keys = all_ns
        .iter()
        .map(|v| v.1.keys().collect::<HashSet<_>>())
        .collect::<Vec<_>>();
    let mut union1 = HashSet::<&Name>::new();
    let mut union1_str = String::new();
    all_keys
        .iter()
        .zip(all_ns.iter().map(|(k, _)| k))
        .for_each(|(v, k)| {
            union1.extend(v);
            write!(&mut union1_str, "{} ∪ ", k).unwrap();
        });
    union1_str.pop();
    union1_str.pop();
    println!("|{}| = {}", union1_str, union1.len());

    let mut union2 = HashSet::<&&Name>::new();
    let mut union2_str = String::new();
    for i in 0..all_ns.len() - 1 {
        for j in i + 1..all_ns.len() {
            let intersect = all_keys[i]
                .intersection(&all_keys[j])
                .collect::<HashSet<_>>();
            println!("|{} ∩ {}| = {}", all_ns[i].0, all_ns[j].0, intersect.len());
            union2.extend(intersect.into_iter());
            write!(&mut union2_str, "({} ∩ {}) ∪ ", all_ns[i].0, all_ns[j].0).unwrap();
        }
    }
    union2_str.pop();
    union2_str.pop();
    println!("|{}| = {}", union2_str, union2.len());

    let mut union3 = HashSet::<&Name>::new();
    let mut union3_str = String::new();
    for i in 0..all_ns.len() - 2 {
        for j in i + 1..all_ns.len() - 1 {
            for k in j + 1..all_ns.len() {
                let tmp = all_keys[i]
                    .intersection(&all_keys[j])
                    .cloned()
                    .collect::<HashSet<_>>();
                let intersect = tmp
                    .intersection(&all_keys[k])
                    .cloned()
                    .collect::<HashSet<_>>();
                println!(
                    "|{} ∩ {} ∩ {}| = {}",
                    all_ns[i].0,
                    all_ns[j].0,
                    all_ns[k].0,
                    intersect.len()
                );
                union3.extend(intersect.into_iter());
                write!(
                    &mut union3_str,
                    "({} ∩ {} ∩ {}) ∪ ",
                    all_ns[i].0, all_ns[j].0, all_ns[k].0
                )
                .unwrap();
            }
        }
    }

    union3_str.pop();
    union3_str.pop();
    union3_str.pop();
    println!("|{}| = {}", union3_str, union3.len());
}

fn print_overlaps_record(all_ns: &[(String, AllDomains)]) {
    let all_records = all_ns
        .iter()
        .map(|v| {
            v.1.iter()
                .map(|(k, v)| (k, DnsAnswers(v.keys().collect())))
                .collect::<HashSet<(&Name, DnsAnswers)>>()
        })
    .collect::<Vec<_>>();
    let mut union1 = HashSet::<&(&Name, DnsAnswers)>::new();
    let mut union1_str = String::new();
    all_records.iter().zip(all_ns.iter().map(|(k, _)| k)).for_each(|(v, k)| {
        union1.extend(v);
        write!(&mut union1_str, "{} ∪ ", k).unwrap();
    });
    union1_str.pop();
    union1_str.pop();
    println!("|{}| = {}", union1_str, union1.len());

    let mut union2 = HashSet::<&(&Name, DnsAnswers)>::new();
    let mut union2_str = String::new();
    for i in 0..all_ns.len() - 1 {
        for j in i + 1..all_ns.len() {
            let intersect = all_records[i]
                .intersection(&all_records[j])
                .collect::<HashSet<_>>();
            println!("|{} ∩ {}| = {}", all_ns[i].0, all_ns[j].0, intersect.len());
            union2.extend(intersect.into_iter());
            write!(&mut union2_str, "({} ∩ {}) ∪ ", all_ns[i].0, all_ns[j].0).unwrap();
        }
    }
    union2_str.pop();
    union2_str.pop();
    println!("|{}| = {}", union2_str, union2.len());

    let mut union3 = HashSet::<(&Name, DnsAnswers)>::new();
    let mut union3_str = String::new();
    for i in 0..all_ns.len() - 2 {
        for j in i + 1..all_ns.len() - 1 {
            for k in j + 1..all_ns.len() {
                let tmp = all_records[i]
                    .intersection(&all_records[j])
                    .cloned()
                    .collect::<HashSet<_>>();
                let intersect = tmp
                    .intersection(&all_records[k])
                    .cloned()
                    .collect::<HashSet<_>>();
                println!(
                    "|{} ∩ {} ∩ {}| = {}",
                    all_ns[i].0,
                    all_ns[j].0,
                    all_ns[k].0,
                    intersect.len()
                );
                union3.extend(intersect.into_iter());
                write!(
                    &mut union3_str,
                    "({} ∩ {} ∩ {}) ∪ ",
                    all_ns[i].0, all_ns[j].0, all_ns[k].0
                )
                .unwrap();
            }
        }
    }

    union3_str.pop();
    union3_str.pop();
    union3_str.pop();
    println!("|{}| = {}", union3_str, union3.len());
}

pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        print_usage(&args[0]);
        std::process::exit(1);
    }
    let mut all_ns = Vec::<(String, AllDomains)>::new();
    let dns_dir = Path::new(&args[1]);
    if dns_dir.is_dir() {
        for entry in read_dir(dns_dir).unwrap() {
            let entry = entry.unwrap();
            let dir_name = entry
                .path()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            all_ns.push((dir_name, read_from_dir(&entry.path())));
        }
    } else {
        panic!("{} is not a directory", dns_dir.display());
    }
    print_dist(args[0].as_ref(), &all_ns[..]);
    println!("=== Domain Name Stats ===");
    print_overlaps(&all_ns[..]);
    println!("=== Record Stats ===");
    print_overlaps_record(&all_ns[..]);
}
