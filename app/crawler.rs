use dns_collect::collect::{collect, AllDomains};
use dns_collect::name_server::{parse_name_servers_json, NameServer};

use std::fs::{create_dir, File};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
use trust_dns_proto::rr::RecordType;

const REPEAT: usize = 10;
const BATCH: usize = 100;
const SAVE_EVERY: usize = 1000;
fn print_usage(this: &str) {
    eprintln!(
        "usage: {} <A | AAAA> <name-servers.json> <top-k-websites.csv> <k> <target_dir>",
        this
    );
}

fn print_info(name_servers: &[NameServer], k: usize) {
    eprintln!("####### crawler information #######");
    eprintln!();
    eprintln!("all name servers:");
    for n in name_servers {
        eprintln!("\t{}: {}", n.name, n.host);
    }
    eprintln!("crawl top k:\t\t\t{}", k);
    eprintln!("#repeats per domain:\t\t{}", REPEAT);
    eprintln!("batch size:\t\t\t{}", BATCH);
    eprintln!("#batches:\t\t\t{}", (k + BATCH - 1) / BATCH);
    eprintln!("#queries per batch:\t\t{}", BATCH * REPEAT);
    eprintln!("#total queries per server:\t{}", k * REPEAT);
    eprintln!("#domains per saved file:\t{}", SAVE_EVERY);
    eprintln!();
    eprintln!("###################################");
    eprintln!();
    eprintln!("######### begin crawling ##########");
    eprintln!();
}

fn print_done(time: Duration) {
    eprintln!();
    eprintln!("############## done! ##############");
    eprintln!();
    eprintln!("time spent: {} minutes", (time.as_secs() + 60 - 1) / 60);
    eprintln!();
    eprintln!("#################### ##############");
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        print_usage(&args[0]);
        return;
    }

    let record_type = match args[1].as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        _ => panic!("Invalid record type {}", args[1]),
    };
    let name_servers = parse_name_servers_json(Path::new(&args[2]));
    let top_websites_reader =
        csv::Reader::from_path(&args[3]).expect("Top websites file not found");
    let k = args[4].parse::<usize>().unwrap();
    let target_dir = PathBuf::from(args[5].clone());
    assert!(target_dir.exists());
    for name_server in name_servers.iter() {
        create_dir(target_dir.join(&name_server.name)).expect("Error creating name server dir");
    }

    let n_batches = (k + BATCH - 1) / BATCH;

    print_info(name_servers.as_slice(), k);

    let mut record_iter = top_websites_reader.into_records().take(k).peekable();
    let mut batch_counter = 1usize;
    let mut accumulated = 0usize;

    let now = Instant::now();

    loop {
        let domain_names = take_n(SAVE_EVERY, &mut record_iter);
        if domain_names.is_empty() {
            break;
        }
        let handles = name_servers
            .iter()
            .cloned()
            .map(|name_server| {
                let domain_names = domain_names.clone();
                let target_dir = target_dir.clone();
                thread::spawn(move || {
                    let mut all_domains = AllDomains::new();
                    domain_names
                        .as_slice()
                        .chunks(BATCH)
                        .enumerate()
                        .for_each(|(i, batch)| {
                            eprintln!(
                                "{}: processing batch {}/{} ...",
                                name_server.name,
                                batch_counter + i,
                                n_batches
                            );
                            collect(&name_server, batch, record_type, REPEAT, &mut all_domains);
                        });
                    let filename = format!(
                        "{}-{}.txt",
                        accumulated + 1,
                        accumulated + domain_names.len()
                    );
                    let file_path = target_dir.join(&name_server.name).join(&filename);
                    let mut file = File::create(&file_path).unwrap();
                    eprintln!(
                        "{}: saving {} ...",
                        name_server.name,
                        file_path.to_str().unwrap()
                    );
                    bincode::serialize_into(&mut file, &all_domains).unwrap();
                })
            })
            .collect::<Vec<_>>();
        handles.into_iter().for_each(|h| h.join().unwrap());
        batch_counter += (domain_names.len() + BATCH - 1) / BATCH;
        accumulated += domain_names.len();
    }
    print_done(now.elapsed());
}
