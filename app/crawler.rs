use dns_collect::collect::{collect, AllDomains};
use dns_collect::name_server::parse_name_servers_json;
use std::fs::{create_dir, File};
use std::path::{Path, PathBuf};
use std::thread;
use trust_dns_proto::rr::RecordType;

const REPEAT: usize = 10;
const BATCH: usize = 100;
const SAVE_EVERY: usize = 1000;
fn print_usage(this: &str) {
    eprintln!(
        "usage: {} <name-servers.csv> <top-k-websites.csv> <k> <target_dir>",
        this
    );
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
    if args.len() != 5 {
        print_usage(&args[0]);
        panic!();
    }

    let name_servers = parse_name_servers_json(Path::new(&args[1]));
    let top_websites_reader =
        csv::Reader::from_path(&args[2]).expect("Top websites file not found");
    let k = args[3].parse::<usize>().unwrap();
    let target_dir = PathBuf::from(args[4].clone());
    assert!(target_dir.exists());
    for name_server in name_servers.iter() {
        create_dir(target_dir.join(&name_server.name)).expect("Error creating name server dir");
    }

    let n_batches = (k + BATCH - 1) / BATCH;
    let mut record_iter = top_websites_reader.into_records().take(k).peekable();
    let mut batch_counter = 1usize;
    let mut accumulated = 0usize;

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
                let handle = thread::spawn(move || {
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
                            collect(
                                &name_server.host,
                                batch,
                                RecordType::A,
                                REPEAT,
                                &mut all_domains,
                            );
                        });
                    let filename = format!(
                        "{}-{}.txt",
                        accumulated + 1,
                        accumulated + domain_names.len()
                    );
                    let mut file =
                        File::create(target_dir.join(&name_server.name).join(&filename)).unwrap();
                    println!("{}: saving {}", name_server.name, filename);
                    bincode::serialize_into(&mut file, &all_domains).unwrap();
                });
                handle
            })
            .collect::<Vec<_>>();
        handles.into_iter().for_each(|h| h.join().unwrap());
        batch_counter += (domain_names.len() + BATCH - 1) / BATCH;
        accumulated += domain_names.len();
    }
}
