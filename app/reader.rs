use dns_collect::collect::AllDomains;
use std::fs::{read_dir, File};
use std::path::Path;

fn print_usage(this: &str) {
    eprintln!("usage: {} <source_dir>", this);
}

pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        print_usage(&args[0]);
        std::process::exit(1);
    }
    let mut all_domains = AllDomains::new();
    let source_dir = Path::new(&args[1]);
    if source_dir.is_dir() {
        for entry in read_dir(source_dir).unwrap() {
            let mut file = File::open(entry.unwrap().path()).unwrap();
            let domains: AllDomains = bincode::deserialize_from(&mut file).unwrap();
            all_domains.extend(domains.into_iter());
        }
    } else {
        panic!("{} is not a directory", source_dir.display());
    }
    for v in all_domains.values() {
        println!("{:#?}", v);
    }
}
