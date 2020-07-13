use dns_collect::collect::AllDomains;
use std::collections::{HashMap, HashSet};
use std::fs::{read_dir, File};
use std::path::Path;

fn print_usage(this: &str) {
    eprintln!("usage: {} <source_dir>", this);
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

pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        print_usage(&args[0]);
        std::process::exit(1);
    }
    let dir = Path::new(&args[1]);
    let mut all_ns = Vec::<(String, AllDomains)>::new();
    if dir.is_dir() {
        for entry in read_dir(dir).unwrap() {
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
        panic!("{} is not a directory", dir.display());
    }

    for (ns, v) in all_ns.iter() {
        println!("{} count: {}", ns, v.len());
    }
    let all_keys = all_ns
        .iter()
        .map(|v| v.1.keys().collect::<HashSet<_>>())
        .collect::<Vec<_>>();
    println!(
        "{} -- {} count {}",
        all_ns[0].0,
        all_ns[1].0,
        all_keys[0].intersection(&all_keys[1]).count()
    );
    println!(
        "{} -- {} count {}",
        all_ns[0].0,
        all_ns[2].0,
        all_keys[0].intersection(&all_keys[2]).count()
    );
    println!(
        "{} -- {} count {}",
        all_ns[1].0,
        all_ns[2].0,
        all_keys[1].intersection(&all_keys[2]).count()
    );
}
