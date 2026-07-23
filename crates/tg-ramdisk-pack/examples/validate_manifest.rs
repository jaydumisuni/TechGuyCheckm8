use std::env;
use std::fs;
use std::process::ExitCode;

use tg_ramdisk_pack::{validate_pack, RamdiskProviderPack};

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: validate_manifest <provider-pack.runtime.json>");
        return ExitCode::from(2);
    };
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read {path}: {error}");
            return ExitCode::from(2);
        }
    };
    let pack: RamdiskProviderPack = match serde_json::from_slice(&bytes) {
        Ok(pack) => pack,
        Err(error) => {
            eprintln!("cannot decode runtime provider pack: {error}");
            return ExitCode::from(2);
        }
    };
    match validate_pack(&pack) {
        Ok(()) => {
            println!("validated provider pack: {}", pack.pack_id);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("provider pack validation failed: {error}");
            ExitCode::from(2)
        }
    }
}
