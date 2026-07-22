use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 1 || args[0] != "-q" {
        eprintln!("fixture accepts only the read-only -q profile");
        return ExitCode::from(2);
    }

    println!("CPID: 0x8020");
    println!("CPRV: 0x11");
    println!("BDID: 0x0e");
    println!("ECID: 0xdeadbeef00000001");
    println!("CPFM: 0x03");
    println!("SCEP: 0x01");
    println!("IBFL: 0x3c");
    println!("SRTG: [iBoot-SYNTHETIC]");
    println!("SRNM: N/A");
    println!("IMEI: N/A");
    println!("NONC: N/A");
    println!("SNON: N/A");
    println!("PWND: usbliter8");
    println!("MODE: DFU");
    println!("PRODUCT: iPhone11,6");
    println!("MODEL: d331pap");
    println!("NAME: Synthetic iPhone XS Max");
    ExitCode::SUCCESS
}
