use std::io::{self, Write};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

fn main() -> ExitCode {
    let scenario = argument("--scenario").unwrap_or_else(|| "success".to_owned());
    match scenario.as_str() {
        "success" => {
            println!("{}", serde_json::json!({"event":"ready"}));
            println!("{}", serde_json::json!({"event":"completed"}));
            ExitCode::SUCCESS
        }
        "failure" => {
            eprintln!(
                "{}",
                serde_json::json!({"event":"failed","code":"fixture_failure"})
            );
            ExitCode::from(7)
        }
        "hang" => {
            println!("{}", serde_json::json!({"event":"started"}));
            let _ = io::stdout().flush();
            let sleep_millis = argument("--sleep-ms")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(5_000);
            thread::sleep(Duration::from_millis(sleep_millis));
            println!("{}", serde_json::json!({"event":"completed"}));
            ExitCode::SUCCESS
        }
        "spam" => {
            let bytes = argument("--bytes")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(32_768);
            print!("{}", "O".repeat(bytes));
            eprint!("{}", "E".repeat(bytes));
            let _ = io::stdout().flush();
            let _ = io::stderr().flush();
            ExitCode::SUCCESS
        }
        "environment" => {
            println!(
                "{}",
                serde_json::json!({
                    "allowed": std::env::var("TGCHECKM8_ALLOWED").ok(),
                    "path_present": std::env::var_os("PATH").is_some(),
                    "unexpected_present": std::env::var_os("TGCHECKM8_UNEXPECTED").is_some()
                })
            );
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "{}",
                serde_json::json!({"event":"failed","code":"unknown_scenario"})
            );
            ExitCode::from(64)
        }
    }
}

fn argument(name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    std::env::args()
        .skip(1)
        .find_map(|argument| argument.strip_prefix(&prefix).map(str::to_owned))
}
