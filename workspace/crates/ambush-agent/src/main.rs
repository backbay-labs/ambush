fn main() {
    if let Err(e) = ambush_agent::run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
