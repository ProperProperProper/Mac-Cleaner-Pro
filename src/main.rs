fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = mac_cleaner_pro::cli::run(&args) {
        std::process::exit(code);
    }
    if let Err(e) = mac_cleaner_pro::gui::run_gui() {
        eprintln!("could not start the app: {e}");
        std::process::exit(1);
    }
}
