fn main() {
    if let Err(error) = d2i_desktop::connector_worker_main() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
