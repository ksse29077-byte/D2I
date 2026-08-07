fn main() {
    if let Err(error) = d2i_desktop::reference_enterprise_server_main() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
