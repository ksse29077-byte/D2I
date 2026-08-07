#[cfg(windows)]
fn main() {
    std::process::exit(d2i_desktop::word_document_worker_main());
}

#[cfg(not(windows))]
fn main() {
    eprintln!("d2i-office200-word-worker requires Windows");
    std::process::exit(1);
}
