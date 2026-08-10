#[cfg(windows)]
fn main() {
    std::process::exit(d2i_desktop::powerpoint_pdf_export_worker_main());
}

#[cfg(not(windows))]
fn main() {
    eprintln!("PowerPoint PDF worker requires Windows");
    std::process::exit(1);
}
