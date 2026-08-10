#[cfg(windows)]
fn main() {
    std::process::exit(d2i_desktop::excel_pdf_export_worker_main());
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Excel PDF worker requires Windows");
    std::process::exit(1);
}
