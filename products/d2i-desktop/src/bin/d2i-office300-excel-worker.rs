#[cfg(windows)]
fn main() {
    std::process::exit(d2i_desktop::excel_spreadsheet_worker_main());
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Excel worker requires Windows desktop Office deployment");
    std::process::exit(2);
}
