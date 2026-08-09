#[cfg(windows)]
fn main() {
    std::process::exit(d2i_desktop::powerpoint_presentation_worker_main());
}

#[cfg(not(windows))]
fn main() {
    eprintln!("PowerPoint worker is available only on Windows");
    std::process::exit(1);
}
