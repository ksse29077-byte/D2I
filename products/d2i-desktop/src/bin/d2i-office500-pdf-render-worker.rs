#[cfg(windows)]
fn main() {
    std::process::exit(d2i_desktop::pdf_render_worker_main());
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Windows PDF render worker requires Windows");
    std::process::exit(1);
}
