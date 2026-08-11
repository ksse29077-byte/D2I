use crate::validation::{validate_hash, validate_id};
use crate::{ResearchError, ResearchLinkSelectionV1, ZERO_HASH};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_SERVER_PAGES: usize = 24;
const MAX_SERVER_LINKS: usize = 12_288;
const MAX_SAFE_HTML_BYTES: usize = 1024 * 1024;
const MAX_HTTP_REQUEST_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct SnapshotServerPageV1 {
    pub session_id: String,
    pub page_id: String,
    pub safe_html: String,
}

#[derive(Debug, Clone)]
pub struct SnapshotServerLinkV1 {
    pub session_id: String,
    pub link_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub browser_session_sha256: String,
    pub source_snapshot_sha256: String,
}

pub struct SnapshotServerV1 {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    request_count: Arc<AtomicU64>,
    selections: Arc<Mutex<Vec<ResearchLinkSelectionV1>>>,
    thread: Option<JoinHandle<()>>,
}

impl SnapshotServerV1 {
    pub fn start(
        pages: Vec<SnapshotServerPageV1>,
        links: Vec<SnapshotServerLinkV1>,
    ) -> Result<Self, ResearchError> {
        let page_routes = validate_pages(pages)?;
        let link_routes = validate_links(links)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|error| ResearchError::Io(format!("snapshot server bind failed: {error}")))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| ResearchError::Io(format!("snapshot server mode failed: {error}")))?;
        let address = listener.local_addr().map_err(|error| {
            ResearchError::Io(format!("snapshot server address failed: {error}"))
        })?;
        let stop = Arc::new(AtomicBool::new(false));
        let request_count = Arc::new(AtomicU64::new(0));
        let selections = Arc::new(Mutex::new(Vec::new()));
        let thread_stop = Arc::clone(&stop);
        let thread_requests = Arc::clone(&request_count);
        let thread_selections = Arc::clone(&selections);
        let worker = thread::Builder::new()
            .name("d2i-office600-snapshot-server".to_owned())
            .spawn(move || {
                serve_loop(
                    listener,
                    page_routes,
                    link_routes,
                    thread_stop,
                    thread_requests,
                    thread_selections,
                );
            })
            .map_err(|error| ResearchError::Io(format!("snapshot server spawn failed: {error}")))?;
        Ok(Self {
            address,
            stop,
            request_count,
            selections,
            thread: Some(worker),
        })
    }

    pub fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    pub fn page_url(&self, session_id: &str, page_id: &str) -> Result<String, ResearchError> {
        validate_id(session_id, "snapshot server session ID")?;
        validate_id(page_id, "snapshot server page ID")?;
        Ok(format!(
            "{}/session/{session_id}/page/{page_id}",
            self.origin()
        ))
    }

    pub fn link_url(&self, session_id: &str, link_id: &str) -> Result<String, ResearchError> {
        validate_id(session_id, "snapshot server session ID")?;
        validate_id(link_id, "snapshot server link ID")?;
        Ok(format!(
            "{}/session/{session_id}/link/{link_id}",
            self.origin()
        ))
    }

    pub fn selections(&self) -> Result<Vec<ResearchLinkSelectionV1>, ResearchError> {
        self.selections
            .lock()
            .map(|value| value.clone())
            .map_err(|_| ResearchError::Integrity("snapshot selection lock poisoned".to_owned()))
    }

    pub fn request_count(&self) -> u64 {
        self.request_count.load(Ordering::SeqCst)
    }

    pub fn shutdown(mut self) -> Result<(), ResearchError> {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if self
            .thread
            .take()
            .is_some_and(|worker| worker.join().is_err())
        {
            return Err(ResearchError::Integrity(
                "snapshot server thread panicked".to_owned(),
            ));
        }
        Ok(())
    }
}

impl Drop for SnapshotServerV1 {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(worker) = self.thread.take() {
            let _ = worker.join();
        }
    }
}

fn validate_pages(
    pages: Vec<SnapshotServerPageV1>,
) -> Result<BTreeMap<String, String>, ResearchError> {
    if pages.is_empty() || pages.len() > MAX_SERVER_PAGES {
        return Err(ResearchError::Resource(
            "snapshot server page count is outside 1..=24".to_owned(),
        ));
    }
    let mut routes = BTreeMap::new();
    for page in pages {
        validate_id(&page.session_id, "snapshot server session ID")?;
        validate_id(&page.page_id, "snapshot server page ID")?;
        if page.safe_html.is_empty() || page.safe_html.len() > MAX_SAFE_HTML_BYTES {
            return Err(ResearchError::Resource(
                "safe snapshot HTML is empty or oversized".to_owned(),
            ));
        }
        let route = format!("/session/{}/page/{}", page.session_id, page.page_id);
        if routes.insert(route, page.safe_html).is_some() {
            return Err(ResearchError::Invalid(
                "snapshot server page route is duplicated".to_owned(),
            ));
        }
    }
    Ok(routes)
}

fn validate_links(
    links: Vec<SnapshotServerLinkV1>,
) -> Result<BTreeMap<String, SnapshotServerLinkV1>, ResearchError> {
    if links.len() > MAX_SERVER_LINKS {
        return Err(ResearchError::Resource(
            "snapshot server link count exceeds the reviewed bound".to_owned(),
        ));
    }
    let mut routes = BTreeMap::new();
    for link in links {
        validate_id(&link.session_id, "snapshot server session ID")?;
        validate_id(&link.link_id, "snapshot server link ID")?;
        validate_id(&link.organization_id, "snapshot link organization")?;
        validate_id(&link.case_id, "snapshot link Case")?;
        validate_hash(&link.browser_session_sha256, "snapshot browser session")?;
        validate_hash(&link.source_snapshot_sha256, "snapshot source")?;
        let route = format!("/session/{}/link/{}", link.session_id, link.link_id);
        if routes.insert(route, link).is_some() {
            return Err(ResearchError::Invalid(
                "snapshot server link route is duplicated".to_owned(),
            ));
        }
    }
    Ok(routes)
}

fn serve_loop(
    listener: TcpListener,
    pages: BTreeMap<String, String>,
    links: BTreeMap<String, SnapshotServerLinkV1>,
    stop: Arc<AtomicBool>,
    request_count: Arc<AtomicU64>,
    selections: Arc<Mutex<Vec<ResearchLinkSelectionV1>>>,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, peer)) if peer.ip().is_loopback() => {
                request_count.fetch_add(1, Ordering::SeqCst);
                let _ = serve_request(&mut stream, &pages, &links, &selections);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

fn serve_request(
    stream: &mut TcpStream,
    pages: &BTreeMap<String, String>,
    links: &BTreeMap<String, SnapshotServerLinkV1>,
    selections: &Arc<Mutex<Vec<ResearchLinkSelectionV1>>>,
) -> Result<(), ResearchError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| ResearchError::Io(error.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| ResearchError::Io(error.to_string()))?;
    let mut request = Vec::new();
    let mut bounded = stream.take((MAX_HTTP_REQUEST_BYTES + 1) as u64);
    let mut chunk = [0_u8; 1024];
    loop {
        let read = bounded
            .read(&mut chunk)
            .map_err(|error| ResearchError::Io(error.to_string()))?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|value| value == b"\r\n\r\n") {
            break;
        }
        if request.len() > MAX_HTTP_REQUEST_BYTES {
            return write_response(
                stream,
                413,
                "text/plain; charset=utf-8",
                b"request too large",
            );
        }
    }
    let first_line = request
        .split(|value| *value == b'\n')
        .next()
        .and_then(|value| std::str::from_utf8(value).ok())
        .map(str::trim)
        .unwrap_or_default();
    let mut parts = first_line.split_ascii_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method != "GET" || version != "HTTP/1.1" || parts.next().is_some() {
        return write_response(
            stream,
            405,
            "text/plain; charset=utf-8",
            b"method not allowed",
        );
    }
    if path == "/health" {
        return write_response(stream, 200, "text/plain; charset=utf-8", b"ok");
    }
    if let Some(html) = pages.get(path) {
        return write_response(stream, 200, "text/html; charset=utf-8", html.as_bytes());
    }
    if let Some(link) = links.get(path) {
        let selection = ResearchLinkSelectionV1 {
            schema_version: 1,
            selection_id: format!("selection:{}:{}", link.session_id, link.link_id),
            organization_id: link.organization_id.clone(),
            case_id: link.case_id.clone(),
            browser_session_sha256: link.browser_session_sha256.clone(),
            source_snapshot_sha256: link.source_snapshot_sha256.clone(),
            link_id: link.link_id.clone(),
            selected_at_unix_ms: unix_milliseconds()?,
            selection_sha256: ZERO_HASH.to_owned(),
        }
        .seal()?;
        selections
            .lock()
            .map_err(|_| ResearchError::Integrity("snapshot selection lock poisoned".to_owned()))?
            .push(selection);
        return write_response(
            stream,
            200,
            "text/html; charset=utf-8",
            b"<!doctype html><title>Source selected</title><p>Source selection recorded.</p>",
        );
    }
    write_response(stream, 404, "text/plain; charset=utf-8", b"not found")
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), ResearchError> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush())
        .map_err(|error| ResearchError::Io(format!("snapshot response failed: {error}")))
}

fn unix_milliseconds() -> Result<u64, ResearchError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ResearchError::Integrity(format!("system clock invalid: {error}")))?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| ResearchError::Resource("system time overflow".to_owned()))
}
