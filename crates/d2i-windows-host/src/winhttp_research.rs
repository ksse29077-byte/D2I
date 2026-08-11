use super::WindowsHostError;
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::mem::{size_of, size_of_val};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::time::Instant;
use windows::core::PCWSTR;
use windows::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpConnectionEstablishmentEnd,
    WinHttpConnectionEstablishmentStart, WinHttpNameResolutionEnd, WinHttpNameResolutionStart,
    WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders, WinHttpQueryOption, WinHttpReadData,
    WinHttpReceiveResponse, WinHttpReceiveResponseEnd, WinHttpReceiveResponseStart,
    WinHttpRequestTimeLast, WinHttpSendRequest, WinHttpSendRequestEnd, WinHttpSetOption,
    WinHttpSetTimeouts, WinHttpTlsHandshakeClientLeg1End, WinHttpTlsHandshakeClientLeg1Start,
    WinHttpTlsHandshakeClientLeg2End, WinHttpTlsHandshakeClientLeg2Start,
    WinHttpTlsHandshakeClientLeg3End, WinHttpTlsHandshakeClientLeg3Start,
    WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_CONNECTION_INFO, WINHTTP_DECOMPRESSION_FLAG_DEFLATE,
    WINHTTP_DECOMPRESSION_FLAG_GZIP, WINHTTP_DISABLE_AUTHENTICATION, WINHTTP_DISABLE_COOKIES,
    WINHTTP_DISABLE_KEEP_ALIVE, WINHTTP_DISABLE_REDIRECTS, WINHTTP_FLAG_SECURE,
    WINHTTP_FLAG_SECURE_DEFAULTS, WINHTTP_OPTION_CONNECTION_INFO, WINHTTP_OPTION_DECOMPRESSION,
    WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_OPTION_REQUEST_TIMES,
    WINHTTP_OPTION_SERVER_CERT_CONTEXT, WINHTTP_QUERY_CONTENT_DISPOSITION,
    WINHTTP_QUERY_CONTENT_ENCODING, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_QUERY_CONTENT_TYPE,
    WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_LOCATION, WINHTTP_QUERY_RAW_HEADERS_CRLF,
    WINHTTP_QUERY_STATUS_CODE, WINHTTP_REQUEST_TIMES,
};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_STORAGE,
};
use windows::Win32::Security::Cryptography::{CertFreeCertificateContext, CERT_CONTEXT};
use windows::Win32::System::Performance::QueryPerformanceFrequency;

const READ_CHUNK_BYTES: usize = 64 * 1024;
const MAX_HEADER_QUERY_BYTES: u32 = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsResearchHttpMethod {
    Get,
    Head,
}

#[derive(Debug, Clone)]
pub struct WindowsWinHttpRequest<'a> {
    pub host: &'a str,
    pub path_and_query: &'a str,
    pub method: WindowsResearchHttpMethod,
    pub connect_timeout_milliseconds: u64,
    pub receive_timeout_milliseconds: u64,
    pub maximum_header_bytes: u64,
    pub maximum_response_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct WindowsWinHttpResponse {
    pub status_code: u16,
    pub content_type: String,
    pub declared_content_length: Option<u64>,
    pub content_encoding: String,
    pub content_disposition: Option<String>,
    pub location: Option<String>,
    pub total_header_bytes: u64,
    pub remote_address: IpAddr,
    pub certificate_sha256: String,
    pub body: Vec<u8>,
    pub dns_microseconds: u64,
    pub connect_microseconds: u64,
    pub tls_microseconds: u64,
    pub ttfb_microseconds: u64,
    pub transfer_microseconds: u64,
    pub elapsed_microseconds: u64,
}

struct WinHttpHandle(*mut c_void);

impl WinHttpHandle {
    fn new(value: *mut c_void, operation: &str) -> Result<Self, WindowsHostError> {
        if value.is_null() {
            return Err(last_error(operation));
        }
        Ok(Self(value))
    }
}

impl Drop for WinHttpHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper owns the non-null WinHTTP handle exactly once.
            let _ = unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

pub fn winhttp_research_request(
    request: WindowsWinHttpRequest<'_>,
) -> Result<WindowsWinHttpResponse, WindowsHostError> {
    validate_request(&request)?;
    let started = Instant::now();
    let agent = wide_null("D2I-OFFICE-600/1.0");
    // SAFETY: all strings are NUL-terminated, proxy parameters are intentionally null,
    // and each returned handle is immediately wrapped in single-owner RAII.
    let session = WinHttpHandle::new(
        unsafe {
            WinHttpOpen(
                PCWSTR(agent.as_ptr()),
                WINHTTP_ACCESS_TYPE_NO_PROXY,
                PCWSTR::null(),
                PCWSTR::null(),
                WINHTTP_FLAG_SECURE_DEFAULTS,
            )
        },
        "WinHttpOpen",
    )?;
    let connect_timeout = timeout_i32(request.connect_timeout_milliseconds)?;
    let receive_timeout = timeout_i32(request.receive_timeout_milliseconds)?;
    // SAFETY: session is a valid WinHTTP session handle and timeout values are bounded.
    unsafe {
        WinHttpSetTimeouts(
            session.0,
            connect_timeout,
            connect_timeout,
            connect_timeout,
            receive_timeout,
        )
        .map_err(|error| windows_error("WinHttpSetTimeouts", error))?;
    }
    let host = wide_null(request.host);
    // SAFETY: session is valid and host is NUL-terminated for the fixed HTTPS port.
    let connection = WinHttpHandle::new(
        unsafe { WinHttpConnect(session.0, PCWSTR(host.as_ptr()), 443, 0) },
        "WinHttpConnect",
    )?;
    let method = wide_null(match request.method {
        WindowsResearchHttpMethod::Get => "GET",
        WindowsResearchHttpMethod::Head => "HEAD",
    });
    let path = wide_null(request.path_and_query);
    // SAFETY: connection is valid, verb/path are NUL-terminated, and no caller-controlled
    // header, referrer, accept list, or non-TLS flag is admitted here.
    let http_request = WinHttpHandle::new(
        unsafe {
            WinHttpOpenRequest(
                connection.0,
                PCWSTR(method.as_ptr()),
                PCWSTR(path.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                ptr::null(),
                WINHTTP_FLAG_SECURE,
            )
        },
        "WinHttpOpenRequest",
    )?;
    let disabled = WINHTTP_DISABLE_COOKIES
        | WINHTTP_DISABLE_REDIRECTS
        | WINHTTP_DISABLE_AUTHENTICATION
        | WINHTTP_DISABLE_KEEP_ALIVE;
    set_u32_option(http_request.0, WINHTTP_OPTION_DISABLE_FEATURE, disabled)?;
    set_u32_option(
        http_request.0,
        WINHTTP_OPTION_DECOMPRESSION,
        WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE,
    )?;
    let fixed_headers = wide_without_null(
        "Accept: text/html,application/xhtml+xml,application/pdf,text/plain,text/csv,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.openxmlformats-officedocument.presentationml.presentation,image/png,image/jpeg\r\nAccept-Encoding: gzip, deflate\r\nCache-Control: no-store\r\nPragma: no-cache\r\n",
    );
    // SAFETY: request is valid and the only headers are this fixed compile-time set.
    unsafe {
        WinHttpSendRequest(http_request.0, Some(&fixed_headers), None, 0, 0, 0)
            .map_err(|error| windows_error("WinHttpSendRequest", error))?;
        WinHttpReceiveResponse(http_request.0, ptr::null_mut())
            .map_err(|error| windows_error("WinHttpReceiveResponse", error))?;
    }
    let raw_headers = query_required_header(http_request.0, WINHTTP_QUERY_RAW_HEADERS_CRLF)?;
    let total_header_bytes = u64::try_from(raw_headers.len().saturating_mul(2))
        .map_err(|_| WindowsHostError::new("response header length overflow"))?;
    if total_header_bytes > request.maximum_header_bytes {
        return Err(WindowsHostError::new(
            "WinHTTP response header budget exceeded",
        ));
    }
    let status_value = query_u32_header(
        http_request.0,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
    )?;
    let status_code = u16::try_from(status_value)
        .map_err(|_| WindowsHostError::new("HTTP status code exceeds u16"))?;
    let content_type = query_optional_header(http_request.0, WINHTTP_QUERY_CONTENT_TYPE)?
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    let content_encoding = query_optional_header(http_request.0, WINHTTP_QUERY_CONTENT_ENCODING)?
        .unwrap_or_else(|| "identity".to_owned());
    let normalized_encoding = content_encoding.trim().to_ascii_lowercase();
    if !matches!(
        normalized_encoding.as_str(),
        "" | "identity" | "gzip" | "deflate"
    ) {
        return Err(WindowsHostError::new("unsupported HTTP content encoding"));
    }
    let declared_content_length =
        query_optional_header(http_request.0, WINHTTP_QUERY_CONTENT_LENGTH)?
            .map(|value| {
                value
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| WindowsHostError::new("invalid Content-Length"))
            })
            .transpose()?;
    if declared_content_length.is_some_and(|value| value > request.maximum_response_bytes) {
        return Err(WindowsHostError::new(
            "declared response body exceeds budget",
        ));
    }
    let remote_address = query_remote_address(http_request.0)?;
    let certificate_sha256 = query_certificate_sha256(http_request.0)?;
    let location = query_optional_header(http_request.0, WINHTTP_QUERY_LOCATION)?;
    let content_disposition =
        query_optional_header(http_request.0, WINHTTP_QUERY_CONTENT_DISPOSITION)?;
    let body =
        if request.method == WindowsResearchHttpMethod::Head || (300..400).contains(&status_code) {
            Vec::new()
        } else {
            read_bounded_body(http_request.0, request.maximum_response_bytes)?
        };
    let request_times = query_request_times(http_request.0)?;
    Ok(WindowsWinHttpResponse {
        status_code,
        content_type,
        declared_content_length,
        content_encoding: normalized_encoding,
        content_disposition,
        location,
        total_header_bytes,
        remote_address,
        certificate_sha256,
        body,
        dns_microseconds: request_times.dns_microseconds,
        connect_microseconds: request_times.connect_microseconds,
        tls_microseconds: request_times.tls_microseconds,
        ttfb_microseconds: request_times.ttfb_microseconds,
        transfer_microseconds: request_times.transfer_microseconds,
        elapsed_microseconds: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
    })
}

#[derive(Debug, Clone, Copy)]
struct RequestTimingMetrics {
    dns_microseconds: u64,
    connect_microseconds: u64,
    tls_microseconds: u64,
    ttfb_microseconds: u64,
    transfer_microseconds: u64,
}

fn query_request_times(handle: *mut c_void) -> Result<RequestTimingMetrics, WindowsHostError> {
    let mut times = WINHTTP_REQUEST_TIMES {
        cTimes: u32::try_from(WinHttpRequestTimeLast.0)
            .map_err(|_| WindowsHostError::new("WinHTTP request time count is invalid"))?,
        ..Default::default()
    };
    let mut bytes = u32::try_from(size_of::<WINHTTP_REQUEST_TIMES>())
        .map_err(|_| WindowsHostError::new("WinHTTP request times size overflow"))?;
    // SAFETY: output points to a correctly sized WINHTTP_REQUEST_TIMES structure.
    unsafe {
        WinHttpQueryOption(
            handle,
            WINHTTP_OPTION_REQUEST_TIMES,
            Some(ptr::addr_of_mut!(times).cast()),
            &mut bytes,
        )
        .map_err(|error| windows_error("WinHttpQueryOption request times", error))?;
    }
    let mut frequency = 0_i64;
    // SAFETY: output points to one writable LARGE_INTEGER-compatible i64.
    unsafe {
        QueryPerformanceFrequency(&mut frequency)
            .map_err(|error| windows_error("QueryPerformanceFrequency", error))?;
    }
    if frequency <= 0 {
        return Err(WindowsHostError::new(
            "performance counter frequency is invalid",
        ));
    }
    let interval = |start: i32, end: i32| -> u64 {
        let Ok(start) = usize::try_from(start) else {
            return 0;
        };
        let Ok(end) = usize::try_from(end) else {
            return 0;
        };
        let Some(start) = times.rgullTimes.get(start).copied() else {
            return 0;
        };
        let Some(end) = times.rgullTimes.get(end).copied() else {
            return 0;
        };
        if start == 0 || end < start {
            return 0;
        }
        end.saturating_sub(start)
            .saturating_mul(1_000_000)
            .checked_div(frequency as u64)
            .unwrap_or(0)
    };
    let tls_microseconds = interval(
        WinHttpTlsHandshakeClientLeg1Start.0,
        WinHttpTlsHandshakeClientLeg1End.0,
    )
    .saturating_add(interval(
        WinHttpTlsHandshakeClientLeg2Start.0,
        WinHttpTlsHandshakeClientLeg2End.0,
    ))
    .saturating_add(interval(
        WinHttpTlsHandshakeClientLeg3Start.0,
        WinHttpTlsHandshakeClientLeg3End.0,
    ));
    Ok(RequestTimingMetrics {
        dns_microseconds: interval(WinHttpNameResolutionStart.0, WinHttpNameResolutionEnd.0),
        connect_microseconds: interval(
            WinHttpConnectionEstablishmentStart.0,
            WinHttpConnectionEstablishmentEnd.0,
        ),
        tls_microseconds,
        ttfb_microseconds: interval(WinHttpSendRequestEnd.0, WinHttpReceiveResponseStart.0),
        transfer_microseconds: interval(WinHttpReceiveResponseStart.0, WinHttpReceiveResponseEnd.0),
    })
}

fn validate_request(request: &WindowsWinHttpRequest<'_>) -> Result<(), WindowsHostError> {
    if request.host.is_empty()
        || request.host.len() > 253
        || !request.host.is_ascii()
        || request.host.contains(['/', ':', '@'])
        || request.path_and_query.is_empty()
        || !request.path_and_query.starts_with('/')
        || request.path_and_query.len() > 4096
        || request.path_and_query.chars().any(char::is_control)
        || request.maximum_header_bytes == 0
        || request.maximum_header_bytes > 128 * 1024
        || request.maximum_response_bytes == 0
        || request.maximum_response_bytes > 256 * 1024 * 1024
    {
        return Err(WindowsHostError::new(
            "WinHTTP research request is outside fixed bounds",
        ));
    }
    Ok(())
}

fn timeout_i32(value: u64) -> Result<i32, WindowsHostError> {
    i32::try_from(value)
        .map_err(|_| WindowsHostError::new("WinHTTP timeout exceeds signed 32-bit range"))
}

fn set_u32_option(handle: *mut c_void, option: u32, value: u32) -> Result<(), WindowsHostError> {
    let bytes = value.to_ne_bytes();
    // SAFETY: handle is valid and the option buffer is exactly one u32.
    unsafe { WinHttpSetOption(Some(handle.cast_const()), option, Some(&bytes)) }
        .map_err(|error| windows_error("WinHttpSetOption", error))
}

fn query_u32_header(handle: *mut c_void, query: u32) -> Result<u32, WindowsHostError> {
    let mut value = 0_u32;
    let mut bytes = u32::try_from(size_of_val(&value))
        .map_err(|_| WindowsHostError::new("header integer size overflow"))?;
    let mut index = 0_u32;
    // SAFETY: output points to a writable u32 with the exact byte length.
    unsafe {
        WinHttpQueryHeaders(
            handle,
            query,
            PCWSTR::null(),
            Some(ptr::addr_of_mut!(value).cast()),
            &mut bytes,
            &mut index,
        )
        .map_err(|error| windows_error("WinHttpQueryHeaders integer", error))?;
    }
    Ok(value)
}

fn query_required_header(handle: *mut c_void, query: u32) -> Result<String, WindowsHostError> {
    query_optional_header(handle, query)?
        .ok_or_else(|| WindowsHostError::new("required WinHTTP response header is absent"))
}

fn query_optional_header(
    handle: *mut c_void,
    query: u32,
) -> Result<Option<String>, WindowsHostError> {
    let mut bytes = 0_u32;
    let mut index = 0_u32;
    // SAFETY: the first call intentionally requests the exact output size.
    let first =
        unsafe { WinHttpQueryHeaders(handle, query, PCWSTR::null(), None, &mut bytes, &mut index) };
    if bytes == 0 {
        if first.is_ok() {
            return Ok(Some(String::new()));
        }
        return Ok(None);
    }
    let units = bounded_header_units(bytes)?;
    let mut buffer = vec![0_u16; units.max(1)];
    index = 0;
    // SAFETY: buffer is writable for the byte size returned by WinHTTP.
    unsafe {
        WinHttpQueryHeaders(
            handle,
            query,
            PCWSTR::null(),
            Some(buffer.as_mut_ptr().cast()),
            &mut bytes,
            &mut index,
        )
        .map_err(|error| windows_error("WinHttpQueryHeaders string", error))?;
    }
    let end = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    Ok(Some(String::from_utf16_lossy(&buffer[..end])))
}

fn bounded_header_units(bytes: u32) -> Result<usize, WindowsHostError> {
    if bytes > MAX_HEADER_QUERY_BYTES {
        return Err(WindowsHostError::new(
            "WinHTTP header query exceeds the allocation bound",
        ));
    }
    Ok(usize::try_from(bytes)
        .map_err(|_| WindowsHostError::new("header allocation overflow"))?
        .saturating_add(1)
        / 2)
}

fn query_remote_address(handle: *mut c_void) -> Result<IpAddr, WindowsHostError> {
    let mut info = WINHTTP_CONNECTION_INFO {
        cbSize: u32::try_from(size_of::<WINHTTP_CONNECTION_INFO>())
            .map_err(|_| WindowsHostError::new("connection info size overflow"))?,
        ..Default::default()
    };
    let mut bytes = info.cbSize;
    // SAFETY: output points to a correctly sized WINHTTP_CONNECTION_INFO structure.
    unsafe {
        WinHttpQueryOption(
            handle,
            WINHTTP_OPTION_CONNECTION_INFO,
            Some(ptr::addr_of_mut!(info).cast()),
            &mut bytes,
        )
        .map_err(|error| windows_error("WinHttpQueryOption connection info", error))?;
        sockaddr_to_ip(&info.RemoteAddress)
    }
}

unsafe fn sockaddr_to_ip(storage: &SOCKADDR_STORAGE) -> Result<IpAddr, WindowsHostError> {
    if storage.ss_family == AF_INET {
        // SAFETY: the address family determines the concrete sockaddr layout.
        let value = unsafe { &*(ptr::from_ref(storage).cast::<SOCKADDR_IN>()) };
        // SAFETY: S_un_b is a valid view of an IPv4 IN_ADDR.
        let octets = unsafe { value.sin_addr.S_un.S_un_b };
        Ok(IpAddr::V4(Ipv4Addr::new(
            octets.s_b1,
            octets.s_b2,
            octets.s_b3,
            octets.s_b4,
        )))
    } else if storage.ss_family == AF_INET6 {
        // SAFETY: the address family determines the concrete sockaddr layout.
        let value = unsafe { &*(ptr::from_ref(storage).cast::<SOCKADDR_IN6>()) };
        // SAFETY: Byte is a valid view of an IPv6 IN6_ADDR.
        Ok(IpAddr::V6(Ipv6Addr::from(unsafe {
            value.sin6_addr.u.Byte
        })))
    } else {
        Err(WindowsHostError::new(
            "WinHTTP remote address family is unsupported",
        ))
    }
}

fn query_certificate_sha256(handle: *mut c_void) -> Result<String, WindowsHostError> {
    let mut context: *const CERT_CONTEXT = ptr::null();
    let mut bytes = u32::try_from(size_of::<*const CERT_CONTEXT>())
        .map_err(|_| WindowsHostError::new("certificate context size overflow"))?;
    // SAFETY: output points to a writable certificate-context pointer. WinHTTP returns
    // a duplicated context that this function releases with CertFreeCertificateContext.
    unsafe {
        WinHttpQueryOption(
            handle,
            WINHTTP_OPTION_SERVER_CERT_CONTEXT,
            Some(ptr::addr_of_mut!(context).cast()),
            &mut bytes,
        )
        .map_err(|error| windows_error("WinHttpQueryOption certificate", error))?;
    }
    if context.is_null() {
        return Err(WindowsHostError::new("WinHTTP certificate context is null"));
    }
    // SAFETY: context is non-null and remains owned until the explicit free below.
    let encoded = unsafe {
        let value = &*context;
        std::slice::from_raw_parts(value.pbCertEncoded, value.cbCertEncoded as usize)
    };
    let digest = format!("sha256:{:x}", Sha256::digest(encoded));
    // SAFETY: context came from WINHTTP_OPTION_SERVER_CERT_CONTEXT and is released once.
    let _ = unsafe { CertFreeCertificateContext(Some(context)) };
    Ok(digest)
}

fn read_bounded_body(handle: *mut c_void, maximum: u64) -> Result<Vec<u8>, WindowsHostError> {
    let initial = usize::try_from(maximum.min(1024 * 1024))
        .map_err(|_| WindowsHostError::new("body capacity overflow"))?;
    let mut body = Vec::with_capacity(initial);
    let mut chunk = vec![0_u8; READ_CHUNK_BYTES];
    loop {
        let mut read = 0_u32;
        // SAFETY: chunk is writable for the exact length passed to WinHTTP.
        unsafe {
            WinHttpReadData(
                handle,
                chunk.as_mut_ptr().cast(),
                u32::try_from(chunk.len())
                    .map_err(|_| WindowsHostError::new("read chunk size overflow"))?,
                &mut read,
            )
            .map_err(|error| windows_error("WinHttpReadData", error))?;
        }
        if read == 0 {
            break;
        }
        let read = usize::try_from(read)
            .map_err(|_| WindowsHostError::new("body read length overflow"))?;
        let next = (body.len() as u64).saturating_add(read as u64);
        if next > maximum {
            return Err(WindowsHostError::new(
                "decoded response body exceeds budget",
            ));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(body)
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_without_null(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

fn windows_error(operation: &str, error: windows::core::Error) -> WindowsHostError {
    WindowsHostError::new(format!("{operation} failed: {error}"))
}

fn last_error(operation: &str) -> WindowsHostError {
    windows_error(operation, windows::core::Error::from_thread())
}

#[cfg(test)]
mod tests {
    use super::{bounded_header_units, MAX_HEADER_QUERY_BYTES};

    #[test]
    fn response_header_allocation_is_bounded_before_allocation() {
        assert!(bounded_header_units(MAX_HEADER_QUERY_BYTES).is_ok());
        assert!(bounded_header_units(MAX_HEADER_QUERY_BYTES + 1).is_err());
    }
}
