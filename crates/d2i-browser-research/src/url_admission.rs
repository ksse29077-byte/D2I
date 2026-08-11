use crate::disclosure::{validate_network_profile_v1, validate_source_policy_v1};
use crate::validation::{sha256_bytes, validate_id};
use crate::{
    ResearchError, ResearchNetworkProfileV1, ResearchSourcePolicyV1,
    ResearchUrlAdmissionDecisionV1, ResearchUrlAdmissionRequestV1, SourcePolicyClassV1,
    UrlAdmissionResultV1, ZERO_HASH,
};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use url::Url;

const MAX_URL_BYTES: usize = 4096;

#[derive(Debug, Clone)]
pub struct AdmittedResearchUrl {
    canonical_url: Url,
    protected_ref: String,
    origin_id: String,
    admitted_addresses: BTreeSet<IpAddr>,
    decision_sha256: String,
    source_class: SourcePolicyClassV1,
}

impl AdmittedResearchUrl {
    pub fn canonical_url_for_network_worker(&self) -> &str {
        self.canonical_url.as_str()
    }

    pub fn protected_ref(&self) -> &str {
        &self.protected_ref
    }

    pub fn origin_id(&self) -> &str {
        &self.origin_id
    }

    pub fn host(&self) -> &str {
        self.canonical_url.host_str().unwrap_or_default()
    }

    pub fn path_and_query(&self) -> String {
        let mut value = self.canonical_url.path().to_owned();
        if let Some(query) = self.canonical_url.query() {
            value.push('?');
            value.push_str(query);
        }
        value
    }

    pub fn admitted_addresses(&self) -> &BTreeSet<IpAddr> {
        &self.admitted_addresses
    }

    pub fn decision_sha256(&self) -> &str {
        &self.decision_sha256
    }

    pub fn source_class(&self) -> SourcePolicyClassV1 {
        self.source_class
    }
}

#[derive(Debug, Clone)]
pub struct UrlAdmissionOutcomeV1 {
    pub decision: ResearchUrlAdmissionDecisionV1,
    pub admitted: Option<AdmittedResearchUrl>,
}

pub fn admit_research_url_v1(
    request: &ResearchUrlAdmissionRequestV1,
    raw_url: &str,
    resolved_addresses: &[IpAddr],
    profile: &ResearchNetworkProfileV1,
    source_policy: &ResearchSourcePolicyV1,
) -> Result<UrlAdmissionOutcomeV1, ResearchError> {
    request.validate_seal()?;
    validate_network_profile_v1(profile)?;
    validate_source_policy_v1(source_policy)?;
    validate_id(&request.request_id, "URL admission request ID")?;
    if request.schema_version != 1
        || request.organization_id != source_policy.organization_id
        || request.network_profile_sha256 != profile.network_profile_sha256
        || request.source_policy_sha256 != source_policy.policy_sha256
    {
        return Err(ResearchError::Integrity(
            "URL admission bindings differ".to_owned(),
        ));
    }
    let rejection = |reason: &str| {
        rejected_decision(
            request,
            reason,
            request.url_protected_ref.clone(),
            String::new(),
        )
    };
    if raw_url.is_empty()
        || raw_url.len() > MAX_URL_BYTES
        || raw_url.chars().any(char::is_control)
        || has_unsafe_url_encoding(raw_url)
    {
        return Ok(UrlAdmissionOutcomeV1 {
            decision: rejection("invalid_or_oversized_url")?,
            admitted: None,
        });
    }
    let mut url = match Url::parse(raw_url) {
        Ok(value) => value,
        Err(_) => {
            return Ok(UrlAdmissionOutcomeV1 {
                decision: rejection("url_parse_failed")?,
                admitted: None,
            })
        }
    };
    if url.scheme() != "https" || !profile.allowed_schemes.iter().any(|value| value == "https") {
        return Ok(UrlAdmissionOutcomeV1 {
            decision: rejection("scheme_not_allowed")?,
            admitted: None,
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Ok(UrlAdmissionOutcomeV1 {
            decision: rejection("url_userinfo_forbidden")?,
            admitted: None,
        });
    }
    let port = url.port_or_known_default().unwrap_or_default();
    if port != 443 || !profile.allowed_ports.contains(&port) {
        return Ok(UrlAdmissionOutcomeV1 {
            decision: rejection("port_not_allowed")?,
            admitted: None,
        });
    }
    let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
        return Ok(UrlAdmissionOutcomeV1 {
            decision: rejection("hostname_missing")?,
            admitted: None,
        });
    };
    if !is_valid_dns_hostname(&host) {
        return Ok(UrlAdmissionOutcomeV1 {
            decision: rejection("invalid_hostname")?,
            admitted: None,
        });
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok(UrlAdmissionOutcomeV1 {
            decision: rejection("ip_literal_forbidden")?,
            admitted: None,
        });
    }
    if is_local_hostname(&host, &source_policy.internal_host_suffixes) {
        return Ok(UrlAdmissionOutcomeV1 {
            decision: rejection("local_hostname_forbidden")?,
            admitted: None,
        });
    }
    let source_class = classify_source(&host, source_policy);
    if source_class == SourcePolicyClassV1::Blocked {
        return Ok(UrlAdmissionOutcomeV1 {
            decision: rejection("origin_blocked_by_policy")?,
            admitted: None,
        });
    }
    if resolved_addresses.is_empty() {
        return Ok(UrlAdmissionOutcomeV1 {
            decision: rejection("dns_resolution_empty")?,
            admitted: None,
        });
    }
    let addresses = resolved_addresses.iter().copied().collect::<BTreeSet<_>>();
    if addresses
        .iter()
        .any(|address| !is_public_destination(*address))
    {
        return Ok(UrlAdmissionOutcomeV1 {
            decision: rejection("prohibited_destination_address")?,
            admitted: None,
        });
    }
    url.set_fragment(None);
    let origin_id = format!("origin:{}", sha256_bytes(host.as_bytes()));
    let protected_ref = request.url_protected_ref.clone();
    let mut address_hashes = addresses
        .iter()
        .map(|address| sha256_bytes(address.to_string().as_bytes()))
        .collect::<Vec<_>>();
    address_hashes.sort();
    let decision = ResearchUrlAdmissionDecisionV1 {
        schema_version: 1,
        decision_id: format!("url-admission:{}", request.source_candidate_id),
        organization_id: request.organization_id.clone(),
        case_id: request.case_id.clone(),
        request_sha256: request.request_sha256.clone(),
        canonical_url_protected_ref: protected_ref.clone(),
        origin_id: origin_id.clone(),
        scheme: "https".to_owned(),
        port,
        resolved_address_hashes: address_hashes,
        result: UrlAdmissionResultV1::Admitted,
        reason_code: "public_https_admitted".to_owned(),
        decision_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    Ok(UrlAdmissionOutcomeV1 {
        admitted: Some(AdmittedResearchUrl {
            canonical_url: url,
            protected_ref,
            origin_id,
            admitted_addresses: addresses,
            decision_sha256: decision.decision_sha256.clone(),
            source_class,
        }),
        decision,
    })
}

pub fn resolve_public_addresses_v1(host: &str) -> Result<Vec<IpAddr>, ResearchError> {
    if host.is_empty() || host.len() > 253 || host.parse::<IpAddr>().is_ok() {
        return Err(ResearchError::Invalid("DNS hostname is invalid".to_owned()));
    }
    let addresses = (host, 443)
        .to_socket_addrs()
        .map_err(|error| ResearchError::Io(format!("DNS resolution failed: {error}")))?
        .map(|value| value.ip())
        .collect::<BTreeSet<_>>();
    if addresses.is_empty() {
        return Err(ResearchError::Invalid(
            "DNS resolution returned no addresses".to_owned(),
        ));
    }
    if addresses
        .iter()
        .any(|address| !is_public_destination(*address))
    {
        return Err(ResearchError::AccessDenied(
            "DNS resolution included a prohibited destination".to_owned(),
        ));
    }
    Ok(addresses.into_iter().collect())
}

pub fn verify_connected_remote_address_v1(
    admitted: &AdmittedResearchUrl,
    connected: IpAddr,
) -> Result<(), ResearchError> {
    if !is_public_destination(connected) || !admitted.admitted_addresses.contains(&connected) {
        return Err(ResearchError::AccessDenied(
            "dns_rebind_or_route_mismatch".to_owned(),
        ));
    }
    Ok(())
}

pub fn resolve_redirect_location_v1(
    current: &AdmittedResearchUrl,
    location: &str,
    redirect_count: u32,
    profile: &ResearchNetworkProfileV1,
) -> Result<String, ResearchError> {
    validate_network_profile_v1(profile)?;
    if redirect_count >= profile.max_redirects {
        return Err(ResearchError::AccessDenied(
            "redirect_budget_exhausted".to_owned(),
        ));
    }
    if location.is_empty()
        || location.len() > MAX_URL_BYTES
        || location.chars().any(char::is_control)
    {
        return Err(ResearchError::Invalid(
            "redirect Location is invalid".to_owned(),
        ));
    }
    let target = current
        .canonical_url
        .join(location)
        .map_err(|_| ResearchError::Invalid("redirect Location cannot be resolved".to_owned()))?;
    if target.scheme() != "https" {
        return Err(ResearchError::AccessDenied(
            "https_downgrade_rejected".to_owned(),
        ));
    }
    Ok(target.to_string())
}

pub fn is_public_destination(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => is_public_ipv4(value),
        IpAddr::V6(value) => is_public_ipv6(value),
    }
}

fn is_public_ipv4(value: Ipv4Addr) -> bool {
    let octets = value.octets();
    if value.is_loopback()
        || value.is_private()
        || value.is_link_local()
        || value.is_multicast()
        || value.is_unspecified()
        || octets[0] == 0
        || octets[0] >= 224
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return false;
    }
    true
}

fn is_public_ipv6(value: Ipv6Addr) -> bool {
    if let Some(mapped) = value.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let segments = value.segments();
    !value.is_loopback()
        && !value.is_unspecified()
        && !value.is_multicast()
        && (segments[0] & 0xffc0) != 0xfe80
        && (segments[0] & 0xfe00) != 0xfc00
        && value != Ipv6Addr::LOCALHOST
}

fn is_local_hostname(host: &str, internal_suffixes: &[String]) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || internal_suffixes.iter().any(|suffix| {
            let suffix = suffix.trim_start_matches('.').to_ascii_lowercase();
            host == suffix || host.ends_with(&format!(".{suffix}"))
        })
}

fn has_unsafe_url_encoding(raw_url: &str) -> bool {
    let bytes = raw_url.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }

    let Some((_, remainder)) = raw_url.split_once("://") else {
        return false;
    };
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.contains(['%', '\\']) {
        return true;
    }
    let path_end = remainder.find(['?', '#']).unwrap_or(remainder.len());
    let path = remainder[..path_end].to_ascii_lowercase();
    path.contains("%2f") || path.contains("%5c") || path.contains("%00")
}

fn is_valid_dns_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() || host.ends_with('.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && (!label.starts_with("xn--") || label.len() >= 7)
    })
}

fn classify_source(host: &str, policy: &ResearchSourcePolicyV1) -> SourcePolicyClassV1 {
    if origin_matches(host, &policy.blocked_origins) {
        SourcePolicyClassV1::Blocked
    } else if origin_matches(host, &policy.preferred_origins) {
        SourcePolicyClassV1::Preferred
    } else if origin_matches(host, &policy.allowed_origins) {
        SourcePolicyClassV1::Allowed
    } else {
        SourcePolicyClassV1::UnclassifiedExternal
    }
}

fn origin_matches(host: &str, origins: &[String]) -> bool {
    origins.iter().any(|origin| {
        let origin = origin.to_ascii_lowercase();
        host == origin || host.ends_with(&format!(".{origin}"))
    })
}

fn rejected_decision(
    request: &ResearchUrlAdmissionRequestV1,
    reason: &str,
    protected_ref: String,
    origin_id: String,
) -> Result<ResearchUrlAdmissionDecisionV1, ResearchError> {
    ResearchUrlAdmissionDecisionV1 {
        schema_version: 1,
        decision_id: format!("url-admission:{}", request.source_candidate_id),
        organization_id: request.organization_id.clone(),
        case_id: request.case_id.clone(),
        request_sha256: request.request_sha256.clone(),
        canonical_url_protected_ref: protected_ref,
        origin_id,
        scheme: String::new(),
        port: 0,
        resolved_address_hashes: Vec::new(),
        result: UrlAdmissionResultV1::Rejected,
        reason_code: reason.to_owned(),
        decision_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}
