use crate::validation::{sha256_bytes, validate_id, validate_text};
use crate::{
    AdmittedResearchUrl, ResearchError, ResearchLinkRelationV1, ResearchLinkV1,
    ResearchNetworkProfileV1, ResearchPageSnapshotV1, ResearchSegmentRoleV1, ResearchSegmentV1,
    SourcePolicyClassV1, ZERO_HASH,
};
use scraper::{ElementRef, Html, Selector};
use std::collections::BTreeSet;
use url::Url;

const MAX_SEGMENTS: usize = 2048;
const MAX_SEGMENT_BYTES: usize = 8192;

#[derive(Debug, Clone)]
pub struct ProtectedResearchLinkV1 {
    pub link_id: String,
    pub protected_ref: String,
    raw_target: Url,
}

impl ProtectedResearchLinkV1 {
    pub fn raw_target_for_admission(&self) -> &str {
        self.raw_target.as_str()
    }
}

#[derive(Debug, Clone)]
pub struct ResearchSnapshotExtractionV1 {
    pub snapshot: ResearchPageSnapshotV1,
    pub protected_links: Vec<ProtectedResearchLinkV1>,
    pub safe_html: String,
}

#[derive(Debug, Clone)]
pub struct SnapshotBuildInputV1<'a> {
    pub snapshot_id: &'a str,
    pub source_id: &'a str,
    pub organization_id: &'a str,
    pub case_id: &'a str,
    pub admitted_url: &'a AdmittedResearchUrl,
    pub requested_url_sha256: &'a str,
    pub http_status: u16,
    pub content_type: &'a str,
    pub retrieved_at_unix_ms: u64,
    pub freshness_expires_at_unix_ms: u64,
    pub generation: u64,
    pub source_policy_class: SourcePolicyClassV1,
    pub browser_session_id: &'a str,
}

pub fn extract_research_snapshot_v1(
    input: SnapshotBuildInputV1<'_>,
    raw_body: &[u8],
    profile: &ResearchNetworkProfileV1,
) -> Result<ResearchSnapshotExtractionV1, ResearchError> {
    validate_id(input.snapshot_id, "snapshot ID")?;
    validate_id(input.source_id, "source ID")?;
    validate_id(input.organization_id, "snapshot organization")?;
    validate_id(input.case_id, "snapshot Case")?;
    validate_id(input.browser_session_id, "browser session ID")?;
    if raw_body.is_empty() || raw_body.len() as u64 > profile.max_response_bytes {
        return Err(ResearchError::Resource(
            "raw HTML body is empty or exceeds the profile bound".to_owned(),
        ));
    }
    if !input
        .content_type
        .to_ascii_lowercase()
        .starts_with("text/html")
    {
        return Err(ResearchError::Unsupported(
            "research snapshot parser accepts text/html only".to_owned(),
        ));
    }
    let raw_html = std::str::from_utf8(raw_body)
        .map_err(|_| ResearchError::Unsupported("HTML is not valid UTF-8".to_owned()))?;
    let document = Html::parse_document(raw_html);
    let selector = Selector::parse("title,h1,h2,h3,h4,h5,h6,p,li,th,td,a")
        .map_err(|_| ResearchError::Integrity("fixed HTML selector failed".to_owned()))?;
    let base_url = Url::parse(input.admitted_url.canonical_url_for_network_worker())
        .map_err(|_| ResearchError::Integrity("admitted URL cannot be reparsed".to_owned()))?;
    let raw_body_sha256 = sha256_bytes(raw_body);
    let mut segments = Vec::new();
    let mut links = Vec::new();
    let mut protected_links = Vec::new();
    let mut seen_link_targets = BTreeSet::new();
    let mut extracted_bytes = 0_u64;
    let mut title = String::new();

    for element in document.select(&selector) {
        if element_is_hidden(element) {
            continue;
        }
        let name = element.value().name();
        let text = normalize_visible_text(element.text());
        if text.is_empty() {
            continue;
        }
        let role = match name {
            "title" => ResearchSegmentRoleV1::Title,
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => ResearchSegmentRoleV1::Heading,
            "p" => ResearchSegmentRoleV1::Paragraph,
            "li" => ResearchSegmentRoleV1::ListItem,
            "th" | "td" => ResearchSegmentRoleV1::TableCell,
            "a" => ResearchSegmentRoleV1::LinkLabel,
            _ => continue,
        };
        let bounded = bound_utf8(&text, MAX_SEGMENT_BYTES);
        extracted_bytes = extracted_bytes.saturating_add(bounded.len() as u64);
        if extracted_bytes > profile.max_extracted_text_bytes {
            break;
        }
        if title.is_empty() && matches!(role, ResearchSegmentRoleV1::Title) {
            title = bounded.clone();
        }
        if segments.len() >= MAX_SEGMENTS {
            break;
        }
        let segment_index = segments.len() + 1;
        let segment = ResearchSegmentV1 {
            segment_id: format!("segment-{segment_index:06}"),
            role,
            heading_level: heading_level(name),
            text: bounded.clone(),
            source_reference: format!("dom-order:{segment_index}"),
            segment_sha256: ZERO_HASH.to_owned(),
        }
        .seal()?;
        segments.push(segment);

        if name == "a" && links.len() < profile.max_links_per_page as usize {
            if let Some(href) = element.value().attr("href") {
                if let Some(target) = safe_resolved_link(&base_url, href) {
                    let identity_hash = sha256_bytes(target.as_str().as_bytes());
                    if !seen_link_targets.insert(identity_hash.clone()) {
                        continue;
                    }
                    let link_index = links.len() + 1;
                    let link_id = format!("research-link-{link_index:06}");
                    let protected_ref = format!("source-store:{identity_hash}");
                    let relation = classify_link_relation(element, &target);
                    let target_origin_hint = target
                        .host_str()
                        .map(|host| {
                            format!(
                                "origin:family:sha256:{}",
                                &sha256_bytes(host.as_bytes())[7..23]
                            )
                        })
                        .unwrap_or_else(|| "origin:unknown".to_owned());
                    let link = ResearchLinkV1 {
                        link_id: link_id.clone(),
                        display_text: bounded.clone(),
                        target_url_protected_ref: protected_ref.clone(),
                        target_origin_hint,
                        relation,
                        source_snapshot_sha256: raw_body_sha256.clone(),
                        link_sha256: ZERO_HASH.to_owned(),
                    }
                    .seal()?;
                    links.push(link);
                    protected_links.push(ProtectedResearchLinkV1 {
                        link_id,
                        protected_ref,
                        raw_target: target,
                    });
                }
            }
        }
    }
    if title.is_empty() {
        title = segments
            .iter()
            .find(|segment| matches!(segment.role, ResearchSegmentRoleV1::Heading))
            .map(|segment| segment.text.clone())
            .unwrap_or_else(|| "Untitled research source".to_owned());
    }
    validate_text(&title, "snapshot title", MAX_SEGMENT_BYTES)?;
    if segments.is_empty() {
        return Err(ResearchError::Unsupported(
            "dynamic_live_browser_required".to_owned(),
        ));
    }
    let extracted_content_sha256 = sha256_bytes(
        &segments
            .iter()
            .flat_map(|segment| segment.segment_sha256.as_bytes())
            .copied()
            .collect::<Vec<_>>(),
    );
    let snapshot = ResearchPageSnapshotV1 {
        schema_version: 1,
        snapshot_id: input.snapshot_id.to_owned(),
        source_id: input.source_id.to_owned(),
        organization_id: input.organization_id.to_owned(),
        case_id: input.case_id.to_owned(),
        requested_url_sha256: input.requested_url_sha256.to_owned(),
        final_url_protected_ref: input.admitted_url.protected_ref().to_owned(),
        origin_id: input.admitted_url.origin_id().to_owned(),
        http_status: input.http_status,
        content_type: input.content_type.to_owned(),
        retrieved_at_unix_ms: input.retrieved_at_unix_ms,
        freshness_expires_at_unix_ms: input.freshness_expires_at_unix_ms,
        raw_body_sha256,
        extracted_content_sha256,
        title,
        segments,
        links,
        source_policy_class: input.source_policy_class,
        generation: input.generation,
        snapshot_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    validate_snapshot_v1(&snapshot, profile)?;
    let safe_html = render_safe_snapshot_html_v1(
        input.browser_session_id,
        &snapshot,
        input.admitted_url.origin_id(),
    )?;
    Ok(ResearchSnapshotExtractionV1 {
        snapshot,
        protected_links,
        safe_html,
    })
}

pub fn validate_snapshot_v1(
    snapshot: &ResearchPageSnapshotV1,
    profile: &ResearchNetworkProfileV1,
) -> Result<(), ResearchError> {
    snapshot.validate_seal()?;
    if snapshot.schema_version != 1
        || snapshot.http_status < 200
        || snapshot.http_status >= 400
        || snapshot.retrieved_at_unix_ms >= snapshot.freshness_expires_at_unix_ms
        || snapshot.segments.is_empty()
        || snapshot.segments.len() > MAX_SEGMENTS
        || snapshot.links.len() > profile.max_links_per_page as usize
    {
        return Err(ResearchError::Invalid(
            "research snapshot bounds differ".to_owned(),
        ));
    }
    let total_text = snapshot
        .segments
        .iter()
        .map(|segment| segment.text.len() as u64)
        .sum::<u64>();
    if total_text > profile.max_extracted_text_bytes {
        return Err(ResearchError::Resource(
            "snapshot extracted text exceeds profile".to_owned(),
        ));
    }
    for segment in &snapshot.segments {
        segment.validate_seal()?;
    }
    for link in &snapshot.links {
        link.validate_seal()?;
        if !link
            .target_url_protected_ref
            .starts_with("source-store:sha256:")
        {
            return Err(ResearchError::AccessDenied(
                "snapshot exposes a raw external URL".to_owned(),
            ));
        }
    }
    Ok(())
}

pub fn render_safe_snapshot_html_v1(
    session_id: &str,
    snapshot: &ResearchPageSnapshotV1,
    source_origin_label: &str,
) -> Result<String, ResearchError> {
    validate_id(session_id, "snapshot session ID")?;
    snapshot.validate_seal()?;
    validate_id(source_origin_label, "snapshot source origin label")?;
    let mut body = String::new();
    for segment in &snapshot.segments {
        let text = escape_html(&segment.text);
        let element = match segment.role {
            ResearchSegmentRoleV1::Title => format!("<h1>{text}</h1>"),
            ResearchSegmentRoleV1::Heading => {
                let level = segment.heading_level.unwrap_or(2).clamp(1, 6);
                format!("<h{level}>{text}</h{level}>")
            }
            ResearchSegmentRoleV1::Paragraph => format!("<p>{text}</p>"),
            ResearchSegmentRoleV1::ListItem => format!("<p class=\"list-item\">• {text}</p>"),
            ResearchSegmentRoleV1::TableCell => format!("<p class=\"table-cell\">{text}</p>"),
            ResearchSegmentRoleV1::LinkLabel => String::new(),
        };
        body.push_str(&element);
    }
    if !snapshot.links.is_empty() {
        body.push_str("<nav aria-label=\"Research links\"><h2>Source links</h2><ul>");
        for link in &snapshot.links {
            body.push_str(&format!(
                "<li><a href=\"/session/{}/link/{}\">{}</a></li>",
                escape_html(session_id),
                escape_html(&link.link_id),
                escape_html(&link.display_text)
            ));
        }
        body.push_str("</ul></nav>");
    }
    Ok(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\"><meta name=\"referrer\" content=\"no-referrer\"><title>{}</title><style>body{{font:16px/1.55 system-ui,sans-serif;max-width:920px;margin:0 auto;padding:32px;color:#172033}}header{{border-bottom:1px solid #dce3ed;margin-bottom:24px}}.source{{color:#536179}}a{{color:#0759c7}}.table-cell{{border:1px solid #dce3ed;padding:8px}}</style></head><body><header><p class=\"source\">Source: {}</p></header><main>{}</main></body></html>",
        escape_html(&snapshot.title),
        escape_html(source_origin_label),
        body
    ))
}

fn normalize_visible_text<'a>(values: impl Iterator<Item = &'a str>) -> String {
    values
        .flat_map(str::split_whitespace)
        .collect::<Vec<_>>()
        .join(" ")
}

fn bound_utf8(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn element_is_hidden(element: ElementRef<'_>) -> bool {
    element
        .ancestors()
        .filter_map(ElementRef::wrap)
        .any(|ancestor| {
            ancestor.value().attr("hidden").is_some()
                || ancestor.value().attr("aria-hidden") == Some("true")
                || ancestor
                    .value()
                    .attr("style")
                    .map(|style| {
                        let compact = style.to_ascii_lowercase().replace(' ', "");
                        compact.contains("display:none") || compact.contains("visibility:hidden")
                    })
                    .unwrap_or(false)
        })
}

fn heading_level(name: &str) -> Option<u8> {
    name.strip_prefix('h')
        .and_then(|value| value.parse::<u8>().ok())
        .filter(|value| (1..=6).contains(value))
}

fn safe_resolved_link(base: &Url, href: &str) -> Option<Url> {
    if href.is_empty() || href.len() > 4096 || href.chars().any(char::is_control) {
        return None;
    }
    let mut target = base.join(href).ok()?;
    if !matches!(target.scheme(), "https" | "http")
        || !target.username().is_empty()
        || target.password().is_some()
    {
        return None;
    }
    target.set_fragment(None);
    Some(target)
}

fn classify_link_relation(element: ElementRef<'_>, target: &Url) -> ResearchLinkRelationV1 {
    let lower_path = target.path().to_ascii_lowercase();
    if element.value().attr("download").is_some()
        || [
            ".pdf", ".docx", ".hwpx", ".xlsx", ".pptx", ".txt", ".csv", ".png", ".jpg", ".jpeg",
        ]
        .iter()
        .any(|extension| lower_path.ends_with(extension))
    {
        ResearchLinkRelationV1::Download
    } else if element
        .value()
        .attr("rel")
        .unwrap_or_default()
        .contains("external")
    {
        ResearchLinkRelationV1::Reference
    } else {
        ResearchLinkRelationV1::Navigation
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
