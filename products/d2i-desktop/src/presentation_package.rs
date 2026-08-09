use d2i_presentation_capability::PresentationResourceLimitsV1;
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

#[derive(Debug, Clone)]
pub(crate) struct BoundedPresentationPackage {
    entries: BTreeMap<String, Vec<u8>>,
}

impl BoundedPresentationPackage {
    pub(crate) fn open(path: &Path, limits: &PresentationResourceLimitsV1) -> Result<Self, String> {
        let metadata = path
            .metadata()
            .map_err(|error| format!("presentation package metadata: {error}"))?;
        if !metadata.is_file() || metadata.len() > limits.maximum_presentation_bytes {
            return Err("presentation package is not a bounded regular file".to_owned());
        }
        let package_bytes =
            std::fs::read(path).map_err(|error| format!("presentation package open: {error}"))?;
        let declared_entries = central_directory_entry_count(&package_bytes)?;
        let mut archive = ZipArchive::new(Cursor::new(package_bytes.as_slice()))
            .map_err(|error| format!("presentation ZIP open: {error}"))?;
        if declared_entries != archive.len() {
            return Err("presentation package contains duplicate or shadowed entries".to_owned());
        }
        if archive.len()
            > usize::try_from(limits.maximum_package_entries)
                .map_err(|error| format!("presentation package entry bound: {error}"))?
        {
            return Err("presentation package has excessive entries".to_owned());
        }
        let mut entries = BTreeMap::new();
        let mut uncompressed_total = 0_u64;
        for index in 0..archive.len() {
            let entry = archive
                .by_index(index)
                .map_err(|error| format!("presentation ZIP entry {index}: {error}"))?;
            let name = entry.name().to_owned();
            validate_package_entry_name(&name)?;
            if entry.is_dir() {
                continue;
            }
            if entry.encrypted() {
                return Err("password-protected presentations are unsupported".to_owned());
            }
            if entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
            {
                return Err("presentation package symlink entry is forbidden".to_owned());
            }
            if is_forbidden_active_part(&name) {
                return Err(format!("active presentation part is forbidden: {name}"));
            }
            let size = entry.size();
            let compressed = entry.compressed_size();
            uncompressed_total = uncompressed_total
                .checked_add(size)
                .ok_or_else(|| "presentation package size overflow".to_owned())?;
            if uncompressed_total > limits.maximum_uncompressed_bytes {
                return Err("presentation package exceeds the uncompressed byte limit".to_owned());
            }
            if size > 0
                && (compressed == 0
                    || size / compressed.max(1) > u64::from(limits.maximum_compression_ratio))
            {
                return Err("presentation package compression ratio is unsafe".to_owned());
            }
            let capacity = usize::try_from(size)
                .map_err(|error| format!("presentation ZIP entry size: {error}"))?;
            let mut bytes = Vec::with_capacity(capacity.min(1024 * 1024));
            let mut bounded = entry.take(size.saturating_add(1));
            bounded
                .read_to_end(&mut bytes)
                .map_err(|error| format!("presentation ZIP entry read: {error}"))?;
            if u64::try_from(bytes.len()).ok() != Some(size) {
                return Err("presentation ZIP entry length differs".to_owned());
            }
            if is_xml_part(&name) {
                validate_xml_part(&bytes, limits)?;
            }
            if is_allowed_chart_workbook(&name) {
                validate_embedded_chart_workbook(&bytes, limits)?;
            }
            if is_relationship_part(&name) {
                validate_relationship_part(&bytes)?;
            }
            if entries.insert(name, bytes).is_some() {
                return Err("presentation package contains a duplicate entry".to_owned());
            }
        }
        validate_required_parts(&entries)?;
        validate_content_types(&entries)?;
        validate_relationship_targets(&entries)?;
        Ok(Self { entries })
    }

    pub(crate) fn entry(&self, name: &str) -> Result<&[u8], String> {
        self.entries
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| format!("required presentation package entry missing: {name}"))
    }

    pub(crate) fn entry_names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    pub(crate) fn replace_entry(&mut self, name: &str, bytes: Vec<u8>) -> Result<(), String> {
        validate_package_entry_name(name)?;
        if !self.entries.contains_key(name) {
            return Err(format!("presentation package entry is not present: {name}"));
        }
        self.entries.insert(name.to_owned(), bytes);
        Ok(())
    }

    pub(crate) fn insert_entry(&mut self, name: &str, bytes: Vec<u8>) -> Result<(), String> {
        validate_package_entry_name(name)?;
        if self.entries.contains_key(name) || is_forbidden_active_part(name) {
            return Err(format!(
                "presentation package entry cannot be inserted: {name}"
            ));
        }
        self.entries.insert(name.to_owned(), bytes);
        Ok(())
    }

    pub(crate) fn write_atomic(
        &self,
        destination: &Path,
        limits: &PresentationResourceLimitsV1,
    ) -> Result<u64, String> {
        if destination.exists() {
            return Err("presentation destination must be a new generation".to_owned());
        }
        let mut archive_bytes = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut archive_bytes);
            for (name, bytes) in &self.entries {
                writer
                    .start_file(
                        name,
                        SimpleFileOptions::default()
                            .compression_method(CompressionMethod::Deflated)
                            .unix_permissions(0o600),
                    )
                    .map_err(|error| format!("presentation ZIP start {name}: {error}"))?;
                writer
                    .write_all(bytes)
                    .map_err(|error| format!("presentation ZIP write {name}: {error}"))?;
            }
            writer
                .finish()
                .map_err(|error| format!("presentation ZIP finish: {error}"))?;
        }
        let bytes = archive_bytes.into_inner();
        if u64::try_from(bytes.len()).map_or(true, |size| size > limits.maximum_presentation_bytes)
        {
            return Err("serialized presentation exceeds its byte limit".to_owned());
        }
        let parent = destination
            .parent()
            .ok_or_else(|| "presentation destination has no parent".to_owned())?;
        if !parent.is_dir() {
            return Err("presentation destination parent is unavailable".to_owned());
        }
        let name = destination
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "presentation destination filename is invalid".to_owned())?;
        let temporary = parent.join(format!(".{name}.d2i-office400-{}.tmp", std::process::id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|error| format!("presentation temporary create: {error}"))?;
            file.write_all(&bytes)
                .map_err(|error| format!("presentation temporary write: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("presentation temporary sync: {error}"))?;
            drop(file);
            std::fs::rename(&temporary, destination)
                .map_err(|error| format!("presentation atomic commit: {error}"))?;
            u64::try_from(bytes.len()).map_err(|error| format!("presentation size: {error}"))
        })();
        if temporary.exists() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
}

fn central_directory_entry_count(bytes: &[u8]) -> Result<usize, String> {
    const SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const MINIMUM: usize = 22;
    const MAX_COMMENT: usize = 65_535;
    if bytes.len() < MINIMUM {
        return Err("presentation package lacks a complete ZIP directory".to_owned());
    }
    let search_start = bytes.len().saturating_sub(MINIMUM + MAX_COMMENT);
    let offset = bytes[search_start..]
        .windows(SIGNATURE.len())
        .rposition(|window| window == SIGNATURE)
        .map(|relative| search_start + relative)
        .ok_or_else(|| "presentation package lacks a ZIP directory".to_owned())?;
    let count_offset = offset
        .checked_add(10)
        .ok_or_else(|| "presentation ZIP directory offset overflow".to_owned())?;
    let count_bytes = bytes
        .get(count_offset..count_offset + 2)
        .ok_or_else(|| "presentation ZIP entry count is truncated".to_owned())?;
    let count = u16::from_le_bytes([count_bytes[0], count_bytes[1]]);
    if count == u16::MAX {
        return Err("ZIP64 presentations are unsupported in v1".to_owned());
    }
    Ok(usize::from(count))
}

fn validate_package_entry_name(name: &str) -> Result<(), String> {
    let lower = name.to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 512
        || name.contains('\\')
        || name.contains(':')
        || name.contains('%')
        || name.starts_with('/')
        || name.starts_with("//")
        || lower.contains("%2e")
        || Path::new(name)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe presentation package entry name: {name}"));
    }
    Ok(())
}

fn is_xml_part(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".xml") || lower.ends_with(".rels")
}

fn is_relationship_part(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".rels")
}

fn is_forbidden_active_part(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with("vbaproject.bin")
        || lower.starts_with("ppt/embeddings/") && !is_allowed_chart_workbook(name)
        || lower.starts_with("ppt/activex/")
        || lower.starts_with("ppt/oleobjects/")
        || lower.starts_with("ppt/macros/")
        || lower.starts_with("ppt/media/") && lower.ends_with(".bin")
        || lower.starts_with("customui/")
        || lower.ends_with(".exe")
        || lower.ends_with(".dll")
        || lower.ends_with(".js")
        || lower.ends_with(".vbs")
        || lower.ends_with(".ps1")
        || lower.ends_with(".cmd")
        || lower.ends_with(".bat")
}

fn is_allowed_chart_workbook(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("ppt/embeddings/")
        && lower.ends_with(".xlsx")
        && lower["ppt/embeddings/".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn validate_embedded_chart_workbook(
    bytes: &[u8],
    limits: &PresentationResourceLimitsV1,
) -> Result<(), String> {
    let declared_entries = central_directory_entry_count(bytes)?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| format!("embedded chart workbook ZIP open: {error}"))?;
    if declared_entries != archive.len() || archive.len() > 2_048 {
        return Err("embedded chart workbook entry count is invalid".to_owned());
    }
    let mut entries = BTreeMap::new();
    let mut uncompressed_total = 0_u64;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("embedded chart workbook entry {index}: {error}"))?;
        let name = entry.name().to_owned();
        validate_package_entry_name(&name)?;
        if entry.is_dir() {
            continue;
        }
        if entry.encrypted()
            || entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
            || is_forbidden_chart_workbook_part(&name)
        {
            return Err(format!("embedded chart workbook part is forbidden: {name}"));
        }
        let size = entry.size();
        let compressed = entry.compressed_size();
        uncompressed_total = uncompressed_total
            .checked_add(size)
            .ok_or_else(|| "embedded chart workbook size overflow".to_owned())?;
        if uncompressed_total > limits.maximum_uncompressed_bytes
            || size > 0
                && (compressed == 0
                    || size / compressed.max(1) > u64::from(limits.maximum_compression_ratio))
        {
            return Err("embedded chart workbook exceeds package bounds".to_owned());
        }
        let mut content = Vec::new();
        entry
            .take(size.saturating_add(1))
            .read_to_end(&mut content)
            .map_err(|error| format!("embedded chart workbook read: {error}"))?;
        if u64::try_from(content.len()).ok() != Some(size) {
            return Err("embedded chart workbook entry length differs".to_owned());
        }
        if is_xml_part(&name) {
            validate_xml_part(&content, limits)?;
        }
        if is_relationship_part(&name) {
            validate_relationship_part(&content)?;
        }
        if entries.insert(name, content).is_some() {
            return Err("embedded chart workbook contains duplicate entries".to_owned());
        }
    }
    for required in ["[Content_Types].xml", "_rels/.rels", "xl/workbook.xml"] {
        if !entries.contains_key(required) {
            return Err(format!(
                "embedded chart workbook part is missing: {required}"
            ));
        }
    }
    validate_content_types(&entries)?;
    validate_relationship_targets(&entries)
}

fn is_forbidden_chart_workbook_part(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with("vbaproject.bin")
        || lower.starts_with("xl/externallinks/")
        || lower.starts_with("xl/embeddings/")
        || lower.starts_with("xl/activex/")
        || lower.starts_with("xl/oleobjects/")
        || lower.starts_with("customui/")
        || lower.ends_with("connections.xml")
        || lower.ends_with(".exe")
        || lower.ends_with(".dll")
        || lower.ends_with(".js")
        || lower.ends_with(".vbs")
        || lower.ends_with(".ps1")
        || lower.ends_with(".cmd")
        || lower.ends_with(".bat")
}

fn validate_required_parts(entries: &BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    for required in [
        "[Content_Types].xml",
        "_rels/.rels",
        "ppt/presentation.xml",
        "ppt/_rels/presentation.xml.rels",
    ] {
        if !entries.contains_key(required) {
            return Err(format!(
                "required presentation package part missing: {required}"
            ));
        }
    }
    if !entries
        .keys()
        .any(|name| name.starts_with("ppt/slides/slide") && name.ends_with(".xml"))
    {
        return Err("presentation package has no slide part".to_owned());
    }
    Ok(())
}

fn validate_content_types(entries: &BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    let text = String::from_utf8_lossy(
        entries
            .get("[Content_Types].xml")
            .ok_or_else(|| "presentation content types are missing".to_owned())?,
    )
    .to_ascii_lowercase();
    for forbidden in [
        "macroenabled",
        "vbaproject",
        "slideshow.macroenabled",
        "oleobject",
        "activex",
    ] {
        if text.contains(forbidden) {
            return Err(format!(
                "presentation content type is forbidden: {forbidden}"
            ));
        }
    }
    Ok(())
}

fn validate_relationship_part(bytes: &[u8]) -> Result<(), String> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    loop {
        match reader
            .read_event()
            .map_err(|error| format!("presentation relationship XML: {error}"))?
        {
            Event::Start(element) | Event::Empty(element)
                if element
                    .local_name()
                    .as_ref()
                    .eq_ignore_ascii_case(b"relationship") =>
            {
                let mut target = None;
                let mut external = false;
                let mut relation_type = None;
                for attribute in element.attributes().with_checks(true) {
                    let attribute = attribute
                        .map_err(|error| format!("presentation relationship attribute: {error}"))?;
                    let value = attribute
                        .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
                        .map_err(|error| format!("presentation relationship value: {error}"))?
                        .into_owned();
                    let key = attribute.key.local_name();
                    if key.as_ref().eq_ignore_ascii_case(b"target") {
                        target = Some(value);
                    } else if key.as_ref().eq_ignore_ascii_case(b"targetmode")
                        && value.eq_ignore_ascii_case("external")
                    {
                        external = true;
                    } else if key.as_ref().eq_ignore_ascii_case(b"type") {
                        relation_type = Some(value);
                    }
                }
                if external {
                    return Err("external presentation relationship is forbidden".to_owned());
                }
                let relation_type = relation_type.unwrap_or_default().to_ascii_lowercase();
                for forbidden in [
                    "vbaproject",
                    "oleobject",
                    "activex",
                    "hyperlink",
                    "attachedtemplate",
                ] {
                    if relation_type.contains(forbidden) {
                        return Err(format!(
                            "presentation relationship type is forbidden: {forbidden}"
                        ));
                    }
                }
                validate_relationship_target(
                    target
                        .as_deref()
                        .ok_or_else(|| "presentation relationship target is missing".to_owned())?,
                )?;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(())
}

fn relationship_targets(bytes: &[u8]) -> Result<Vec<String>, String> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut targets = Vec::new();
    loop {
        match reader
            .read_event()
            .map_err(|error| format!("presentation relationship XML: {error}"))?
        {
            Event::Start(element) | Event::Empty(element)
                if element
                    .local_name()
                    .as_ref()
                    .eq_ignore_ascii_case(b"relationship") =>
            {
                for attribute in element.attributes().with_checks(true) {
                    let attribute = attribute
                        .map_err(|error| format!("presentation relationship attribute: {error}"))?;
                    if attribute
                        .key
                        .local_name()
                        .as_ref()
                        .eq_ignore_ascii_case(b"target")
                    {
                        targets.push(
                            attribute
                                .decoded_and_normalized_value(
                                    XmlVersion::Implicit1_0,
                                    reader.decoder(),
                                )
                                .map_err(|error| {
                                    format!("presentation relationship target: {error}")
                                })?
                                .into_owned(),
                        );
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(targets)
}

fn validate_relationship_target(target: &str) -> Result<(), String> {
    let lower = target.to_ascii_lowercase();
    if target.is_empty()
        || target.len() > 512
        || target.contains('\0')
        || target.contains('\\')
        || target.contains('%')
        || target.starts_with('/')
        || target.starts_with("//")
        || lower.contains("://")
        || lower.starts_with("file:")
        || lower.starts_with("data:")
    {
        return Err("presentation relationship target is unsafe".to_owned());
    }
    Ok(())
}

fn validate_relationship_targets(entries: &BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    for (relationship_part, bytes) in entries
        .iter()
        .filter(|(name, _)| is_relationship_part(name))
    {
        let base = relationship_base(relationship_part)?;
        for target in relationship_targets(bytes)? {
            let resolved = resolve_relationship_target(&base, &target)?;
            if !entries.contains_key(&resolved) {
                return Err(format!(
                    "presentation relationship target is missing: {resolved}"
                ));
            }
        }
    }
    Ok(())
}

fn relationship_base(relationship_part: &str) -> Result<Vec<String>, String> {
    if relationship_part == "_rels/.rels" {
        return Ok(Vec::new());
    }
    let (prefix, file) = relationship_part
        .rsplit_once("/_rels/")
        .ok_or_else(|| "presentation relationship part path is malformed".to_owned())?;
    if !file.ends_with(".rels") || file.len() <= ".rels".len() {
        return Err("presentation relationship filename is malformed".to_owned());
    }
    Ok(prefix.split('/').map(str::to_owned).collect())
}

fn resolve_relationship_target(base: &[String], target: &str) -> Result<String, String> {
    validate_relationship_target(target)?;
    let mut components = base.to_vec();
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components
                    .pop()
                    .ok_or_else(|| "presentation relationship escapes the package".to_owned())?;
            }
            value => components.push(value.to_owned()),
        }
    }
    if components.is_empty() {
        return Err("presentation relationship target is empty".to_owned());
    }
    Ok(components.join("/"))
}

pub(crate) fn validate_xml_part(
    bytes: &[u8],
    limits: &PresentationResourceLimitsV1,
) -> Result<(), String> {
    if u64::try_from(bytes.len()).map_or(true, |size| size > limits.maximum_xml_bytes) {
        return Err("presentation XML exceeds its byte limit".to_owned());
    }
    let uppercase = String::from_utf8_lossy(bytes).to_ascii_uppercase();
    if uppercase.contains("<!DOCTYPE")
        || uppercase.contains("<!ENTITY")
        || uppercase.contains(" SYSTEM ")
        || uppercase.contains(" PUBLIC ")
    {
        return Err("presentation XML DTD or entity declaration is forbidden".to_owned());
    }
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().check_end_names = true;
    reader.config_mut().expand_empty_elements = false;
    let mut depth = 0_u32;
    let mut nodes = 0_u32;
    let mut attributes = 0_u32;
    loop {
        match reader
            .read_event()
            .map_err(|error| format!("presentation XML parse: {error}"))?
        {
            Event::Start(start) => {
                depth = depth
                    .checked_add(1)
                    .ok_or_else(|| "presentation XML depth overflow".to_owned())?;
                nodes = nodes
                    .checked_add(1)
                    .ok_or_else(|| "presentation XML node overflow".to_owned())?;
                for attribute in start.attributes().with_checks(true) {
                    let attribute = attribute
                        .map_err(|error| format!("presentation XML attribute: {error}"))?;
                    attributes = attributes
                        .checked_add(1)
                        .ok_or_else(|| "presentation XML attribute overflow".to_owned())?;
                    if attribute.value.len() > MAX_XML_VALUE_BYTES {
                        return Err("presentation XML attribute exceeds its bound".to_owned());
                    }
                }
            }
            Event::Empty(start) => {
                let empty_depth = depth
                    .checked_add(1)
                    .ok_or_else(|| "presentation XML depth overflow".to_owned())?;
                if empty_depth > limits.maximum_xml_depth {
                    return Err("presentation XML exceeds structural limits".to_owned());
                }
                nodes = nodes
                    .checked_add(1)
                    .ok_or_else(|| "presentation XML node overflow".to_owned())?;
                for attribute in start.attributes().with_checks(true) {
                    let attribute = attribute
                        .map_err(|error| format!("presentation XML attribute: {error}"))?;
                    attributes = attributes
                        .checked_add(1)
                        .ok_or_else(|| "presentation XML attribute overflow".to_owned())?;
                    if attribute.value.len() > MAX_XML_VALUE_BYTES {
                        return Err("presentation XML attribute exceeds its bound".to_owned());
                    }
                }
            }
            Event::End(_) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| "presentation XML depth is unbalanced".to_owned())?;
            }
            Event::Text(text) => {
                if text.len()
                    > usize::try_from(limits.maximum_text_characters)
                        .unwrap_or(usize::MAX)
                        .saturating_mul(4)
                {
                    return Err("presentation XML text node exceeds its bound".to_owned());
                }
            }
            Event::CData(text) => {
                if text.len()
                    > usize::try_from(limits.maximum_text_characters)
                        .unwrap_or(usize::MAX)
                        .saturating_mul(4)
                {
                    return Err("presentation XML CDATA node exceeds its bound".to_owned());
                }
            }
            Event::DocType(_) | Event::PI(_) | Event::GeneralRef(_) => {
                return Err(
                    "presentation XML active declaration or reference is forbidden".to_owned(),
                )
            }
            Event::Eof => break,
            Event::Decl(_) | Event::Comment(_) => {}
        }
        if depth > limits.maximum_xml_depth
            || nodes > limits.maximum_xml_nodes
            || attributes > limits.maximum_xml_nodes.saturating_mul(8)
        {
            return Err("presentation XML exceeds structural limits".to_owned());
        }
    }
    if depth != 0 {
        return Err("presentation XML is not balanced".to_owned());
    }
    Ok(())
}

const MAX_XML_VALUE_BYTES: usize = 32 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use d2i_presentation_capability::default_presentation_resource_limits;

    #[test]
    fn package_names_reject_traversal_and_xml_rejects_entities() {
        for name in [
            "../evil",
            "C:/evil",
            "//server/share",
            "safe/%2e%2e/evil",
            "safe\\evil",
        ] {
            assert!(validate_package_entry_name(name).is_err(), "{name}");
        }
        assert!(validate_xml_part(
            b"<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///x'>]><x>&e;</x>",
            &default_presentation_resource_limits()
        )
        .is_err());
    }

    #[test]
    fn active_parts_and_external_relationships_are_rejected() {
        assert!(is_forbidden_active_part("ppt/vbaProject.bin"));
        assert!(is_forbidden_active_part("ppt/embeddings/oleObject1.bin"));
        assert!(validate_relationship_part(
            br#"<Relationships><Relationship Id="rId1" Type="x" Target="https://example.test" TargetMode="External"/></Relationships>"#
        )
        .is_err());
    }
}
