use d2i_document_capability::{DocumentFormatV1, DocumentResourceLimitsV1};
use quick_xml::events::Event;
use quick_xml::Reader;
use quick_xml::XmlVersion;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

#[derive(Debug, Clone)]
pub(crate) struct BoundedDocumentPackage {
    format: DocumentFormatV1,
    entries: BTreeMap<String, Vec<u8>>,
}

impl BoundedDocumentPackage {
    pub(crate) fn open(
        path: &Path,
        format: DocumentFormatV1,
        limits: &DocumentResourceLimitsV1,
    ) -> Result<Self, String> {
        let metadata = path
            .metadata()
            .map_err(|error| format!("document package metadata: {error}"))?;
        if !metadata.is_file() || metadata.len() > limits.maximum_document_bytes {
            return Err("document package is not a bounded regular file".to_owned());
        }
        let package_bytes =
            std::fs::read(path).map_err(|error| format!("document package open: {error}"))?;
        let declared_entries = central_directory_entry_count(&package_bytes)?;
        let mut archive = ZipArchive::new(Cursor::new(package_bytes.as_slice()))
            .map_err(|error| format!("document ZIP open: {error}"))?;
        if declared_entries != archive.len() {
            return Err("document package contains duplicate or shadowed entries".to_owned());
        }
        if archive.len()
            > usize::try_from(limits.maximum_package_entries)
                .map_err(|error| format!("package entry bound: {error}"))?
        {
            return Err("document package has excessive entries".to_owned());
        }
        let mut entries = BTreeMap::new();
        let mut uncompressed_total = 0_u64;
        for index in 0..archive.len() {
            let entry = archive
                .by_index(index)
                .map_err(|error| format!("document ZIP entry {index}: {error}"))?;
            let name = entry.name().to_owned();
            validate_package_entry_name(&name)?;
            if entry.is_dir() {
                continue;
            }
            if entry.encrypted() {
                return Err("password-protected document packages are unsupported".to_owned());
            }
            if entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
            {
                return Err("document package symlink entry is forbidden".to_owned());
            }
            let size = entry.size();
            let compressed = entry.compressed_size();
            uncompressed_total = uncompressed_total
                .checked_add(size)
                .ok_or_else(|| "document package size overflow".to_owned())?;
            if uncompressed_total > limits.maximum_uncompressed_bytes {
                return Err("document package exceeds the uncompressed byte limit".to_owned());
            }
            if size > 0
                && (compressed == 0
                    || size / compressed.max(1) > u64::from(limits.maximum_compression_ratio))
            {
                return Err("document package compression ratio is unsafe".to_owned());
            }
            let capacity = usize::try_from(size)
                .map_err(|error| format!("document ZIP entry size: {error}"))?;
            let mut bytes = Vec::with_capacity(capacity.min(1024 * 1024));
            let mut bounded = entry.take(size.saturating_add(1));
            bounded
                .read_to_end(&mut bytes)
                .map_err(|error| format!("document ZIP entry read: {error}"))?;
            if u64::try_from(bytes.len()).ok() != Some(size) {
                return Err("document ZIP entry length differs".to_owned());
            }
            if is_xml_part(&name) {
                validate_xml_part(&bytes, limits)?;
            }
            if is_forbidden_active_part(format, &name) {
                return Err(format!("active document part is forbidden: {name}"));
            }
            if is_relationship_part(&name) {
                validate_relationship_part(&bytes)?;
            }
            if entries.insert(name, bytes).is_some() {
                return Err("document package contains a duplicate entry".to_owned());
            }
        }
        validate_required_parts(format, &entries)?;
        validate_relationship_targets(&entries)?;
        Ok(Self { format, entries })
    }

    pub(crate) fn from_entries(
        format: DocumentFormatV1,
        entries: BTreeMap<String, Vec<u8>>,
        limits: &DocumentResourceLimitsV1,
    ) -> Result<Self, String> {
        if entries.len()
            > usize::try_from(limits.maximum_package_entries)
                .map_err(|error| format!("package entry bound: {error}"))?
        {
            return Err("generated document package has excessive entries".to_owned());
        }
        let mut total = 0_u64;
        for (name, bytes) in &entries {
            validate_package_entry_name(name)?;
            total = total
                .checked_add(
                    u64::try_from(bytes.len())
                        .map_err(|error| format!("generated package size: {error}"))?,
                )
                .ok_or_else(|| "generated document package size overflow".to_owned())?;
            if total > limits.maximum_uncompressed_bytes {
                return Err("generated document package exceeds byte limits".to_owned());
            }
            if is_xml_part(name) {
                validate_xml_part(bytes, limits)?;
            }
            if is_forbidden_active_part(format, name) {
                return Err("generated document contains an active part".to_owned());
            }
            if is_relationship_part(name) {
                validate_relationship_part(bytes)?;
            }
        }
        validate_required_parts(format, &entries)?;
        validate_relationship_targets(&entries)?;
        Ok(Self { format, entries })
    }

    pub(crate) fn entry(&self, name: &str) -> Result<&[u8], String> {
        self.entries
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| format!("required document package entry missing: {name}"))
    }

    pub(crate) fn replace_entry(&mut self, name: &str, bytes: Vec<u8>) -> Result<(), String> {
        validate_package_entry_name(name)?;
        if !self.entries.contains_key(name) {
            return Err(format!("document package entry is not present: {name}"));
        }
        self.entries.insert(name.to_owned(), bytes);
        Ok(())
    }

    pub(crate) fn insert_entry(&mut self, name: &str, bytes: Vec<u8>) -> Result<(), String> {
        validate_package_entry_name(name)?;
        if self.entries.insert(name.to_owned(), bytes).is_some() {
            return Err(format!("document package entry already exists: {name}"));
        }
        Ok(())
    }

    pub(crate) fn has_entry(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    pub(crate) fn entry_names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    pub(crate) fn write_atomic(
        &self,
        destination: &Path,
        limits: &DocumentResourceLimitsV1,
    ) -> Result<u64, String> {
        let mut archive_bytes = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut archive_bytes);
            if self.format == DocumentFormatV1::Hwpx {
                let mimetype = self.entry("mimetype")?;
                writer
                    .start_file(
                        "mimetype",
                        SimpleFileOptions::default()
                            .compression_method(CompressionMethod::Stored)
                            .unix_permissions(0o600),
                    )
                    .map_err(|error| format!("HWPX mimetype entry: {error}"))?;
                writer
                    .write_all(mimetype)
                    .map_err(|error| format!("HWPX mimetype write: {error}"))?;
            }
            for (name, bytes) in &self.entries {
                if self.format == DocumentFormatV1::Hwpx && name == "mimetype" {
                    continue;
                }
                writer
                    .start_file(
                        name,
                        SimpleFileOptions::default()
                            .compression_method(CompressionMethod::Deflated)
                            .unix_permissions(0o600),
                    )
                    .map_err(|error| format!("document ZIP start {name}: {error}"))?;
                writer
                    .write_all(bytes)
                    .map_err(|error| format!("document ZIP write {name}: {error}"))?;
            }
            writer
                .finish()
                .map_err(|error| format!("document ZIP finish: {error}"))?;
        }
        let bytes = archive_bytes.into_inner();
        if u64::try_from(bytes.len()).map_or(true, |size| size > limits.maximum_document_bytes) {
            return Err("serialized document package exceeds its byte limit".to_owned());
        }
        let parent = destination
            .parent()
            .ok_or_else(|| "document destination has no parent".to_owned())?;
        if !parent.is_dir() {
            return Err("document destination parent is unavailable".to_owned());
        }
        let name = destination
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "document destination filename is invalid".to_owned())?;
        let temporary = parent.join(format!(".{name}.d2i-office200-{}.tmp", std::process::id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|error| format!("document temporary create: {error}"))?;
            file.write_all(&bytes)
                .map_err(|error| format!("document temporary write: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("document temporary sync: {error}"))?;
            drop(file);
            std::fs::rename(&temporary, destination)
                .map_err(|error| format!("document atomic commit: {error}"))?;
            Ok(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
        })();
        if temporary.exists() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
}

fn central_directory_entry_count(bytes: &[u8]) -> Result<usize, String> {
    const EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const EOCD_MINIMUM_BYTES: usize = 22;
    const MAX_ZIP_COMMENT_BYTES: usize = 65_535;
    if bytes.len() < EOCD_MINIMUM_BYTES {
        return Err("document package lacks a complete ZIP directory".to_owned());
    }
    let search_start = bytes
        .len()
        .saturating_sub(EOCD_MINIMUM_BYTES + MAX_ZIP_COMMENT_BYTES);
    let offset = bytes[search_start..]
        .windows(EOCD_SIGNATURE.len())
        .rposition(|window| window == EOCD_SIGNATURE)
        .map(|relative| search_start + relative)
        .ok_or_else(|| "document package lacks a ZIP directory".to_owned())?;
    let count_offset = offset
        .checked_add(10)
        .ok_or_else(|| "document ZIP directory offset overflow".to_owned())?;
    let count_bytes = bytes
        .get(count_offset..count_offset + 2)
        .ok_or_else(|| "document ZIP directory entry count is truncated".to_owned())?;
    let count = u16::from_le_bytes([count_bytes[0], count_bytes[1]]);
    if count == u16::MAX {
        return Err("ZIP64 document packages are unsupported in v1".to_owned());
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
        return Err(format!("unsafe document package entry name: {name}"));
    }
    Ok(())
}

fn is_xml_part(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".xml") || lower.ends_with(".rels") || lower.ends_with(".hpf")
}

fn is_relationship_part(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".rels")
}

fn validate_relationship_part(bytes: &[u8]) -> Result<(), String> {
    for target in relationship_targets(bytes)? {
        validate_relationship_target(&target)?;
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
            .map_err(|error| format!("relationship XML: {error}"))?
        {
            Event::Start(element) | Event::Empty(element)
                if element
                    .local_name()
                    .as_ref()
                    .eq_ignore_ascii_case(b"relationship") =>
            {
                let mut target = None;
                let mut external = false;
                for attribute in element.attributes() {
                    let attribute =
                        attribute.map_err(|error| format!("relationship attribute: {error}"))?;
                    let value = attribute
                        .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
                        .map_err(|error| format!("relationship value: {error}"))?
                        .into_owned();
                    if attribute
                        .key
                        .local_name()
                        .as_ref()
                        .eq_ignore_ascii_case(b"target")
                    {
                        target = Some(value);
                    } else if attribute
                        .key
                        .local_name()
                        .as_ref()
                        .eq_ignore_ascii_case(b"targetmode")
                        && value.eq_ignore_ascii_case("external")
                    {
                        external = true;
                    }
                }
                if external {
                    return Err("external document relationship is forbidden".to_owned());
                }
                targets.push(
                    target
                        .ok_or_else(|| "document relationship is missing its target".to_owned())?,
                );
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
        return Err("document relationship target is unsafe".to_owned());
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
                    "document relationship target is missing: {resolved}"
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
    let marker = "/_rels/";
    let (prefix, file) = relationship_part
        .rsplit_once(marker)
        .ok_or_else(|| "relationship part path is malformed".to_owned())?;
    if !file.ends_with(".rels") || file.len() <= ".rels".len() {
        return Err("relationship part filename is malformed".to_owned());
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
                    .ok_or_else(|| "document relationship escapes the package".to_owned())?;
            }
            value => components.push(value.to_owned()),
        }
    }
    if components.is_empty() {
        return Err("document relationship target is empty".to_owned());
    }
    Ok(components.join("/"))
}

fn is_forbidden_active_part(format: DocumentFormatV1, name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    match format {
        DocumentFormatV1::Docx => {
            lower.ends_with("vbaproject.bin")
                || lower.starts_with("word/activex/")
                || lower.starts_with("word/embeddings/")
                || lower.starts_with("customui/")
                || lower.ends_with(".exe")
                || lower.ends_with(".dll")
                || lower.ends_with(".js")
                || lower.ends_with(".vbs")
        }
        DocumentFormatV1::Hwpx => {
            lower.starts_with("scripts/")
                || lower.contains("/scripts/")
                || lower.ends_with(".js")
                || lower.ends_with(".exe")
                || lower.ends_with(".dll")
                || lower.ends_with(".com")
                || lower.ends_with(".bat")
                || lower.ends_with(".cmd")
        }
        DocumentFormatV1::Hwp | DocumentFormatV1::Doc => true,
    }
}

fn validate_required_parts(
    format: DocumentFormatV1,
    entries: &BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    let required: &[&str] = match format {
        DocumentFormatV1::Hwpx => &[
            "mimetype",
            "version.xml",
            "META-INF/container.xml",
            "META-INF/manifest.xml",
            "Contents/content.hpf",
            "Contents/header.xml",
            "Contents/section0.xml",
        ],
        DocumentFormatV1::Docx => &[
            "[Content_Types].xml",
            "_rels/.rels",
            "word/document.xml",
            "word/_rels/document.xml.rels",
        ],
        DocumentFormatV1::Hwp | DocumentFormatV1::Doc => {
            return Err("legacy binary documents require a licensed application backend".to_owned())
        }
    };
    for name in required {
        if !entries.contains_key(*name) {
            return Err(format!("required document package part missing: {name}"));
        }
    }
    if format == DocumentFormatV1::Hwpx
        && entries.get("mimetype").map(Vec::as_slice) != Some(b"application/hwp+zip")
    {
        return Err("HWPX mimetype signature differs".to_owned());
    }
    Ok(())
}

pub(crate) fn validate_xml_part(
    bytes: &[u8],
    limits: &DocumentResourceLimitsV1,
) -> Result<(), String> {
    if u64::try_from(bytes.len()).map_or(true, |size| size > limits.maximum_xml_bytes) {
        return Err("document XML exceeds its byte limit".to_owned());
    }
    let uppercase = String::from_utf8_lossy(bytes).to_ascii_uppercase();
    if uppercase.contains("<!DOCTYPE")
        || uppercase.contains("<!ENTITY")
        || uppercase.contains(" SYSTEM ")
        || uppercase.contains(" PUBLIC ")
    {
        return Err("document XML DTD or entity declaration is forbidden".to_owned());
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
            .map_err(|error| format!("document XML parse: {error}"))?
        {
            Event::Start(start) => {
                depth = depth
                    .checked_add(1)
                    .ok_or_else(|| "document XML depth overflow".to_owned())?;
                nodes = nodes
                    .checked_add(1)
                    .ok_or_else(|| "document XML node overflow".to_owned())?;
                for attribute in start.attributes().with_checks(true) {
                    let attribute =
                        attribute.map_err(|error| format!("document XML attribute: {error}"))?;
                    attributes = attributes
                        .checked_add(1)
                        .ok_or_else(|| "document XML attribute overflow".to_owned())?;
                    if attribute.value.len() > MAX_XML_VALUE_BYTES {
                        return Err("document XML attribute exceeds its bound".to_owned());
                    }
                }
            }
            Event::Empty(start) => {
                let empty_depth = depth
                    .checked_add(1)
                    .ok_or_else(|| "document XML depth overflow".to_owned())?;
                if empty_depth > limits.maximum_xml_depth {
                    return Err("document XML exceeds structural limits".to_owned());
                }
                nodes = nodes
                    .checked_add(1)
                    .ok_or_else(|| "document XML node overflow".to_owned())?;
                for attribute in start.attributes().with_checks(true) {
                    let attribute =
                        attribute.map_err(|error| format!("document XML attribute: {error}"))?;
                    attributes = attributes
                        .checked_add(1)
                        .ok_or_else(|| "document XML attribute overflow".to_owned())?;
                    if attribute.value.len() > MAX_XML_VALUE_BYTES {
                        return Err("document XML attribute exceeds its bound".to_owned());
                    }
                }
            }
            Event::End(_) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| "document XML depth is unbalanced".to_owned())?;
            }
            Event::Text(text) => {
                if text.len()
                    > usize::try_from(limits.maximum_text_characters_per_node)
                        .unwrap_or(usize::MAX)
                        .saturating_mul(4)
                {
                    return Err("document XML text node exceeds its bound".to_owned());
                }
            }
            Event::CData(text) => {
                if text.len()
                    > usize::try_from(limits.maximum_text_characters_per_node)
                        .unwrap_or(usize::MAX)
                        .saturating_mul(4)
                {
                    return Err("document XML CDATA node exceeds its bound".to_owned());
                }
            }
            Event::DocType(_) | Event::PI(_) | Event::GeneralRef(_) => {
                return Err("document XML active declaration or reference is forbidden".to_owned())
            }
            Event::Eof => break,
            Event::Decl(_) | Event::Comment(_) => {}
        }
        if depth > limits.maximum_xml_depth
            || nodes > limits.maximum_xml_nodes
            || attributes > limits.maximum_xml_attributes
        {
            return Err("document XML exceeds structural limits".to_owned());
        }
    }
    if depth != 0 {
        return Err("document XML is not balanced".to_owned());
    }
    Ok(())
}

const MAX_XML_VALUE_BYTES: usize = 32 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> DocumentResourceLimitsV1 {
        crate::document_work::default_document_resource_limits()
    }

    #[test]
    fn xml_validator_rejects_doctype_entity_and_depth() {
        assert!(validate_xml_part(
            b"<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///x'>]><x>&e;</x>",
            &limits()
        )
        .is_err());
        let mut constrained = limits();
        constrained.maximum_xml_depth = 2;
        assert!(validate_xml_part(b"<a><b><c/></b></a>", &constrained).is_err());
    }

    #[test]
    fn package_entry_rejects_traversal_drive_unc_and_encoding() {
        for name in [
            "../evil",
            "C:/evil",
            "//server/share",
            "safe/%2e%2e/evil",
            "safe\\evil",
        ] {
            assert!(validate_package_entry_name(name).is_err(), "{name}");
        }
        assert!(validate_package_entry_name("Contents/section0.xml").is_ok());
    }
}
