use crate::source::read_bounded;
use crate::{Diagnostic, Severity, SourceInventory, SourceLocation, MAX_SOURCE_FILE_BYTES};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::path::Path;

const MAX_RECORDS_PER_FILE: usize = 100_000;

/// Supported Phase 1 source formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFormat {
    Markdown,
    Text,
    Csv,
    Json,
    JsonLines,
    Yaml,
}

/// Parsed, bounded representation retained before Domain IR exists.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedContent {
    Text(String),
    Csv {
        headers: Vec<String>,
        records: Vec<Vec<String>>,
    },
    Json(JsonValue),
    JsonLines(Vec<JsonValue>),
    Yaml(YamlValue),
}

/// One parsed source document with its normalized relative path.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedDocument {
    path: String,
    format: SourceFormat,
    content: ParsedContent,
}

impl ParsedDocument {
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn format(&self) -> SourceFormat {
        self.format
    }

    #[must_use]
    pub const fn content(&self) -> &ParsedContent {
        &self.content
    }
}

/// Parses all inventory entries while accumulating independent file errors.
#[must_use]
pub fn parse_inventory(inventory: &SourceInventory) -> (Vec<ParsedDocument>, Vec<Diagnostic>) {
    let mut documents = Vec::new();
    let mut diagnostics = Vec::new();

    for entry in inventory.entries() {
        let path = inventory.root().join(Path::new(entry.path()));
        match parse_file(&path, entry.path()) {
            Ok(document) => documents.push(document),
            Err(mut errors) => diagnostics.append(&mut errors),
        }
    }

    (documents, diagnostics)
}

fn parse_file(path: &Path, relative: &str) -> Result<ParsedDocument, Vec<Diagnostic>> {
    let bytes = read_bounded(path, MAX_SOURCE_FILE_BYTES).map_err(|error| {
        vec![parse_error(
            relative,
            None,
            "D2I1200",
            format!("cannot read source: {error}"),
            "check file permissions",
        )]
    })?;
    let source = std::str::from_utf8(&bytes).map_err(|error| {
        vec![parse_error(
            relative,
            u32::try_from(error.valid_up_to()).ok(),
            "D2I1201",
            "source is not valid UTF-8",
            "encode the file as UTF-8",
        )]
    })?;
    let extension = path
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();

    let (format, content) = match extension.as_str() {
        "md" => (
            SourceFormat::Markdown,
            ParsedContent::Text(source.to_owned()),
        ),
        "txt" => (SourceFormat::Text, ParsedContent::Text(source.to_owned())),
        "csv" => (SourceFormat::Csv, parse_csv(relative, source)?),
        "json" => {
            let value = serde_json::from_str(source).map_err(|error| {
                vec![parse_error(
                    relative,
                    u32::try_from(error.line()).ok(),
                    "D2I1202",
                    format!("invalid JSON: {error}"),
                    "fix the JSON syntax",
                )]
            })?;
            (SourceFormat::Json, ParsedContent::Json(value))
        }
        "jsonl" => (SourceFormat::JsonLines, parse_json_lines(relative, source)?),
        "yaml" | "yml" => {
            let value = serde_yaml::from_str(source).map_err(|error| {
                let line = error
                    .location()
                    .and_then(|location| u32::try_from(location.line()).ok());
                vec![parse_error(
                    relative,
                    line,
                    "D2I1203",
                    format!("invalid YAML: {error}"),
                    "fix the YAML syntax",
                )]
            })?;
            (SourceFormat::Yaml, ParsedContent::Yaml(value))
        }
        _ => {
            return Err(vec![parse_error(
                relative,
                None,
                "D2I1204",
                "unsupported source format",
                "use a Phase 1 supported extension",
            )]);
        }
    };

    Ok(ParsedDocument {
        path: relative.to_owned(),
        format,
        content,
    })
}

fn parse_csv(relative: &str, source: &str) -> Result<ParsedContent, Vec<Diagnostic>> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(source.as_bytes());
    let headers = reader
        .headers()
        .map_err(|error| {
            vec![parse_error(
                relative,
                error.position().and_then(|position| {
                    position
                        .line()
                        .checked_add(0)
                        .and_then(|line| u32::try_from(line).ok())
                }),
                "D2I1205",
                format!("invalid CSV header: {error}"),
                "provide a valid UTF-8 CSV header row",
            )]
        })?
        .iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    if headers.is_empty() {
        return Err(vec![parse_error(
            relative,
            Some(1),
            "D2I1206",
            "CSV must have a header row",
            "add one or more named columns",
        )]);
    }

    let mut records = Vec::new();
    let mut diagnostics = Vec::new();
    for record in reader.records() {
        if records.len() >= MAX_RECORDS_PER_FILE {
            diagnostics.push(parse_error(
                relative,
                None,
                "D2I1207",
                format!("CSV exceeds {MAX_RECORDS_PER_FILE} records"),
                "split the CSV into smaller files",
            ));
            break;
        }
        match record {
            Ok(record) => records.push(record.iter().map(str::to_owned).collect()),
            Err(error) => diagnostics.push(parse_error(
                relative,
                error
                    .position()
                    .and_then(|position| u32::try_from(position.line()).ok()),
                "D2I1208",
                format!("invalid CSV record: {error}"),
                "fix the record width or quoting",
            )),
        }
    }

    if diagnostics.is_empty() {
        Ok(ParsedContent::Csv { headers, records })
    } else {
        Err(diagnostics)
    }
}

fn parse_json_lines(relative: &str, source: &str) -> Result<ParsedContent, Vec<Diagnostic>> {
    let mut values = Vec::new();
    let mut diagnostics = Vec::new();

    for (index, line) in source.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if values.len() >= MAX_RECORDS_PER_FILE {
            diagnostics.push(parse_error(
                relative,
                u32::try_from(index + 1).ok(),
                "D2I1209",
                format!("JSONL exceeds {MAX_RECORDS_PER_FILE} records"),
                "split the JSONL into smaller files",
            ));
            break;
        }
        match serde_json::from_str(line) {
            Ok(value) => values.push(value),
            Err(error) => diagnostics.push(parse_error(
                relative,
                u32::try_from(index + 1).ok(),
                "D2I1210",
                format!("invalid JSONL record: {error}"),
                "store exactly one valid JSON value per non-empty line",
            )),
        }
    }

    if diagnostics.is_empty() {
        Ok(ParsedContent::JsonLines(values))
    } else {
        Err(diagnostics)
    }
}

fn parse_error(
    path: &str,
    line: Option<u32>,
    code: &str,
    message: impl Into<String>,
    help: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(Severity::Error, code, message)
        .with_location(SourceLocation::new(path, line, None))
        .with_help(help)
}
