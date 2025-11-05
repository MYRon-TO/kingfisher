use std::hash::{Hash, Hasher};

use base64::{engine::general_purpose, Engine};
use rustc_hash::{FxHashMap, FxHasher};
use xxhash_rust::xxh3::xxh3_64;

use crate::{
    location::OffsetSpan,
    parser::{self, Language},
};

#[derive(Debug, Clone)]
pub struct DecodedData {
    pub original: String,
    pub decoded: String,
    pub pos_start: usize,
    pub pos_end: usize,
}

#[inline]
fn is_base64_byte(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/')
}

pub fn get_base64_strings(input: &[u8]) -> Vec<DecodedData> {
    let mut results = Vec::new();
    let mut i = 0;
    while i < input.len() {
        while i < input.len() && !is_base64_byte(input[i]) {
            i += 1;
        }
        let start = i;
        while i < input.len() && is_base64_byte(input[i]) {
            i += 1;
        }

        let mut eq_count = 0;
        while i < input.len() && input[i] == b'=' && eq_count < 2 {
            i += 1;
            eq_count += 1;
        }
        let end = i;

        let len = end - start;
        if len >= 32 && len % 4 == 0 {
            let base64_slice = &input[start..end];
            if let Ok(decoded) = general_purpose::STANDARD.decode(base64_slice) {
                if let Ok(decoded_str) = std::str::from_utf8(&decoded) {
                    if decoded_str.is_ascii() {
                        results.push(DecodedData {
                            original: String::from_utf8_lossy(base64_slice).into_owned(),
                            decoded: decoded_str.to_string(),
                            pos_start: start,
                            pos_end: end,
                        });
                    }
                }
            }
        }
    }

    results
}

pub fn compute_finding_fingerprint(
    finding_value: &str,
    file_or_commit: &str,
    offset_start: u64,
    offset_end: u64,
) -> u64 {
    // Combine all into a byte buffer and hash it directly:
    let mut buf = Vec::with_capacity(
        finding_value.len() + file_or_commit.len() + 2 * std::mem::size_of::<u64>(),
    );
    buf.extend_from_slice(finding_value.as_bytes());
    buf.extend_from_slice(file_or_commit.as_bytes());
    buf.extend_from_slice(&offset_start.to_le_bytes());
    buf.extend_from_slice(&offset_end.to_le_bytes());

    xxh3_64(&buf)
}

pub(crate) fn get_language_and_queries(lang: &str) -> Option<(Language, FxHashMap<String, String>)> {
    match lang.to_lowercase().as_str() {
        "bash" | "shell" => Some((Language::Bash, parser::queries::bash::get_bash_queries())),
        "c" => Some((Language::C, parser::queries::c::get_c_queries())),
        "c#" | "csharp" => Some((Language::CSharp, parser::queries::csharp::get_csharp_queries())),
        "c++" | "cpp" => Some((Language::Cpp, parser::queries::cpp::get_cpp_queries())),
        "css" => Some((Language::Css, parser::queries::css::get_css_queries())),
        "go" => Some((Language::Go, parser::queries::go::get_go_queries())),
        "html" => Some((Language::Html, parser::queries::html::get_html_queries())),
        "java" => Some((Language::Java, parser::queries::java::get_java_queries())),
        "javascript" | "js" => {
            Some((Language::JavaScript, parser::queries::javascript::get_javascript_queries()))
        }
        // "kotlin" => Some((
        //     Language::Kotlin,
        //     parser::queries::kotlin::get_kotlin_queries(),
        // )),
        "php" => Some((Language::Php, parser::queries::php::get_php_queries())),
        "python" | "py" | "starlark" => {
            Some((Language::Python, parser::queries::python::get_python_queries()))
        }
        "ruby" => Some((Language::Ruby, parser::queries::ruby::get_ruby_queries())),
        "rust" => Some((Language::Rust, parser::queries::rust::get_rust_queries())),
        "toml" => Some((Language::Toml, parser::queries::toml::get_toml_queries())),
        "typescript" | "ts" => {
            Some((Language::TypeScript, parser::queries::typescript::get_typescript_queries()))
        }
        "yaml" => Some((Language::Yaml, parser::queries::yaml::get_yaml_queries())),
        _ => None,
    }
}

#[inline]
pub(crate) fn compute_match_key(content: &[u8], rule_id: &[u8], start: usize, end: usize) -> u64 {
    let mut hasher = FxHasher::default();
    // Hash each component directly without allocation
    content.hash(&mut hasher);
    rule_id.hash(&mut hasher);
    start.hash(&mut hasher);
    end.hash(&mut hasher);
    hasher.finish()
}

#[inline]
fn insert_span(spans: &mut Vec<OffsetSpan>, span: OffsetSpan) -> bool {
    let mut idx = spans.binary_search_by(|s| s.start.cmp(&span.start)).unwrap_or_else(|i| i);
    if idx > 0 {
        if spans[idx - 1].fully_contains(&span) {
            return false;
        }
        if span.fully_contains(&spans[idx - 1]) {
            spans.remove(idx - 1);
            idx -= 1;
        }
    }
    if idx < spans.len() {
        if spans[idx].fully_contains(&span) {
            return false;
        }
        if span.fully_contains(&spans[idx]) {
            spans.remove(idx);
        }
    }
    spans.insert(idx, span);
    true
}

#[inline]
pub(crate) fn record_match(
    map: &mut FxHashMap<usize, Vec<OffsetSpan>>,
    rule_id: usize,
    span: OffsetSpan,
) -> bool {
    insert_span(map.entry(rule_id).or_default(), span)
}
