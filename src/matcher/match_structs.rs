use std::sync::Arc;

use http::StatusCode;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    blob::BlobId,
    location::{Location, LocationMapping, OffsetSpan, SourcePoint, SourceSpan},
    rules::rule::Rule,
    snippet::Base64BString,
};

use super::{captures::SerializableCaptures, util::compute_finding_fingerprint};

// -------------------------------------------------------------------------------------------------
// RawMatch
// -------------------------------------------------------------------------------------------------
/// A raw match, as recorded by a callback to Vectorscan.
///
/// When matching with Vectorscan, we simply collect all matches into a
/// preallocated `Vec`, and then go through them all after scanning is complete.
#[derive(PartialEq, Eq, Debug, Clone)]
pub(crate) struct RawMatch {
    pub(crate) rule_id: u32,
    pub(crate) start_idx: u64,
    pub(crate) end_idx: u64,
}

#[derive(Clone)]
pub struct OwnedBlobMatch {
    pub rule: Arc<Rule>,
    pub blob_id: BlobId,
    /// The unique content-based identifier of this match
    pub finding_fingerprint: u64,
    pub matching_input_offset_span: OffsetSpan,
    pub captures: SerializableCaptures,
    pub validation_response_body: String,
    pub validation_response_status: StatusCode,
    pub validation_success: bool,
    pub calculated_entropy: f32,
    pub is_base64: bool,
}

impl OwnedBlobMatch {
    pub fn convert_match_to_owned_blobmatch(m: &Match, rule: Arc<Rule>) -> OwnedBlobMatch {
        OwnedBlobMatch {
            rule,
            blob_id: m.blob_id,
            finding_fingerprint: m.finding_fingerprint,
            // matching_input: m.snippet.matching.0.to_vec(),
            matching_input_offset_span: m.location.offset_span,
            captures: m.groups.clone(),
            validation_response_body: m.validation_response_body.clone(),
            validation_response_status: StatusCode::from_u16(m.validation_response_status)
                .unwrap_or(StatusCode::CONTINUE),
            validation_success: m.validation_success,
            calculated_entropy: m.calculated_entropy,
            is_base64: m.is_base64,
        }
    }

    pub fn from_blob_match(blob_match: BlobMatch) -> Self {
        // Get the matching value from capture group 1 (or 0 if not available)
        let matching_finding = blob_match
            .captures
            .captures
            .get(1)
            .or_else(|| blob_match.captures.captures.first())
            .map(|capture| capture.value.as_bytes().to_vec())
            .unwrap_or_default();

        let mut owned_blob_match = OwnedBlobMatch {
            rule: blob_match.rule,
            blob_id: blob_match.blob_id,
            matching_input_offset_span: blob_match.matching_input_offset_span,
            captures: blob_match.captures.clone(),
            validation_response_body: blob_match.validation_response_body,
            validation_response_status: blob_match.validation_response_status,
            validation_success: blob_match.validation_success,
            calculated_entropy: blob_match.calculated_entropy,
            finding_fingerprint: 0, //default
            is_base64: blob_match.is_base64,
        };

        // Convert matching_finding to a &str (using lossy conversion if needed)
        let finding_value = std::str::from_utf8(&matching_finding).unwrap_or("");
        // Use blob_id as the file/commit identifier
        let file_or_commit = &blob_match.blob_id.to_string();

        let offset_start: u64 =
            owned_blob_match.matching_input_offset_span.start.try_into().unwrap();
        let offset_end: u64 = owned_blob_match.matching_input_offset_span.end.try_into().unwrap();

        owned_blob_match.finding_fingerprint =
            compute_finding_fingerprint(finding_value, file_or_commit, offset_start, offset_end);

        owned_blob_match
    }
}

// -------------------------------------------------------------------------------------------------
// BlobMatch
// -------------------------------------------------------------------------------------------------
/// A `BlobMatch` is the result type from `Matcher::scan_blob`.
///
/// It is mostly made up of references and small data.
/// For a representation that is more friendly for human consumption, see
/// `Match`.
#[derive(Clone)]
pub struct BlobMatch {
    /// The rule that was matched
    pub rule: Arc<Rule>, // Changed from `&'a Rule` to `Arc<Rule`

    /// The blob that was matched
    pub blob_id: BlobId,

    /// The matching input in `blob.input`
    // pub matching_input: Vec<u8>,

    /// The location of the matching input in `blob.input`
    pub matching_input_offset_span: OffsetSpan,

    /// The capture groups from the match
    pub captures: SerializableCaptures, // regex::bytes::Captures<'a>,

    pub validation_response_body: String,
    pub validation_response_status: StatusCode,

    pub validation_success: bool,
    pub calculated_entropy: f32,
    pub is_base64: bool,
}

// -------------------------------------------------------------------------------------------------
// Match
// -------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Match {
    /// The location of the entire matching content
    pub location: Location,

    /// The capture groups
    pub groups: SerializableCaptures, // Store serialized captures

    /// unique identifier of file / blob where this match was found
    pub blob_id: BlobId,

    /// The unique content-based identifier of this match
    pub finding_fingerprint: u64,

    /// The rule that produced this match
    #[serde(skip_serializing)]
    #[schemars(skip)]
    pub rule: Arc<Rule>,

    /// Validation Body
    pub validation_response_body: String,

    /// Validation Status Code
    pub validation_response_status: u16,

    /// Validation Success
    pub validation_success: bool,

    /// Validation Success
    pub calculated_entropy: f32,

    pub visible: bool,
    #[serde(default)]
    pub is_base64: bool,
}

impl Match {
    #[inline]
    pub fn convert_owned_blobmatch_to_match<'a>(
        loc_mapping: Option<&'a LocationMapping<'a>>,
        owned_blob_match: &'a OwnedBlobMatch,
        origin_type: &'a str,
    ) -> Self {
        let offset_span = owned_blob_match.matching_input_offset_span;
        // Extract the matched secret content. Use capture group 1 if it exists, otherwise fall back
        // to group 0.
        let matching_finding_bytes = owned_blob_match
            .captures
            .captures
            .get(1)
            .or_else(|| owned_blob_match.captures.captures.first())
            .map(|capture| capture.value.as_bytes())
            .unwrap_or_default();

        // The fingerprint will be based on the content of the secret.
        let finding_value_for_fp = std::str::from_utf8(matching_finding_bytes).unwrap_or("");

        let source_span =
            loc_mapping.map(|lm| lm.get_source_span(&offset_span)).unwrap_or(SourceSpan {
                start: SourcePoint { line: 0, column: 0 },
                end: SourcePoint { line: 0, column: 0 },
            });
        let offset_start: u64 =
            owned_blob_match.matching_input_offset_span.start.try_into().unwrap();
        let offset_end: u64 = owned_blob_match.matching_input_offset_span.end.try_into().unwrap();

        let finding_fingerprint = compute_finding_fingerprint(
            finding_value_for_fp,
            origin_type, // file_or_commit,
            offset_start,
            offset_end,
        );

        // matching_snippet
        Match {
            rule: owned_blob_match.rule.clone(),
            visible: owned_blob_match.rule.visible().to_owned(),
            location: Location {
                offset_span,
                source_span: source_span.clone(),
            },
            groups: owned_blob_match.captures.clone(),
            blob_id: owned_blob_match.blob_id,
            finding_fingerprint,
            validation_response_body: owned_blob_match.validation_response_body.clone(),
            validation_response_status: owned_blob_match.validation_response_status.as_u16(),
            validation_success: owned_blob_match.validation_success,
            calculated_entropy: owned_blob_match.calculated_entropy,
            is_base64: owned_blob_match.is_base64,
        }
    }

    /// Returns the `blob_id` of the match.
    pub fn get_blob_id(&self) -> BlobId {
        self.blob_id
    }

    pub fn finding_id(&self) -> String {
        let mut buffer = Vec::with_capacity(128);
        buffer.extend_from_slice(self.rule.finding_sha1_fingerprint().as_bytes());
        buffer.push(0);
        serde_json::to_writer(&mut buffer, &self.groups)
            .expect("should be able to serialize groups as JSON");
        let mut num = xxhash_rust::xxh3::xxh3_64(&buffer);
        // Ensure the number is positive and within i64 range
        num &= 0x7FFF_FFFF_FFFF_FFFF; // Clear the sign bit to make it positive
                                      // Convert to string
        num.to_string()
    }
}
