use bstr::BString;
use regex::bytes::Regex;
use schemars::{
    gen::SchemaGenerator,
    schema::{ArrayValidation, InstanceType, Schema},
    JsonSchema,
};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use crate::{
    snippet::Base64BString,
    util::{intern, redact_value},
};

// -------------------------------------------------------------------------------------------------
// Group
// -------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct Group(pub Base64BString);
impl Group {
    pub fn new(m: regex::bytes::Match<'_>) -> Self {
        Self(Base64BString(BString::from(m.as_bytes())))
    }
}
// -------------------------------------------------------------------------------------------------
// Groups
// -------------------------------------------------------------------------------------------------
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Groups(pub SmallVec<[Group; 1]>);
impl JsonSchema for Groups {
    fn schema_name() -> String {
        "Groups".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        let group_schema = gen.subschema_for::<Group>();
        Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(InstanceType::Array.into()),
            array: Some(Box::new(ArrayValidation {
                items: Some(group_schema.into()),
                ..Default::default()
            })),
            ..Default::default()
        })
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SerializableCapture {
    pub name: Option<String>,
    pub match_number: i32,
    pub start: usize,
    pub end: usize,
    /// Interned value of the capture.
    pub value: &'static str,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SerializableCaptures {
    #[schemars(with = "Vec<SerializableCapture>")]
    pub captures: SmallVec<[SerializableCapture; 2]>, // All captures (named and unnamed)
}
impl SerializableCaptures {
    pub fn from_captures(
        captures: &regex::bytes::Captures,
        _input: &[u8],
        re: &Regex,
        redact: bool,
    ) -> Self {
        let mut serialized_captures: SmallVec<[SerializableCapture; 2]> = SmallVec::new();
        // Process named captures
        for name in re.capture_names().flatten() {
            if let Some(capture) = captures.name(name) {
                let value = if redact {
                    redact_value(&String::from_utf8_lossy(capture.as_bytes()))
                } else {
                    String::from_utf8_lossy(capture.as_bytes()).to_string()
                };
                serialized_captures.push(SerializableCapture {
                    name: Some(name.to_string()),
                    match_number: -1,
                    start: capture.start(),
                    end: capture.end(),
                    value: intern(&value),
                });
            }
        }
        // Process unnamed captures (numbered groups)
        for i in 0..captures.len() {
            if let Some(capture) = captures.get(i) {
                let value = if redact {
                    redact_value(&String::from_utf8_lossy(capture.as_bytes()))
                } else {
                    String::from_utf8_lossy(capture.as_bytes()).to_string()
                };
                serialized_captures.push(SerializableCapture {
                    name: None,
                    match_number: i32::try_from(i).unwrap_or(0),
                    start: capture.start(),
                    end: capture.end(),
                    value: intern(&value),
                });
            }
        }
        SerializableCaptures { captures: serialized_captures }
    }
}
