use reqwest::Url;
use tokio::net::lookup_host;

use crate::validation::SerializableCaptures;

/// Return (NAME, value, start, end) for every capture we care about.
///
/// * If a capture has a name, use that (upper-cased)  
/// * If it’s unnamed, fall back to `"TOKEN"`  
/// * Skip the unnamed “whole-match” capture **only when** there are
///   additional captures to return.
pub fn process_captures(captures: &SerializableCaptures) -> Vec<(String, String, usize, usize)> {
    let multiple = captures.captures.len() > 1;

    captures
        .captures
        .iter()
        // Skip the whole-match capture (match_number == 0) only when there
        // are additional captures. All other captures – named or unnamed –
        // should be preserved.
        .filter(|cap| !multiple || cap.match_number != 0)
        .map(|cap| {
            let name =
                cap.name.as_ref().map(|n| n.to_uppercase()).unwrap_or_else(|| "TOKEN".to_string());
            (name, cap.value.to_string(), cap.start, cap.end)
        })
        .collect()
}

pub fn find_closest_variable(
    captures: &[(String, String, usize, usize)],
    target_value: &String,
    target_variable_name: &str,
    search_variable_name: &str,
) -> Option<String> {
    // Collect the positions of the target variable for the provided value so we can
    // compare relative offsets with candidate variables.
    let mut target_positions = Vec::new();
    for (name, value, start, end) in captures {
        if name == target_variable_name && value == target_value {
            target_positions.push((*start, *end));
        }
    }

    if target_positions.is_empty() {
        return None;
    }

    // Prefer candidates that appear before the target value (same logical block), but
    // fall back to overlapping values and then to those that appear after the target
    // value when no better match exists. This avoids pairing with the next block when
    // multiple credentials are close together in the same file.
    let mut best_before: Option<(usize, String)> = None;
    let mut best_overlap: Option<(usize, String)> = None;
    let mut best_after: Option<(usize, String)> = None;

    for (target_start, target_end) in target_positions.iter().copied() {
        for (name, value, start, end) in captures {
            if name != search_variable_name {
                continue;
            }

            if *end <= target_start {
                // Candidate is before the target; choose the one closest to the target start.
                let distance = target_start - *end;
                match &mut best_before {
                    Some((best_distance, best_value)) if distance < *best_distance => {
                        *best_distance = distance;
                        *best_value = value.clone();
                    }
                    None => {
                        best_before = Some((distance, value.clone()));
                    }
                    _ => {}
                }
            } else if *start >= target_end {
                // Candidate is after the target; choose the one closest to the target end.
                let distance = *start - target_end;
                match &mut best_after {
                    Some((best_distance, best_value)) if distance < *best_distance => {
                        *best_distance = distance;
                        *best_value = value.clone();
                    }
                    None => {
                        best_after = Some((distance, value.clone()));
                    }
                    _ => {}
                }
            } else {
                // Candidate overlaps the target – treat as an exact match.
                let distance = 0usize;
                match &mut best_overlap {
                    Some((best_distance, best_value)) if distance < *best_distance => {
                        *best_distance = distance;
                        *best_value = value.clone();
                    }
                    None => {
                        best_overlap = Some((distance, value.clone()));
                    }
                    _ => {}
                }
            }
        }
    }

    best_before.or(best_overlap).or(best_after).map(|(_, value)| value)
}

pub async fn check_url_resolvable(url: &Url) -> Result<(), Box<dyn std::error::Error>> {
    let host = url.host_str().ok_or("No host in URL")?;
    let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    let addr = format!("{}:{}", host, port);
    lookup_host(addr).await?.next().ok_or_else(|| "Failed to resolve URL".into()).map(|_| ())
}

// -----------------------------------------------------------------------------
// tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::{captures::SerializableCapture, SerializableCaptures};
    use pretty_assertions::assert_eq;
    use smallvec::smallvec;

    #[test]
    fn single_unnamed_capture_is_returned() {
        let captures = SerializableCaptures {
            captures: smallvec![SerializableCapture {
                name: None,
                match_number: 0,
                start: 1,
                end: 4,
                value: "abc",
            }],
        };
        let result = process_captures(&captures);
        assert_eq!(result, vec![("TOKEN".to_string(), "abc".to_string(), 1usize, 4usize)]);
    }

    #[test]
    fn skips_whole_match_when_multiple() {
        let captures = SerializableCaptures {
            captures: smallvec![
                SerializableCapture {
                    name: None,
                    match_number: 0,
                    start: 0,
                    end: 5,
                    value: "abcde",
                },
                SerializableCapture {
                    name: Some("foo".to_string()),
                    match_number: -1,
                    start: 1,
                    end: 4,
                    value: "bcd",
                },
            ],
        };
        let result = process_captures(&captures);
        assert_eq!(result, vec![("FOO".to_string(), "bcd".to_string(), 1usize, 4usize)]);
    }

    #[test]
    fn includes_unnamed_groups_but_skips_whole_match() {
        let captures = SerializableCaptures {
            captures: smallvec![
                SerializableCapture {
                    name: None,
                    match_number: 0,
                    start: 0,
                    end: 6,
                    value: "aabbcc",
                },
                SerializableCapture {
                    name: Some("foo".to_string()),
                    match_number: -1,
                    start: 0,
                    end: 2,
                    value: "aa",
                },
                SerializableCapture { name: None, match_number: 1, start: 4, end: 6, value: "cc" },
            ],
        };
        let result = process_captures(&captures);
        assert_eq!(
            result,
            vec![
                ("FOO".to_string(), "aa".to_string(), 0usize, 2usize),
                ("TOKEN".to_string(), "cc".to_string(), 4usize, 6usize),
            ]
        );
    }

    #[test]
    fn prefers_closest_preceding_variable() {
        let captures = vec![
            ("TOKEN".to_string(), "secret".to_string(), 75usize, 115usize),
            ("AKID".to_string(), "preceding".to_string(), 30usize, 50usize),
            ("AKID".to_string(), "following".to_string(), 180usize, 200usize),
        ];

        let result =
            find_closest_variable(&captures, &"secret".to_string(), "TOKEN", "AKID").unwrap();

        assert_eq!(result, "preceding".to_string());
    }

    #[test]
    fn falls_back_to_following_when_no_preceding() {
        let captures = vec![
            ("TOKEN".to_string(), "secret".to_string(), 10usize, 50usize),
            ("AKID".to_string(), "after".to_string(), 60usize, 80usize),
        ];

        let result =
            find_closest_variable(&captures, &"secret".to_string(), "TOKEN", "AKID").unwrap();

        assert_eq!(result, "after".to_string());
    }
}
