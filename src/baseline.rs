use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use chrono::Local;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::findings_store::FindingsStore;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BaselineFile {
    #[serde(rename = "ExactFindings", default)]
    pub exact_findings: ExactFindings,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ExactFindings {
    #[serde(default)]
    pub matches: Vec<BaselineFinding>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BaselineFinding {
    pub filepath: String,
    pub fingerprint: String,
    pub linenum: usize,
    pub lastupdated: String,
}

pub fn load_baseline(path: &Path) -> Result<BaselineFile> {
    let data = fs::read_to_string(path).context("read baseline file")?;
    Ok(serde_yaml::from_str(&data).context("parse baseline yaml")?)
}

pub fn save_baseline(path: &Path, baseline: &BaselineFile) -> Result<()> {
    let data = serde_yaml::to_string(baseline).context("serialize baseline")?;
    fs::write(path, data).context("write baseline file")
}

fn normalize_path(p: &Path, roots: &[PathBuf]) -> String {
    for root in roots {
        if let Ok(stripped) = p.strip_prefix(root) {
            if let Some(name) = root.file_name() {
                return PathBuf::from(name).join(stripped).to_string_lossy().replace('\\', "/");
            }
        }
    }
    p.to_string_lossy().replace('\\', "/")
}

pub fn apply_baseline(
    store: &mut FindingsStore,
    baseline_path: &Path,
    manage: bool,
    roots: &[PathBuf],
) -> Result<()> {
    let mut baseline = if baseline_path.exists() {
        load_baseline(baseline_path)?
    } else {
        BaselineFile::default()
    };

    let mut known: HashSet<String> =
        baseline.exact_findings.matches.iter().map(|m| m.fingerprint.clone()).collect();

    let mut encountered: HashSet<String> = HashSet::new();
    let mut new_entries = Vec::new();
    for arc_msg in store.get_matches_mut() {
        let (origin, _blob, m) = Arc::make_mut(arc_msg);
        let file_path = origin.iter().filter_map(|o| o.full_path()).next();
        let hash = format!("{:016x}", m.finding_fingerprint);

        if let Some(fp) = file_path {
            let normalized = normalize_path(&fp, roots);
            if known.contains(&hash) {
                debug!("Skipping {} due to baseline (hash {})", normalized, hash);
                m.visible = false;
                if manage {
                    encountered.insert(hash.clone());
                }
            } else if manage {
                known.insert(hash.clone());
                encountered.insert(hash.clone());
                let entry = BaselineFinding {
                    filepath: normalized,
                    fingerprint: hash,
                    linenum: m.location.source_span.start.line,
                    lastupdated: Local::now().to_rfc2822(),
                };
                new_entries.push(entry);
            }
        } else if known.contains(&hash) {
            m.visible = false;
            if manage {
                encountered.insert(hash.clone());
            }
        }
    }
    if manage {
        let original_len = baseline.exact_findings.matches.len();
        baseline.exact_findings.matches.retain(|m| encountered.contains(&m.fingerprint));
        let mut changed = baseline.exact_findings.matches.len() != original_len;

        if !new_entries.is_empty() {
            baseline.exact_findings.matches.extend(new_entries);
            changed = true;
        }

        if changed {
            save_baseline(baseline_path, &baseline)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blob::{BlobId, BlobMetadata},
        location::{Location, OffsetSpan, SourcePoint, SourceSpan},
        matcher::{Match, SerializableCaptures, captures::SerializableCapture},
        origin::{Origin, OriginSet},
        rules::rule::{Confidence, Rule, RuleSyntax},
    };
    use anyhow::Result;
    use smallvec::SmallVec;
    use std::{path::Path, sync::Arc};
    use tempfile::TempDir;

    fn test_rule() -> Arc<Rule> {
        Arc::new(Rule::new(RuleSyntax {
            name: "test".to_string(),
            id: "test.rule".to_string(),
            pattern: "test".to_string(),
            min_entropy: 0.0,
            confidence: Confidence::Low,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None,
            depends_on_rule: vec![],
        }))
    }

    fn empty_captures() -> SerializableCaptures {
        SerializableCaptures { captures: SmallVec::<[SerializableCapture; 2]>::new() }
    }

    fn make_store_with_match(fingerprint: u64, file_path: &Path) -> FindingsStore {
        let mut store = FindingsStore::new(PathBuf::from("."));
        let rule = test_rule();
        let match_item = Match {
            location: Location {
                offset_span: OffsetSpan { start: 0, end: 1 },
                source_span: SourceSpan {
                    start: SourcePoint { line: 1, column: 0 },
                    end: SourcePoint { line: 1, column: 1 },
                },
            },
            groups: empty_captures(),
            blob_id: BlobId::default(),
            finding_fingerprint: fingerprint,
            rule: Arc::clone(&rule),
            validation_response_body: String::new(),
            validation_response_status: 0,
            validation_success: false,
            calculated_entropy: 0.0,
            visible: true,
            is_base64: false,
        };

        let origin = OriginSet::from(Origin::from_file(file_path.to_path_buf()));
        let blob_meta = Arc::new(BlobMetadata {
            id: BlobId::default(),
            num_bytes: 0,
            mime_essence: None,
            language: None,
        });

        let entry = Arc::new((Arc::new(origin), blob_meta, match_item));
        store.get_matches_mut().push(entry);
        store
    }

    fn expected_relative_path(root: &Path, file: &Path) -> String {
        let mut expected = PathBuf::from(root.file_name().unwrap());
        if let Ok(stripped) = file.strip_prefix(root) {
            expected = expected.join(stripped);
        }
        expected.to_string_lossy().replace('\\', "/")
    }

    #[test]
    fn apply_baseline_filters_existing_fingerprints() -> Result<()> {
        let tmp = TempDir::new()?;
        let roots = [tmp.path().to_path_buf()];
        let secret_file = tmp.path().join("secret.txt");
        fs::write(&secret_file, "dummy")?;
        let baseline_path = tmp.path().join("baseline.yaml");
        let fingerprint = 0x1234_u64;

        let mut store = make_store_with_match(fingerprint, &secret_file);
        apply_baseline(&mut store, &baseline_path, true, &roots)?;

        let baseline = load_baseline(&baseline_path)?;
        assert_eq!(baseline.exact_findings.matches.len(), 1);
        let entry = &baseline.exact_findings.matches[0];
        assert_eq!(entry.fingerprint, format!("{:016x}", fingerprint));
        assert_eq!(entry.filepath, expected_relative_path(roots[0].as_path(), &secret_file));

        let (_, _, recorded) = store.get_matches()[0].as_ref();
        assert!(recorded.visible);

        let mut follow_up = make_store_with_match(fingerprint, &secret_file);
        apply_baseline(&mut follow_up, &baseline_path, false, &roots)?;
        let (_, _, filtered) = follow_up.get_matches()[0].as_ref();
        assert!(!filtered.visible);

        Ok(())
    }

    #[test]
    fn managing_baseline_is_idempotent() -> Result<()> {
        let tmp = TempDir::new()?;
        let roots = [tmp.path().to_path_buf()];
        let secret_file = tmp.path().join("secret.txt");
        fs::write(&secret_file, "dummy")?;
        let baseline_path = tmp.path().join("baseline.yaml");
        let fingerprint = 0xfeed_beef_dade_f00d_u64;

        let mut initial = make_store_with_match(fingerprint, &secret_file);
        apply_baseline(&mut initial, &baseline_path, true, &roots)?;
        let baseline_before = fs::read_to_string(&baseline_path)?;

        let mut rerun = make_store_with_match(fingerprint, &secret_file);
        apply_baseline(&mut rerun, &baseline_path, true, &roots)?;
        let baseline_after = fs::read_to_string(&baseline_path)?;
        assert_eq!(baseline_before, baseline_after);

        let (_, _, suppressed) = rerun.get_matches()[0].as_ref();
        assert!(!suppressed.visible);

        Ok(())
    }
}
