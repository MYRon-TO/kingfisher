use std::{
    fmt::Write,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use http::StatusCode;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use schemars::JsonSchema;
use serde::Serialize;
use url::Url;

use crate::{
    blob::BlobMetadata,
    bstring_escape::Escaped,
    cli,
    cli::global::GlobalArgs,
    finding_data, findings_store,
    matcher::match_structs::Match,
    origin::{Origin, OriginSet},
    rules::rule::Confidence,
};
mod bson_format;
mod json_format;
mod pretty_format;
mod sarif_format;
pub mod styles;
use std::io::IsTerminal;

use styles::{StyledObject, Styles};

use crate::{
    cli::commands::output::ReportOutputFormat,
    location::SourceSpan,
    origin::{get_repo_url, GitRepoOrigin},
};

const BITBUCKET_FRAGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'|');

const AZURE_QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'|');

fn build_git_urls(
    repo_url: &str,
    commit_id: &str,
    file_path: &str,
    line: usize,
) -> (String, String, String) {
    let repo_url = repo_url.trim_end_matches('/');
    let mut repository_url = repo_url.to_string();
    let mut commit_url = format!("{repo_url}/commit/{commit_id}");
    let mut file_url = format!("{repo_url}/blob/{commit_id}/{file_path}#L{line}",);

    if let Ok(parsed) = Url::parse(repo_url) {
        let scheme = parsed.scheme();
        let host = parsed.host_str().unwrap_or_default();
        let segments: Vec<&str> = parsed
            .path_segments()
            .map(|segments| segments.filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();

        let format_anchor = |path: &str| {
            let normalized = path.replace('\\', "/");
            utf8_percent_encode(normalized.trim_start_matches('/'), BITBUCKET_FRAGMENT_ENCODE_SET)
                .to_string()
        };

        if host.eq_ignore_ascii_case("bitbucket.org") {
            let joined = segments.join("/");
            let base = if joined.is_empty() {
                format!("{scheme}://{host}")
            } else {
                format!("{scheme}://{host}/{joined}")
            };
            let anchor = format_anchor(file_path);
            repository_url = base.clone();
            commit_url = format!("{base}/commits/{commit_id}");
            file_url = format!("{base}/commits/{commit_id}#L{anchor}F{line}");
        } else if host.contains("bitbucket") {
            if segments.len() >= 3 && segments[0].eq_ignore_ascii_case("scm") {
                let project = segments[1];
                let repo = segments[2];
                let base = format!("{scheme}://{host}/projects/{project}/repos/{repo}");
                let anchor = format_anchor(file_path);
                repository_url = base.clone();
                commit_url = format!("{base}/commits/{commit_id}");
                file_url = format!("{base}/commits/{commit_id}#L{anchor}F{line}");
            }
        } else if host.eq_ignore_ascii_case("dev.azure.com") || host.ends_with(".visualstudio.com")
        {
            let normalized = file_path.replace('\\', "/");
            let trimmed = normalized.trim_start_matches('/');
            let encoded_path = utf8_percent_encode(trimmed, AZURE_QUERY_ENCODE_SET).to_string();
            repository_url = repo_url.to_string();
            commit_url = format!("{repo_url}/commit/{commit_id}");
            if line > 0 {
                file_url =
                    format!("{repo_url}/commit/{commit_id}?path=/{}&line={line}", encoded_path);
            } else {
                file_url = format!("{repo_url}/commit/{commit_id}?path=/{}", encoded_path);
            }
        }
    }

    (repository_url, commit_url, file_url)
}

pub fn run(
    global_args: &GlobalArgs,
    ds: Arc<Mutex<findings_store::FindingsStore>>,
    args: &cli::commands::scan::ScanArgs,
) -> Result<()> {
    global_args.use_color(std::io::stdout());
    let stdout_is_tty = std::io::stdout().is_terminal();
    let use_color = stdout_is_tty && !args.output_args.has_output();
    let styles = Styles::new(use_color);

    let ds_clone = Arc::clone(&ds);
    // Initialize the reporter
    let reporter = DetailsReporter { datastore: ds_clone, styles, only_valid: args.only_valid };
    let writer = args.output_args.get_writer()?;
    // Generate and write the report in the specified format
    reporter.report(args.output_args.format, writer, args)
}
pub struct DetailsReporter {
    pub datastore: Arc<Mutex<findings_store::FindingsStore>>,
    pub styles: Styles,
    pub only_valid: bool,
}

impl DetailsReporter {
    pub fn extract_git_metadata(
        &self,
        prov: &GitRepoOrigin,
        source_span: &SourceSpan,
    ) -> Option<serde_json::Value> {
        let repo_url = get_repo_url(&prov.repo_path)
            .unwrap_or_else(|_| prov.repo_path.to_string_lossy().to_string().into());
        let repo_url = repo_url.trim_end_matches(".git").to_string();
        if let Some(cs) = &prov.first_commit {
            let cmd = &cs.commit_metadata;
            let commit_id = cmd.commit_id.to_string();
            let (repository_url, commit_url, file_url) =
                build_git_urls(&repo_url, &commit_id, &cs.blob_path, source_span.start.line);
            // let msg =
            //     String::from_utf8_lossy(cmd.message.lines().next().unwrap_or(&[],),).
            // into_owned();

            let atime =
                cmd.committer_timestamp.format(gix::date::time::format::SHORT.clone()).to_string();

            let git_metadata = serde_json::json!({
                "repository_url": repository_url,
                "commit": {
                    "id": commit_id,
                    "url": commit_url,
                    "date": atime,
                    "committer": {
                        "name": &cmd.committer_name,
                        "email": &cmd.committer_email,
                    },
                    // "author": {
                    //     "name": String::from_utf8_lossy(&cmd.author_name),
                    //     "email": String::from_utf8_lossy(&cmd.author_email),
                    // },
                    // "message": msg,
                },
                "file": {
                    "path": &cs.blob_path,
                    "url": file_url,
                    "git_command": format!(
                        "git -C {} show {}:{}",
                        prov.repo_path.display(),
                        cmd.commit_id,
                        &cs.blob_path
                    )
                }
            });
            Some(git_metadata)
        } else {
            None
        }
    }

    /// If the given file path corresponds to a Jira issue downloaded to disk,
    /// return the online Jira URL for that issue.
    fn jira_issue_url(
        &self,
        path: &std::path::Path,
        args: &cli::commands::scan::ScanArgs,
    ) -> Option<String> {
        // drop any trailing slash so we don’t end up with “//browse/…”
        let jira_url = args.input_specifier_args.jira_url.as_ref()?.as_str().trim_end_matches('/');

        let ds = self.datastore.lock().ok()?;
        let root = ds.clone_root();
        let jira_dir = root.join("jira_issues");
        if path.starts_with(&jira_dir) {
            let key = path.file_stem()?.to_string_lossy();
            Some(format!("{}/browse/{}", jira_url, key))
        } else {
            None
        }
    }

    /// If the given file path corresponds to a Confluence page downloaded to disk,
    /// return the URL for that page.
    fn confluence_page_url(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        ds.confluence_links().get(path).cloned()
    }

    /// If the given file path corresponds to a Slack message downloaded to disk,
    /// return the permalink for that message.
    fn slack_message_url(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        ds.slack_links().get(path).cloned()
    }

    fn repo_artifact_url(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        ds.repo_links().get(path).cloned()
    }

    fn s3_display_path(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        for (dir, bucket) in ds.s3_buckets().iter() {
            if path.starts_with(dir) {
                let rel = path.strip_prefix(dir).ok()?;
                return Some(format!("s3://{}/{}", bucket, rel.display()));
            }
        }
        None
    }

    fn docker_display_path(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        for (dir, image) in ds.docker_images().iter() {
            if path.starts_with(dir) {
                let rel = path.strip_prefix(dir).ok()?;
                let mut rel_str = rel.display().to_string();
                rel_str = rel_str.replace(".decomp.tar!", ".tar.gz | ");
                rel_str = rel_str.replace(".tar!", ".tar | ");
                rel_str = rel_str.replace('!', " | ");
                return Some(format!("{} | {}", image, rel_str));
            }
        }
        None
    }

    fn process_matches(&self, only_valid: bool, filter_visible: bool) -> Result<Vec<ReportMatch>> {
        let datastore = self.datastore.lock().unwrap();
        Ok(datastore
            .get_matches()
            .iter()
            .filter(|msg| {
                let (_origin, _blob_metadata, match_item) = &***msg;
                if only_valid {
                    // If filter_visible is true, require the match to be visible.
                    if filter_visible {
                        match_item.validation_success
                            && match_item.validation_response_status
                                != StatusCode::CONTINUE.as_u16()
                            && match_item.visible
                    } else {
                        // Do not filter by visibility when not needed (for validation)
                        match_item.validation_success
                            && match_item.validation_response_status
                                != StatusCode::CONTINUE.as_u16()
                    }
                } else {
                    // When not filtering by only_valid, use visibility if desired.
                    if filter_visible {
                        match_item.visible
                    } else {
                        true
                    }
                }
            })
            .map(|msg| {
                let (origin, blob_metadata, match_item) = &**msg;
                ReportMatch {
                    origin: (**origin).clone(),
                    blob_metadata: (**blob_metadata).clone(),
                    m: match_item.clone(),
                    comment: None,
                    visible: match_item.visible,
                    match_confidence: match_item.rule.confidence(),
                    validation_response_body: match_item.validation_response_body.clone(),
                    validation_response_status: match_item.validation_response_status,
                    validation_success: match_item.validation_success,
                }
            })
            .collect())
    }

    pub fn get_filtered_matches(&self) -> Result<Vec<ReportMatch>> {
        self.process_matches(self.only_valid, true)
    }

    pub fn get_unfiltered_matches(&self, only_valid: Option<bool>) -> Result<Vec<ReportMatch>> {
        self.process_matches(only_valid.unwrap_or(self.only_valid), false)
    }

    pub fn deduplicate_matches(
        &self,
        matches: Vec<ReportMatch>,
        no_dedup: bool,
    ) -> Vec<ReportMatch> {
        if no_dedup {
            return matches;
        }

        use std::collections::HashMap;
        let mut by_fp: HashMap<u64, ReportMatch> = HashMap::new();

        for rm in matches {
            let fp = rm.m.finding_fingerprint;
            if let Some(existing) = by_fp.get_mut(&fp) {
                // merge origin sets (keep first origin, append the rest)
                for o in rm.origin.iter() {
                    if !existing.origin.iter().any(|e| e == o) {
                        existing.origin = OriginSet::new(
                            existing.origin.first().clone(),
                            existing
                                .origin
                                .iter()
                                .skip(1)
                                .cloned()
                                .chain(std::iter::once(o.clone()))
                                .collect(),
                        );
                    }
                }
                continue;
            }
            by_fp.insert(fp, rm);
        }
        by_fp.into_values().collect()
    }

    fn matches_for_output(&self, args: &cli::commands::scan::ScanArgs) -> Result<Vec<ReportMatch>> {
        let mut matches = self.get_filtered_matches()?;
        if !args.no_dedup {
            matches = self.deduplicate_matches(matches, args.no_dedup);
        }
        if args.no_dedup {
            let mut expanded = Vec::new();
            for rm in matches {
                if rm.origin.len() > 1 {
                    for origin in rm.origin.iter() {
                        let mut single = rm.clone();
                        single.origin = OriginSet::new(origin.clone(), Vec::new());
                        expanded.push(single);
                    }
                } else {
                    expanded.push(rm);
                }
            }
            matches = expanded;
        }
        matches.sort_by(|a, b| {
            let path_a = a
                .origin
                .first()
                .full_path()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let path_b = b
                .origin
                .first()
                .full_path()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            path_a
                .cmp(&path_b)
                .then_with(|| {
                    a.m.location.source_span.start.line.cmp(&b.m.location.source_span.start.line)
                })
                .then_with(|| {
                    a.m.location
                        .source_span
                        .start
                        .column
                        .cmp(&b.m.location.source_span.start.column)
                })
        });
        Ok(matches)
    }

    pub fn build_finding_record(
        &self,
        rm: &ReportMatch,
        args: &cli::commands::scan::ScanArgs,
    ) -> FindingReporterRecord {
        let source_span = &rm.m.location.source_span;
        let line_num = source_span.start.line;

        let snippet = Escaped(
            rm.m.groups
                .captures
                .get(1)
                .or_else(|| rm.m.groups.captures.get(0))
                .map(|capture| capture.value.as_bytes())
                .unwrap_or_default(),
        )
        .to_string();

        let validation_status = if rm.validation_success {
            "Active Credential".to_string()
        } else if rm.validation_response_status == StatusCode::CONTINUE.as_u16() {
            "Not Attempted".to_string()
        } else {
            "Inactive Credential".to_string()
        };

        const MAX_RESPONSE_LENGTH: usize = 512;
        let truncated_body: String =
            rm.validation_response_body.chars().take(MAX_RESPONSE_LENGTH).collect();
        let ellipsis =
            if rm.validation_response_body.len() > MAX_RESPONSE_LENGTH { "..." } else { "" };
        let response_body = format!("{}{}", truncated_body, ellipsis);

        let git_metadata_val = rm
            .origin
            .iter()
            .filter_map(|origin| {
                if let Origin::GitRepo(e) = origin {
                    self.extract_git_metadata(e, source_span)
                } else {
                    None
                }
            })
            .next();

        let file_path = rm
            .origin
            .iter()
            .find_map(|origin| self.origin_display_path(origin, args))
            .or_else(|| {
                rm.origin.iter().find_map(|origin| {
                    origin
                        .blob_path()
                        .map(|p| p.display().to_string())
                        .and_then(Self::non_empty_string)
                })
            })
            .or_else(|| self.git_object_fallback_path(rm))
            .unwrap_or_else(|| format!("blob:{}", rm.blob_metadata.id.hex()));

        FindingReporterRecord {
            rule: RuleMetadata {
                name: rm.m.rule.name().to_string(),
                id: rm.m.rule.id().to_string(),
            },
            finding: FindingRecordData {
                snippet,
                fingerprint: rm.m.finding_fingerprint.to_string(),
                confidence: rm.m.rule.confidence().to_string(),
                entropy: format!("{:.2}", rm.m.calculated_entropy),
                validation: ValidationInfo { status: validation_status, response: response_body },
                language: rm
                    .blob_metadata
                    .language
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
                line: line_num as u32,
                column_start: source_span.start.column as u32,
                column_end: source_span.end.column as u32,
                path: file_path,
                encoding: if rm.m.is_base64 { Some("base64".to_string()) } else { None },
                git_metadata: git_metadata_val,
            },
        }
    }

    fn origin_display_path(
        &self,
        origin: &Origin,
        args: &cli::commands::scan::ScanArgs,
    ) -> Option<String> {
        match origin {
            Origin::File(e) => self
                .repo_artifact_url(&e.path)
                .and_then(Self::non_empty_string)
                .or_else(|| self.jira_issue_url(&e.path, args).and_then(Self::non_empty_string))
                .or_else(|| self.confluence_page_url(&e.path).and_then(Self::non_empty_string))
                .or_else(|| self.slack_message_url(&e.path).and_then(Self::non_empty_string))
                .or_else(|| self.s3_display_path(&e.path).and_then(Self::non_empty_string))
                .or_else(|| self.docker_display_path(&e.path).and_then(Self::non_empty_string))
                .or_else(|| Self::non_empty_string(e.path.display().to_string())),
            Origin::GitRepo(e) => {
                e.first_commit.as_ref().and_then(|c| Self::non_empty_string(c.blob_path.clone()))
            }
            Origin::Extended(e) => {
                e.path().map(|p| p.display().to_string()).and_then(Self::non_empty_string)
            }
        }
    }

    fn git_object_fallback_path(&self, rm: &ReportMatch) -> Option<String> {
        let blob_hex = rm.blob_metadata.id.hex();
        rm.origin.iter().find_map(|origin| {
            if let Origin::GitRepo(repo_origin) = origin {
                let (prefix, suffix) = blob_hex.split_at(2);
                let repo_path = repo_origin.repo_path.as_ref();
                let git_dir_objects = repo_path.join(".git").join("objects");
                let objects_dir = if git_dir_objects.is_dir() {
                    git_dir_objects
                } else {
                    repo_path.join("objects")
                };
                let fallback_path = objects_dir.join(prefix).join(suffix);
                Self::non_empty_string(fallback_path.display().to_string())
            } else {
                None
            }
        })
    }

    fn non_empty_string(value: String) -> Option<String> {
        if value.trim().is_empty() {
            None
        } else {
            Some(value)
        }
    }

    pub fn build_finding_records(
        &self,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<Vec<FindingReporterRecord>> {
        let matches = self.matches_for_output(args)?;
        Ok(matches.iter().map(|rm| self.build_finding_record(rm, args)).collect())
    }

    fn style_finding_heading<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_finding_heading.apply_to(val)
    }

    fn style_finding_active_heading<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_finding_active_heading.apply_to(val)
    }

    #[allow(dead_code)]
    fn style_rule<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_rule.apply_to(val)
    }

    #[allow(dead_code)]
    fn style_heading<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_heading.apply_to(val)
    }

    fn style_match<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_match.apply_to(val)
    }

    fn style_metadata<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_metadata.apply_to(val)
    }

    fn style_active_creds<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_active_creds.apply_to(val)
    }
}
/// A trait for things that can be output as a document.
///
/// This trait is used to factor output-related code, such as friendly handling
/// of buffering, into one place.
pub trait Reportable {
    type Format;
    fn report<W: std::io::Write>(
        &self,
        format: Self::Format,
        writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()>;
}
impl Reportable for DetailsReporter {
    type Format = ReportOutputFormat;

    fn report<W: std::io::Write>(
        &self,
        format: Self::Format,
        writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        match format {
            ReportOutputFormat::Pretty => self.pretty_format(writer, args),
            ReportOutputFormat::Json => self.json_format(writer, args),
            ReportOutputFormat::Jsonl => self.jsonl_format(writer, args),
            ReportOutputFormat::Bson => self.bson_format(writer, args),
            ReportOutputFormat::Sarif => self.sarif_format(writer, args.no_dedup, args),
        }
    }
}

/// A match produced by one of kingfisher's rules.
/// This corresponds to a single location.
#[derive(Serialize, JsonSchema, Clone)]
pub struct ReportMatch {
    pub origin: OriginSet,

    #[serde(rename = "blob_metadata")]
    pub blob_metadata: BlobMetadata,

    #[serde(flatten)]
    pub m: Match,

    /// An optional comment assigned to the match
    pub comment: Option<String>,

    /// The confidence level of the match
    pub match_confidence: Confidence,

    /// Whether the match is visible in the output
    pub visible: bool,

    /// Validation Body
    pub validation_response_body: String,

    /// Validation Status Code
    pub validation_response_status: u16,

    /// Validation Success
    pub validation_success: bool,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct FindingReporterRecord {
    pub rule: RuleMetadata,
    pub finding: FindingRecordData,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct RuleMetadata {
    pub name: String,
    pub id: String,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct ValidationInfo {
    pub status: String,
    pub response: String,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct FindingRecordData {
    pub snippet: String,
    pub fingerprint: String,
    pub confidence: String,
    pub entropy: String,
    pub validation: ValidationInfo,
    pub language: String,
    pub line: u32,
    pub column_start: u32,
    pub column_end: u32,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_metadata: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blob::{BlobId, BlobMetadata},
        cli::commands::inputs::{ContentFilteringArgs, InputSpecifierArgs},
        cli::commands::output::OutputArgs,
        cli::commands::scan::{ConfidenceLevel, ScanArgs},
        cli::commands::{
            azure::AzureRepoType,
            bitbucket::{BitbucketAuthArgs, BitbucketRepoType},
            gitea::GiteaRepoType,
            github::{GitCloneMode, GitHistoryMode, GitHubRepoType},
            gitlab::GitLabRepoType,
            rules::RuleSpecifierArgs,
        },
        git_commit_metadata::CommitMetadata,
        location::{Location, OffsetSpan, SourcePoint, SourceSpan},
        matcher::{SerializableCapture, SerializableCaptures},
        origin::{Origin, OriginSet},
        rules::rule::{Confidence, Rule, RuleSyntax},
    };
    use gix::{date::Time, ObjectId};
    use smallvec::SmallVec;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn sample_scan_args() -> ScanArgs {
        ScanArgs {
            num_jobs: 1,
            rules: RuleSpecifierArgs::default(),
            input_specifier_args: InputSpecifierArgs {
                path_inputs: Vec::new(),
                git_url: Vec::new(),
                github_user: Vec::new(),
                github_organization: Vec::new(),
                github_exclude: Vec::new(),
                all_github_organizations: false,
                github_api_url: Url::parse("https://api.github.com/").unwrap(),
                github_repo_type: GitHubRepoType::Source,
                gitlab_user: Vec::new(),
                gitlab_group: Vec::new(),
                gitlab_exclude: Vec::new(),
                all_gitlab_groups: false,
                gitlab_api_url: Url::parse("https://gitlab.com/").unwrap(),
                gitlab_repo_type: GitLabRepoType::All,
                gitlab_include_subgroups: false,
                huggingface_user: Vec::new(),
                huggingface_organization: Vec::new(),
                huggingface_model: Vec::new(),
                huggingface_dataset: Vec::new(),
                huggingface_space: Vec::new(),
                huggingface_exclude: Vec::new(),
                gitea_user: Vec::new(),
                gitea_organization: Vec::new(),
                gitea_exclude: Vec::new(),
                all_gitea_organizations: false,
                gitea_api_url: Url::parse("https://gitea.com/api/v1/").unwrap(),
                gitea_repo_type: GiteaRepoType::Source,
                bitbucket_user: Vec::new(),
                bitbucket_workspace: Vec::new(),
                bitbucket_project: Vec::new(),
                bitbucket_exclude: Vec::new(),
                all_bitbucket_workspaces: false,
                bitbucket_api_url: Url::parse("https://api.bitbucket.org/2.0/").unwrap(),
                bitbucket_repo_type: BitbucketRepoType::Source,
                bitbucket_auth: BitbucketAuthArgs::default(),
                azure_organization: Vec::new(),
                azure_project: Vec::new(),
                azure_exclude: Vec::new(),
                all_azure_projects: false,
                azure_base_url: Url::parse("https://dev.azure.com/").unwrap(),
                azure_repo_type: AzureRepoType::Source,
                jira_url: None,
                jql: None,
                confluence_url: None,
                cql: None,
                slack_query: None,
                slack_api_url: Url::parse("https://slack.com/api/").unwrap(),
                max_results: 100,
                s3_bucket: None,
                s3_prefix: None,
                role_arn: None,
                aws_local_profile: None,
                gcs_bucket: None,
                gcs_prefix: None,
                gcs_service_account: None,
                docker_image: Vec::new(),
                git_clone: GitCloneMode::Bare,
                git_history: GitHistoryMode::Full,
                commit_metadata: true,
                repo_artifacts: false,
                scan_nested_repos: true,
                since_commit: None,
                branch: None,
                branch_root: false,
                branch_root_commit: None,
            },
            extra_ignore_comments: Vec::new(),
            content_filtering_args: ContentFilteringArgs {
                max_file_size_mb: 256.0,
                exclude: Vec::new(),
                no_extract_archives: false,
                extraction_depth: 2,
                no_binary: false,
            },
            confidence: ConfidenceLevel::Medium,
            no_validate: false,
            only_valid: false,
            min_entropy: None,
            rule_stats: false,
            no_dedup: false,
            redact: false,
            no_base64: false,
            git_repo_timeout: 1_800,
            output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
            baseline_file: None,
            manage_baseline: false,
            skip_regex: Vec::new(),
            skip_word: Vec::new(),
            skip_aws_account: Vec::new(),
            skip_aws_account_file: None,
            no_inline_ignore: false,
        }
    }

    fn sample_report_match(
        validation_body: &str,
        validation_status: u16,
        validation_success: bool,
    ) -> (ReportMatch, String) {
        let repo_path = Arc::new(PathBuf::from("/tmp/repo"));
        let commit_metadata = Arc::new(CommitMetadata {
            commit_id: ObjectId::from_hex(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            committer_name: "Alice".into(),
            committer_email: "alice@example.com".into(),
            committer_timestamp: Time::new(0, 0),
        });
        let blob_path = "path/in/history.txt".to_string();
        let origin = OriginSet::new(
            Origin::from_git_repo_with_first_commit(repo_path, commit_metadata, blob_path.clone()),
            vec![],
        );

        let rule = Arc::new(Rule::new(RuleSyntax {
            name: "Test Rule".into(),
            id: "test.rule".into(),
            pattern: ".*".into(),
            min_entropy: 0.0,
            confidence: Confidence::Medium,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None,
            depends_on_rule: vec![],
        }));

        let blob_id = BlobId::new(b"blob-data");
        let validation_body_owned = validation_body.to_string();
        let report_match = ReportMatch {
            origin,
            blob_metadata: BlobMetadata {
                id: blob_id,
                num_bytes: 42,
                mime_essence: None,
                language: Some("Unknown".into()),
            },
            m: Match {
                location: Location {
                    offset_span: OffsetSpan { start: 0, end: 10 },
                    source_span: SourceSpan {
                        start: SourcePoint { line: 19, column: 0 },
                        end: SourcePoint { line: 19, column: 10 },
                    },
                },
                groups: SerializableCaptures {
                    captures: SmallVec::<[SerializableCapture; 2]>::new(),
                },
                blob_id,
                finding_fingerprint: 123,
                rule: Arc::clone(&rule),
                validation_response_body: validation_body_owned.clone(),
                validation_response_status: validation_status,
                validation_success,
                calculated_entropy: 5.29,
                visible: true,
                is_base64: false,
            },
            comment: None,
            match_confidence: Confidence::Medium,
            visible: true,
            validation_response_body: validation_body_owned,
            validation_response_status: validation_status,
            validation_success,
        };

        (report_match, blob_path)
    }

    #[test]
    fn build_finding_record_uses_git_blob_path() {
        let temp = tempdir().unwrap();
        let datastore =
            Arc::new(Mutex::new(findings_store::FindingsStore::new(temp.path().to_path_buf())));
        let reporter = DetailsReporter { datastore, styles: Styles::new(false), only_valid: false };

        let (report_match, blob_path) =
            sample_report_match("Bad credentials", StatusCode::UNAUTHORIZED.as_u16(), false);

        let scan_args = sample_scan_args();

        let record = reporter.build_finding_record(&report_match, &scan_args);
        assert_eq!(record.finding.path, blob_path);
        let git_file_path = record
            .finding
            .git_metadata
            .as_ref()
            .and_then(|git| git.get("file"))
            .and_then(|file| file.get("path"))
            .and_then(|path| path.as_str())
            .unwrap();
        assert_eq!(git_file_path, "path/in/history.txt");
    }

    #[test]
    fn skip_list_matches_surface_skip_reason() {
        let temp = tempdir().unwrap();
        let datastore =
            Arc::new(Mutex::new(findings_store::FindingsStore::new(temp.path().to_path_buf())));
        let reporter = DetailsReporter { datastore, styles: Styles::new(false), only_valid: false };

        let (report_match, _) = sample_report_match(
            "(skip list entry) AWS validation not attempted for account 111122223333.",
            StatusCode::CONTINUE.as_u16(),
            false,
        );
        let scan_args = sample_scan_args();

        let record = reporter.build_finding_record(&report_match, &scan_args);
        assert_eq!(record.finding.validation.status, "Not Attempted");
        assert_eq!(
            record.finding.validation.response,
            "(skip list entry) AWS validation not attempted for account 111122223333."
        );
    }

    use super::build_git_urls;

    #[test]
    fn azure_commit_links_use_query_paths() {
        let (repo_url, commit_url, file_url) = build_git_urls(
            "https://dev.azure.com/org/project/_git/repo",
            "0123456789abcdef",
            "dir/file.txt",
            7,
        );

        assert_eq!(repo_url, "https://dev.azure.com/org/project/_git/repo");
        assert_eq!(
            commit_url,
            "https://dev.azure.com/org/project/_git/repo/commit/0123456789abcdef"
        );
        assert_eq!(
            file_url,
            "https://dev.azure.com/org/project/_git/repo/commit/0123456789abcdef?path=/dir/file.txt&line=7"
        );
    }
}

impl From<finding_data::FindingDataEntry> for ReportMatch {
    fn from(e: finding_data::FindingDataEntry) -> Self {
        ReportMatch {
            origin: e.origin,
            blob_metadata: e.blob_metadata,
            m: e.match_val,
            comment: e.match_comment,
            visible: e.visible,
            match_confidence: e.match_confidence,
            validation_response_body: e.validation_response_body.clone(),
            validation_response_status: e.validation_response_status,
            validation_success: e.validation_success,
        }
    }
}
