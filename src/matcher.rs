use std::{
    hash::{Hash, Hasher},
    str,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use bstr::BString;
use http::StatusCode;
use regex::bytes::{Captures, Regex}; // 显式导入 Captures
use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use schemars::{
    gen::SchemaGenerator,
    schema::{ArrayValidation, InstanceType, Schema},
    JsonSchema,
};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use tracing::debug;
use xxhash_rust::xxh3::xxh3_64;

use crate::{
    blob::{Blob, BlobId, BlobIdMap},
    entropy::calculate_shannon_entropy,
    inline_ignore::InlineIgnoreConfig,
    location::{Location, LocationMapping, OffsetSpan, SourcePoint, SourceSpan},
    origin::OriginSet,
    parser,
    parser::{Checker, Language},
    rule_profiling::{ConcurrentRuleProfiler, RuleStats, RuleTimer},
    rules::rule::Rule,
    rules_database::RulesDatabase,
    safe_list::{is_safe_match, is_user_match},
    scanner_pool::ScannerPool,
    snippet::Base64BString,
    util::{intern, redact_value},
};

const MAX_CHUNK_SIZE: usize = 1 << 30; // 1 GiB per scan segment
const CHUNK_OVERLAP: usize = 64 * 1024; // 64 KiB overlap to catch boundary matches
const BASE64_SCAN_LIMIT: usize = 64 * 1024 * 1024; // skip expensive Base64 pass on huge blobs
const TREE_SITTER_MAX_LIMIT: usize = 64 * 1024; // only run tree-sitter on blobs <= 64 KiB
const TREE_SITTER_MIN_LIMIT: usize = 1 * 1024; // only run tree-sitter on blobs >= 1 KiB

// -------------------------------------------------------------------------------------------------
// RawMatch
// -------------------------------------------------------------------------------------------------
/// A raw match, as recorded by a callback to Vectorscan.
///
/// When matching with Vectorscan, we simply collect all matches into a
/// preallocated `Vec`, and then go through them all after scanning is complete.
#[derive(PartialEq, Eq, Debug, Clone)]
struct RawMatch {
    rule_id: u32,
    start_idx: u64,
    end_idx: u64,
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
    pub rule: Arc<Rule>, // Changed from `&'a Rule` to `Arc<Rule

    /// The blob that was matched
    pub blob_id: BlobId,

    /// The matching input in `blob.input`
    pub matching_input: Vec<u8>,

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
#[derive(Clone)]
struct UserData {
    /// A scratch vector for raw matches from Vectorscan, to minimize allocation
    raw_matches_scratch: Vec<RawMatch>,

    /// The length of the input being scanned
    input_len: u64,
}

// -------------------------------------------------------------------------------------------------
// REFACTOR: Pipeline Definitions
// -------------------------------------------------------------------------------------------------

/// 一个临时的、零拷贝的候选者，用于在过滤管道中传递。
/// 它的生命周期 'a 绑定到 `captures_iter` 所在的 `haystack`。
struct LightweightCandidate<'a> {
    // --- 零拷贝数据 (引用) ---
    finding_bytes: &'a [u8],      // 密钥 (group 1 or 0)
    full_capture_bytes: &'a [u8], // 完整匹配 (group 0)
    captures: &'a Captures<'a>,   // 原始捕获组
    haystack: &'a [u8],           // 被搜索的字符串
    re: &'a Regex,                // 使用的正则表达式
    // --- 上下文 (廉价拷贝) ---
    rule: Arc<Rule>,
    rule_id_usize: usize,
    blob_id: BlobId,
    is_base64: bool,
    redact: bool,
    // --- 预计算数据 ---
    finding_span_in_blob: OffsetSpan,
    calculated_entropy: f32,
}

/// 包含所有过滤器可能需要的上下文和可变状态。
/// 它的生命周期 'ctx 绑定到 `scan_blob` 的作用域。
struct FilterContext<'ctx> {
    /// 原始 Blob 的字节，用于 inline_ignore 等检查
    blob_bytes: &'ctx [u8],
    inline_ignore_config: &'ctx InlineIgnoreConfig,
    /// 可变的状态，用于有状态的过滤器
    seen_matches: &'ctx mut FxHashSet<u64>,
    previous_matches: &'ctx mut FxHashMap<usize, Vec<OffsetSpan>>,
}

/// “统一风格的函数”：一个可组合的、零拷贝的过滤器函数。
///
/// ★ REFACTOR: 修正了 `type` 别名，使用了您提供的 `for<...>` (HRTB) 语法。★
/// 这使其可以被存储在 Vec 中，并接受任何传入的生命周期。
type ZeroCopyFilterFn =
    Box<dyn for<'a, 'ctx> Fn(&LightweightCandidate<'a>, &mut FilterContext<'ctx>) -> bool>;

// -------------------------------------------------------------------------------------------------
// Matcher
// -------------------------------------------------------------------------------------------------
/// A `Matcher` is able to scan inputs for matches from rules in a
/// `RulesDatabase`.
///
/// If doing multi-threaded scanning, use a separate `Matcher` for each thread.
#[derive(Clone)]
pub struct Matcher<'a> {
    /// Thread-local pool that hands out a &mut BlockScanner
    scanner_pool: std::sync::Arc<crate::scanner_pool::ScannerPool>,

    /// The rules database used for matching
    rules_db: &'a RulesDatabase,

    /// Local statistics for this `Matcher`
    local_stats: MatcherStats,

    /// Global statistics, updated with the local statsistics when this
    /// `Matcher` is dropped
    global_stats: Option<&'a Mutex<MatcherStats>>,

    /// The set of blobs that have been seen
    seen_blobs: &'a BlobIdMap<bool>,

    /// Data passed to the Vectorscan callback
    user_data: UserData,

    /// Rule profiler for measuring performance of individual rules
    profiler: Option<Arc<ConcurrentRuleProfiler>>,

    /// Configuration that controls inline ignore directives
    inline_ignore_config: InlineIgnoreConfig,
}
impl<'a> Matcher<'a> {
    pub fn get_profiling_report(&self) -> Option<Vec<RuleStats>> {
        self.profiler.as_ref().map(|p| p.generate_report())
    }
}
/// This `Drop` implementation updates the `global_stats` with the local stats
impl<'a> Drop for Matcher<'a> {
    fn drop(&mut self) {
        if let Some(global_stats) = self.global_stats {
            let mut global_stats = global_stats.lock().unwrap();
            global_stats.update(&self.local_stats);
        }
    }
}
pub enum ScanResult {
    SeenWithMatches,
    SeenSansMatches,
    New(Vec<BlobMatch>),
}
impl<'a> Matcher<'a> {
    /// Create a new `Matcher` from the given `RulesDatabase`.
    ///
    /// If `global_stats` is provided, it will be updated with the local stats
    /// from this `Matcher` when it is dropped.
    pub fn new(
        rules_db: &'a RulesDatabase,
        scanner_pool: Arc<ScannerPool>,
        seen_blobs: &'a BlobIdMap<bool>,
        global_stats: Option<&'a Mutex<MatcherStats>>,
        enable_profiling: bool,
        shared_profiler: Option<Arc<ConcurrentRuleProfiler>>,
        extra_ignore_directives: &[String],
        disable_inline_ignores: bool,
    ) -> Result<Self> {
        // Changed: removed `with_capacity(16384)` so we don't pre-allocate a large Vec
        let raw_matches_scratch = Vec::new();
        let user_data = UserData { raw_matches_scratch, input_len: 0 };
        // let vs_scanner = vectorscan_rs::BlockScanner::new(&rules_db.vsdb)?;
        // pool is created once per scan run (see Scanner section below)
        let profiler = shared_profiler.or_else(|| {
            if enable_profiling {
                Some(Arc::new(ConcurrentRuleProfiler::new()))
            } else {
                None
            }
        });
        Ok(Matcher {
            scanner_pool,
            rules_db,
            local_stats: MatcherStats::default(),
            global_stats,
            seen_blobs,
            user_data,
            profiler,
            inline_ignore_config: if disable_inline_ignores {
                InlineIgnoreConfig::disabled()
            } else {
                InlineIgnoreConfig::new(extra_ignore_directives)
            },
        })
    }

    fn scan_bytes_raw(&mut self, input: &[u8], _filename: &str) -> Result<()> {
        // Remember previous peak automatically
        let prev_capacity = self.user_data.raw_matches_scratch.capacity();
        self.user_data.raw_matches_scratch.clear();
        self.user_data.raw_matches_scratch.reserve(prev_capacity.max(64));

        self.user_data.input_len = input.len() as u64;

        let mut offset: usize = 0;
        while offset < input.len() {
            let end = (offset + MAX_CHUNK_SIZE).min(input.len());
            let slice = &input[offset..end];
            let base = offset as u64;
            self.scanner_pool.with(|scanner| {
                scanner.scan(slice, |rule_id, from, to, _flags| {
                    self.user_data.raw_matches_scratch.push(RawMatch {
                        rule_id,
                        start_idx: from + base,
                        end_idx: to + base,
                    });
                    vectorscan_rs::Scan::Continue
                })
            })?;

            if end == input.len() {
                break;
            }
            offset = end.saturating_sub(CHUNK_OVERLAP);
        }

        Ok(())
    }

    // -------------------------------------------------------------------------------------
    // REFACTOR: `scan_blob` 签名不再有 'b 生命周期
    // -------------------------------------------------------------------------------------
    pub fn scan_blob(
        &mut self,
        blob: &Blob, // ★ 这是一个常规借用, 没有 'a 或 'b
        origin: &OriginSet,
        lang: Option<String>,
        redact: bool,
        no_dedup: bool,
        no_base64: bool,
    ) -> Result<ScanResult> {
        // Update local stats
        self.local_stats.blobs_seen += 1;
        self.local_stats.bytes_seen += blob.bytes().len() as u64;
        self.local_stats.blobs_scanned += 1;
        self.local_stats.bytes_scanned += blob.bytes().len() as u64;

        // Extract filename from origin
        let filename = origin
            .first()
            .blob_path()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .unwrap_or("unknown_file")
            .to_string();
        // Perform the scan
        self.scan_bytes_raw(blob.bytes(), &filename)?;

        // Opportunistically look for standalone Base64 blobs. If neither
        // the raw scan nor this check yields anything, we can return early
        // before doing any heavier work.
        let mut b64_items = if no_base64 || blob.len() > BASE64_SCAN_LIMIT {
            Vec::new()
        } else {
            get_base64_strings(blob.bytes())
        };

        let lang_hint = lang.as_deref();
        let has_raw_matches = !self.user_data.raw_matches_scratch.is_empty();
        let has_base64_items = !b64_items.is_empty();

        if !has_raw_matches && !has_base64_items {
            return Ok(ScanResult::New(Vec::new()));
        }

        let rules_db = self.rules_db;

        let blob_len = blob.len();

        let should_run_tree_sitter = blob_len > 0
            && (TREE_SITTER_MIN_LIMIT..=TREE_SITTER_MAX_LIMIT).contains(&blob_len)
            && has_raw_matches
            && lang_hint.is_some()
            && !no_base64; //tree-sitter parsing is turned off when base64 scanning is disabled

        let tree_sitter_result = if should_run_tree_sitter {
            lang_hint.and_then(|lang_str| {
                get_language_and_queries(lang_str).and_then(|(language, queries)| {
                    let checker = Checker { language, rules: queries };
                    match checker.check(blob.bytes()) {
                        Ok(results) => Some(results),
                        Err(e) => {
                            println!("Error in checker.check: {}", e);
                            None
                        }
                    }
                })
            })
        } else {
            None
        };
        // Process matches
        let owned_ts_results = tree_sitter_result.map(|ts_results| {
            ts_results
                .into_iter()
                .filter(|match_result| match_result.is_base64_decoded)
                .map(|match_result| {
                    (
                        match_result.range,
                        match_result.text,
                        match_result.is_base64_decoded,
                        match_result.original_base64,
                    )
                })
                .collect::<Vec<_>>()
        });

        // -------------------------------------------------------------------------------------
        // REFACTOR: 1. 设置管道
        // -------------------------------------------------------------------------------------

        // 最终的 `BlobMatch` 列表
        let mut final_matches: Vec<BlobMatch> = Vec::new();

        // 为所有过滤器设置可变状态
        let mut seen_matches = FxHashSet::default();
        let mut previous_matches: FxHashMap<usize, Vec<OffsetSpan>> = FxHashMap::default();
        let mut previous_raw_matches: FxHashMap<usize, Vec<OffsetSpan>> = FxHashMap::default();

        // ★ blob_bytes 借用了 blob，生命周期为 'local_blob
        let blob_bytes = blob.bytes();

        // 创建一次性的上下文
        let mut filter_context = FilterContext {
            blob_bytes,
            inline_ignore_config: &self.inline_ignore_config,
            seen_matches: &mut seen_matches,
            previous_matches: &mut previous_matches,
        };

        // ★ 这就是你的可组合管道！★
        // `ZeroCopyFilterFn` (使用 for<...>) 允许我们存储这些函数
        let filters: Vec<ZeroCopyFilterFn> = vec![
            Box::new(filter_entropy_and_safelist), // 阶段 1
            Box::new(filter_inline_ignore),        // 阶段 2 (零拷贝)
            Box::new(filter_overlap_dedup),        // 阶段 2 (零拷贝)
            Box::new(filter_hash_dedup),           // 阶段 2 (零拷贝, 内容感知)
                                                   // ★ 要添加新功能，只需： Box::new(my_new_filter_function), ★
        ];

        // -------------------------------------------------------------------------------------
        // REFACTOR: 2. 执行管道
        // -------------------------------------------------------------------------------------

        // --- 2a. 处理 Vectorscan (Raw) 匹配 ---
        for &RawMatch { rule_id, start_idx, end_idx } in
            self.user_data.raw_matches_scratch.iter().rev()
        {
            let rule_id_usize: usize = rule_id as usize;
            let rule = Arc::clone(&rules_db.rules[rule_id_usize]);
            let re = &rules_db.anchored_regexes[rule_id_usize];
            let start_idx_usize = start_idx as usize;
            let end_idx_usize = end_idx as usize;
            let current_span = OffsetSpan::from_range(start_idx_usize..end_idx_usize);
            if !record_match(&mut previous_raw_matches, rule_id_usize, current_span) {
                continue;
            }

            // ★ haystack 借用了 'local_blob 生命周期
            let haystack = &blob_bytes[start_idx_usize..end_idx_usize];
            process_captures_pipeline(
                blob.id(),
                rule,
                re,
                rule_id_usize,
                redact,
                haystack,
                start_idx_usize,
                false, // is_base64
                &filename,
                self.profiler.as_ref(),
                &mut final_matches,
                &mut filter_context,
                &filters,
            );
        }

        // --- 2b. 处理 Tree-Sitter 解码的匹配 ---
        // ★ owned_ts_results 拥有数据, 'haystack 将借用它
        if let Some(ref ts_results) = owned_ts_results {
            for (ts_range, ts_match, is_base64_decoded, _original_base64) in ts_results.iter() {
                if *is_base64_decoded {
                    for (rule_id_usize, rule) in rules_db.rules.iter().enumerate() {
                        let re = &rules_db.anchored_regexes[rule_id_usize];
                        process_captures_pipeline(
                            blob.id(),
                            rule.clone(),
                            re,
                            rule_id_usize,
                            redact,
                            ts_match.as_bytes(), // 'haystack 借用 ts_match
                            ts_range.start,
                            true, // is_base64
                            &filename,
                            self.profiler.as_ref(),
                            &mut final_matches,
                            &mut filter_context,
                            &filters,
                        );
                    }
                }
            }
        }

        // --- 2c. 处理独立 Base64 解码的匹配 ---
        // ★ b64_stack 拥有数据, 'haystack 将借用它
        if !no_base64 {
            const MAX_B64_DEPTH: usize = 2;
            let mut b64_stack: Vec<(DecodedData, usize)> =
                b64_items.drain(..).map(|d| (d, 0)).collect();
            while let Some((item, depth)) = b64_stack.pop() {
                for (rule_id_usize, rule) in rules_db.rules.iter().enumerate() {
                    let re = &rules_db.anchored_regexes[rule_id_usize];
                    process_captures_pipeline(
                        blob.id(),
                        rule.clone(),
                        re,
                        rule_id_usize,
                        redact,
                        item.decoded.as_bytes(), // 'haystack 借用 item.decoded
                        item.pos_start,
                        true, // is_base64
                        &filename,
                        self.profiler.as_ref(),
                        &mut final_matches,
                        &mut filter_context,
                        &filters,
                    );
                }
                if depth + 1 < MAX_B64_DEPTH {
                    for nested in get_base64_strings(item.decoded.as_bytes()) {
                        b64_stack.push((
                            DecodedData {
                                original: nested.original,
                                decoded: nested.decoded,
                                pos_start: item.pos_start,
                                pos_end: item.pos_end,
                            },
                            depth + 1,
                        ));
                    }
                }
            }
        }

        // -------------------------------------------------------------------------------------
        // REFACTOR: 3. 返回最终结果
        // -------------------------------------------------------------------------------------

        // Finalize
        if !no_dedup && !final_matches.is_empty() {
            let blob_id = blob.id();
            if let Some(had_matches) = self.seen_blobs.insert(blob_id, true) {
                return Ok(if had_matches {
                    ScanResult::SeenWithMatches
                } else {
                    ScanResult::SeenSansMatches
                });
            }
        }

        // --- opportunistic capacity cap ---------------------------------
        if self.user_data.raw_matches_scratch.capacity()
            > self.user_data.raw_matches_scratch.len() * 4
        {
            self.user_data.raw_matches_scratch.shrink_to_fit();
        }

        Ok(ScanResult::New(final_matches))
    }
}

#[inline]
fn compute_match_key(content: &[u8], rule_id: &[u8], start: usize, end: usize) -> u64 {
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
fn record_match(
    map: &mut FxHashMap<usize, Vec<OffsetSpan>>,
    rule_id: usize,
    span: OffsetSpan,
) -> bool {
    insert_span(map.entry(rule_id).or_default(), span)
}

// -------------------------------------------------------------------------------------------------
// REFACTOR: 阶段 1 & 2: 零拷贝管道执行
// -------------------------------------------------------------------------------------------------

/// 取代 filter_match。
/// 在 `captures_iter` 循环内部执行完整的零拷贝过滤管道。
/// 只有通过所有过滤的候选者才会被“提升”为 `BlobMatch`。
fn process_captures_pipeline<'a, 'ctx>(
    // --- 上下文 ---
    blob_id: BlobId,
    rule: Arc<Rule>,
    re: &'a Regex,
    rule_id_usize: usize,
    redact: bool,
    // --- 零拷贝数据 ---
    haystack: &'a [u8], // 'a 是 haystack 的生命周期
    haystack_start_in_blob: usize,
    is_base64: bool,
    // --- Profiling ---
    filename: &str,
    profiler: Option<&'ctx Arc<ConcurrentRuleProfiler>>, // 'ctx 是 Matcher 的 'a
    // --- 输出 ---
    matches: &mut Vec<BlobMatch>,
    // --- 状态 & 管道 ---
    filter_context: &mut FilterContext<'ctx>,
    filters: &[ZeroCopyFilterFn], // ★ 使用修正后的 type 别名
) {
    let mut timer =
        profiler.map(|p| RuleTimer::new(p, rule.id(), rule.name(), &rule.syntax.pattern, filename));

    let initial_len = matches.len();

    'capture_loop: for captures in re.captures_iter(haystack) {
        let full_capture = captures.get(0).unwrap();
        let matching_input = captures.get(1).unwrap_or(full_capture);
        let mi_bytes = matching_input.as_bytes(); // 零拷贝切片

        let calculated_entropy = calculate_shannon_entropy(mi_bytes);
        let finding_span_in_blob = OffsetSpan::from_range(
            (haystack_start_in_blob + matching_input.start())
                ..(haystack_start_in_blob + matching_input.end()),
        );

        // 创建临时的“轻量级候选者”
        let candidate = LightweightCandidate {
            finding_bytes: mi_bytes,
            full_capture_bytes: full_capture.as_bytes(),
            captures: &captures,
            haystack,
            re,
            rule: rule.clone(),
            rule_id_usize,
            blob_id,
            is_base64,
            redact,
            finding_span_in_blob,
            calculated_entropy,
        };

        // ★ 执行可组合的零拷贝管道 ★
        for filter in filters {
            if !filter(&candidate, filter_context) {
                continue 'capture_loop; // 任何一个过滤器失败，则丢弃
            }
        }

        // -----------------------------------------------------------------
        // REFACTOR: 阶段 3: 提升 (Promote)
        // -----------------------------------------------------------------
        // 只有通过所有过滤器的候选者才会到达这里。
        // 现在我们支付昂贵的拷贝代价。
        let final_match = promote_to_blob_match(&candidate);
        matches.push(final_match);
    }

    if let Some(t) = timer.take() {
        let new_count = (matches.len() - initial_len) as u64;
        t.end(new_count > 0, new_count, 0);
    }
}

// -------------------------------------------------------------------------------------------------
// REFACTOR: 阶段 3: 提升 (Promotion)
// -------------------------------------------------------------------------------------------------

/// 辅助函数：执行昂贵的拷贝操作，将零拷贝的候选者转换为拥有的 `BlobMatch`。
/// 这只在所有过滤器都通过后才被调用。
fn promote_to_blob_match(cand: &LightweightCandidate) -> BlobMatch {
    // 昂贵的操作 1: 拷贝 `finding_bytes`
    let owned_matching_input = cand.finding_bytes.to_vec();

    // 昂贵的操作 2: 创建 `SerializableCaptures`
    let groups =
        SerializableCaptures::from_captures(cand.captures, cand.haystack, cand.re, cand.redact);

    BlobMatch {
        rule: cand.rule.clone(),
        blob_id: cand.blob_id,
        matching_input: owned_matching_input,
        matching_input_offset_span: cand.finding_span_in_blob,
        captures: groups,
        validation_response_body: String::new(),
        validation_response_status: StatusCode::from_u16(0).unwrap_or(StatusCode::CONTINUE),
        validation_success: false,
        calculated_entropy: cand.calculated_entropy,
        is_base64: cand.is_base64,
    }
}

// -------------------------------------------------------------------------------------------------
// REFACTOR: 统一风格的过滤器函数 (零拷贝)
// -------------------------------------------------------------------------------------------------

/// 过滤器 (阶段 1): 检查熵和安全列表
#[inline]
fn filter_entropy_and_safelist(candidate: &LightweightCandidate, _ctx: &mut FilterContext) -> bool {
    if candidate.calculated_entropy <= candidate.rule.min_entropy() {
        debug!(
            "Skipping match with entropy {} <= {} or safe match",
            candidate.calculated_entropy,
            candidate.rule.min_entropy()
        );
        return false; // 丢弃
    }
    if is_safe_match(candidate.finding_bytes)
        || is_user_match(candidate.finding_bytes, candidate.full_capture_bytes)
    {
        debug!("Skipping match due to safe list or user match");
        return false; // 丢弃
    }
    true // 保留
}

/// 过滤器 (阶段 2): 检查行内忽略指令
#[inline]
fn filter_inline_ignore(candidate: &LightweightCandidate, ctx: &mut FilterContext) -> bool {
    if ctx.inline_ignore_config.should_ignore(ctx.blob_bytes, &candidate.finding_span_in_blob) {
        debug!("Skipping match due to inline ignore directive");
        false // 丢弃
    } else {
        true // 保留
    }
}

/// 过滤器 (阶段 2): 执行基于哈希的去重 (零拷贝)
#[inline]
fn filter_hash_dedup(candidate: &LightweightCandidate, ctx: &mut FilterContext) -> bool {
    let match_key = compute_match_key(
        candidate.finding_bytes, // ★ 在这里使用零拷贝的切片 ★
        candidate.rule.id().as_bytes(),
        candidate.finding_span_in_blob.start,
        candidate.finding_span_in_blob.end,
    );
    ctx.seen_matches.insert(match_key) // .insert() 返回 'true' 如果是新值
}

/// 过滤器 (阶段 2): 执行基于重叠 Span 的去重
#[inline]
fn filter_overlap_dedup(candidate: &LightweightCandidate, ctx: &mut FilterContext) -> bool {
    record_match(ctx.previous_matches, candidate.rule_id_usize, candidate.finding_span_in_blob)
    // record_match() 返回 'true' 如果是新 span
}

// -------------------------------------------------------------------------------------------------
// (以下函数保持不变)
// -------------------------------------------------------------------------------------------------

fn get_language_and_queries(lang: &str) -> Option<(Language, FxHashMap<String, String>)> {
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
// -------------------------------------------------------------------------------------------------
// MatchStats
// -------------------------------------------------------------------------------------------------
#[derive(Debug, Default, Clone)]
pub struct MatcherStats {
    pub blobs_seen: u64,
    pub blobs_scanned: u64,
    pub bytes_seen: u64,
    pub bytes_scanned: u64,
    // #[cfg(feature = "rule_profiling")]
    // pub rule_stats: crate::rule_profiling::RuleProfile,
}
impl MatcherStats {
    pub fn update(&mut self, other: &Self) {
        self.blobs_seen += other.blobs_seen;
        self.blobs_scanned += other.blobs_scanned;
        self.bytes_seen += other.bytes_seen;
        self.bytes_scanned += other.bytes_scanned;

        // #[cfg(feature = "rule_profiling")]
        // self.rule_stats.update(&other.rule_stats);
    }
}
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
// #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
// pub struct SerializableCapture {
//     pub name: Option<String>, // Named group (if available)
//     pub match_number: i32,
//     pub start: usize,  // Start position of the match
//     pub end: usize,    // End position of the match
//     pub value: String, // The actual captured value
// }
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
            location: Location { offset_span, source_span: source_span.clone() },
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
        let mut num = xxh3_64(&buffer);
        // Ensure the number is positive and within i64 range
        num &= 0x7FFF_FFFF_FFFF_FFFF; // Clear the sign bit to make it positive
                                      // Convert to string
        num.to_string()
    }
}
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

// -------------------------------------------------------------------------------------------------
// test
// -------------------------------------------------------------------------------------------------
#[cfg(test)]
mod test {
    use std::{collections::BTreeMap, path::PathBuf};

    use pretty_assertions::assert_eq;
    // ---------------------------------------------------------------------
    // proptest: raw-match dedup + entropy gate
    // ---------------------------------------------------------------------
    use proptest::prelude::*;

    use super::*;
    use crate::{
        blob::{Blob, BlobIdMap},
        origin::{Origin, OriginSet},
        rules::rule::{DependsOnRule, HttpRequest, HttpValidation, RuleSyntax, Validation},
    };

    proptest! {
        #[test]
        fn prop_no_dupes_and_entropy(
            // random ASCII up to 300 bytes
            mut noise in proptest::collection::vec(any::<u8>().prop_filter("ascii", |b| b.is_ascii()), 0..300),
            // 0-4 random insertion points
            inserts in proptest::collection::vec(0usize..300, 0..5)
        ) {
            // Constant high-entropy secret token that matches the rule below
            const TOKEN: &[u8] = b"secret_abcd1234";

            // Splice the token at the requested offsets
            for &idx in &inserts {
                let pos = idx.min(noise.len());
                noise.splice(pos..pos, TOKEN.iter().copied());
            }

            // ── build a single test rule ──────────────────────────────────
            use crate::rules::rule::{RuleSyntax, Validation, Confidence};

            let rule = Rule::new(RuleSyntax {
                id: "prop.secret".into(),
                name: "prop secret".into(),
                pattern: "secret_[a-z]{4}[0-9]{4}".into(),
                confidence: Confidence::Low,
                min_entropy: 3.0,
                visible: true,
                examples: vec![],
                negative_examples: vec![],
                references: vec![],
                validation: None::<Validation>,          // no HTTP validation needed
                depends_on_rule: vec![],
            });

            let rules_db  = RulesDatabase::from_rules(vec![rule]).unwrap();
            let seen      = BlobIdMap::new();
            let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vsdb.clone())));
            let mut m     = Matcher::new(
                &rules_db,
                scanner_pool,
                &seen,
                None,
                false,
                None,
                &[],
                false,
            )
            .unwrap();

            // ── run the scan ──────────────────────────────────────────────
            m.scan_bytes_raw(&noise, "buf").unwrap();

            // ── property 1: dedup – each (rule,start,end) is unique ──────

            let mut coords = FxHashSet::default();
            for RawMatch{rule_id, start_idx, end_idx} in &m.user_data.raw_matches_scratch {
                assert!(
                    coords.insert((*rule_id, *start_idx, *end_idx)),
                    "duplicate raw-match detected for coords ({rule_id},{start_idx},{end_idx})"
                );

                // ── property 2: entropy gate held ────────────────────────
                let slice = &noise[*start_idx as usize .. *end_idx as usize];
                let ent   = calculate_shannon_entropy(slice);
                assert!(ent > 3.0, "entropy {ent} ≤ min_entropy, gate failed");
            }
        }
    }

    #[test]
    pub fn test_simple() -> Result<()> {
        let rules = vec![Rule::new(RuleSyntax {
            id: "test.1".to_string(),
            name: "test".to_string(),
            pattern: "test".to_string(),
            confidence: crate::rules::rule::Confidence::Medium,
            min_entropy: 1.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: Some(Validation::Http(HttpValidation {
                request: HttpRequest {
                    method: "GET".to_string(),
                    url: "https://example.com".to_string(),
                    headers: BTreeMap::new(),
                    body: None,
                    response_matcher: Some(vec![]),
                    multipart: None,
                    response_is_html: false,
                },
                multipart: None,
            })),
            depends_on_rule: vec![
                Some(DependsOnRule {
                    rule_id: "d8f3c34b-015f-4cd6-b411-b1366493104c".to_string(),
                    variable: "email".to_string(),
                }),
                Some(DependsOnRule {
                    rule_id: "8910f364-7718-4a27-a435-d2da13e6ba9e".to_string(),
                    variable: "domain".to_string(),
                }),
            ],
        })];
        let rules_db = RulesDatabase::from_rules(rules)?;
        let input = "some test data for vectorscan";
        let seen_blobs: BlobIdMap<bool> = BlobIdMap::new();
        let enable_rule_profiling = true;
        // let mut matcher = Matcher::new(&rules_db, &seen_blobs, None,
        // enable_rule_profiling)?;
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vsdb.clone())));
        let mut matcher = Matcher::new(
            &rules_db,
            scanner_pool,
            &seen_blobs,
            None,
            enable_rule_profiling,
            None, // Pass the shared profiler
            &[],
            false,
        )?;
        matcher.scan_bytes_raw(input.as_bytes(), "fname")?;
        assert_eq!(
            matcher.user_data.raw_matches_scratch,
            vec![RawMatch { rule_id: 0, start_idx: 0, end_idx: 9 },]
        );
        Ok(())
    }

    // ---------------------------------------------------------------------
    // additional deterministic unit-tests
    // ---------------------------------------------------------------------

    /// `get_base64_strings` should recognise a well-formed token, decode it,
    /// and report correct byte-offsets.
    #[test]
    fn test_get_base64_strings_basic() {
        let raw = b"foo MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY= bar";
        // decodes to "0123456789abcdef0123456789abcdef"
        let hits = get_base64_strings(raw);
        assert_eq!(hits.len(), 1);
        let item = &hits[0];
        assert_eq!(item.decoded, "0123456789abcdef0123456789abcdef");
        assert_eq!(item.original, "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=");
        // "foo␠" is 4 bytes, so the start offset is 4
        assert_eq!((item.pos_start, item.pos_end), (4, 4 + item.original.len()));
    }

    /// `compute_finding_fingerprint` must be stable (same input ⇒ same output)
    /// and sensitive to any input component.
    #[test]
    fn test_finding_fingerprint_stability_and_uniqueness() {
        let a = compute_finding_fingerprint("secret", "fileA", 0, 6);
        let b = compute_finding_fingerprint("secret", "fileA", 0, 6);
        assert_eq!(a, b, "fingerprint should be deterministic");

        // changing any parameter should perturb the hash
        let c = compute_finding_fingerprint("secret", "fileA", 1, 7); // offsets differ
        let d = compute_finding_fingerprint("secret", "fileB", 0, 6); // file id differs
        let e = compute_finding_fingerprint("different", "fileA", 0, 6); // content differs
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(a, e);
    }

    /// The (private) `compute_match_key` helper is the linchpin of the raw-dedup
    /// path.  It should return identical keys for identical inputs and different
    /// keys as soon as *anything* changes.
    #[test]
    fn test_compute_match_key_uniqueness() {
        use super::compute_match_key;

        let k1 = compute_match_key(b"abc", b"rule-1", 0, 3);
        let k2 = compute_match_key(b"abc", b"rule-1", 0, 3);
        assert_eq!(k1, k2);

        // mutate each component in turn
        let diff_content = compute_match_key(b"abcd", b"rule-1", 0, 4);
        let diff_rule = compute_match_key(b"abc", b"rule-2", 0, 3);
        let diff_span = compute_match_key(b"abc", b"rule-1", 1, 4);
        assert_ne!(k1, diff_content);
        assert_ne!(k1, diff_rule);
        assert_ne!(k1, diff_span);
    }

    /// Running `scan_bytes_raw` twice over the *same* input should never record
    /// duplicate entries in `raw_matches_scratch`.
    #[test]
    fn test_scan_bytes_raw_no_duplicate_raw_matches() -> Result<()> {
        // simple rule: literal "dup"
        let rule = Rule::new(RuleSyntax {
            id: "dup.check".into(),
            name: "dup".into(),
            pattern: "dup".into(),
            confidence: crate::rules::rule::Confidence::Low,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            depends_on_rule: vec![],
        });

        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vsdb.clone())));
        let mut m = Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false)?;

        let buf = b"dup dup"; // two literal hits, same rule

        // first scan
        m.scan_bytes_raw(buf, "buf1")?;
        let first_len = m.user_data.raw_matches_scratch.len();

        // second scan over the same buffer
        m.scan_bytes_raw(buf, "buf1")?;
        let second_len = m.user_data.raw_matches_scratch.len();

        // we should still only have two unique raw matches recorded
        assert_eq!(first_len, 2);
        assert_eq!(second_len, 2);
        Ok(())
    }

    #[test]
    fn inline_comment_skips_match() -> Result<()> {
        let rule = Rule::new(RuleSyntax {
            id: "inline.ignore".into(),
            name: "inline".into(),
            pattern: "secret_token".into(),
            confidence: crate::rules::rule::Confidence::Low,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            depends_on_rule: vec![],
        });
        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vsdb.clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false)?;

        let blob = Blob::from_bytes(b"let key = \"secret_token\" # kingfisher:ignore".to_vec());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("inline.txt")));

        match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
            ScanResult::New(matches) => assert!(matches.is_empty()),
            _ => panic!("unexpected scan result"),
        }

        Ok(())
    }

    #[test]
    fn inline_comment_after_multiline_secret_skips_match() -> Result<()> {
        let rule = Rule::new(RuleSyntax {
            id: "inline.multiline".into(),
            name: "inline multiline".into(),
            pattern: "line1\\s+line2".into(),
            confidence: crate::rules::rule::Confidence::Low,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            depends_on_rule: vec![],
        });
        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vsdb.clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false)?;

        let blob = Blob::from_bytes(
            br#"let data = """
line1
line2
"""
# kingfisher:ignore
"#
            .to_vec(),
        );
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("multiline.txt")));

        match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
            ScanResult::New(matches) => assert!(matches.is_empty()),
            _ => panic!("unexpected scan result"),
        }

        Ok(())
    }

    #[test]
    fn compat_flag_controls_external_directives() -> Result<()> {
        let rule = Rule::new(RuleSyntax {
            id: "inline.compat".into(),
            name: "inline compat".into(),
            pattern: "supersecret123".into(),
            confidence: crate::rules::rule::Confidence::Low,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            depends_on_rule: vec![],
        });
        let rules_db = RulesDatabase::from_rules(vec![rule])?;

        let blob = Blob::from_bytes(b"token = \"supersecret123\" # gitleaks:allow".to_vec());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("compat.txt")));

        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vsdb.clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false)?;
        let matches_without_compat =
            match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
                ScanResult::New(matches) => matches.len(),
                _ => panic!("unexpected scan result"),
            };
        assert_eq!(matches_without_compat, 1, "directive should be ignored without compat flag");

        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vsdb.clone())));
        let extra = vec![String::from("gitleaks:allow")];
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &extra, false)?;
        match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
            ScanResult::New(matches) => assert!(matches.is_empty()),
            _ => panic!("unexpected scan result"),
        }

        Ok(())
    }
}
