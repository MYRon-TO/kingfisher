pub mod captures;
pub mod filter;
pub mod match_structs;
pub mod producer;
pub mod stats;
pub mod util;

pub use self::captures::SerializableCaptures;
pub use self::match_structs::{BlobMatch, Match, OwnedBlobMatch};
pub use self::stats::MatcherStats;

use std::sync::{Arc, Mutex};

use anyhow::Result;

use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    blob::{Blob, BlobIdMap},
    inline_ignore::InlineIgnoreConfig,
    location::OffsetSpan,
    origin::OriginSet,
    parser::{self, Checker},
    rule_profiling::{ConcurrentRuleProfiler, RuleStats},
    rules_database::RulesDatabase,
    scanner_pool::ScannerPool,
};

use self::{
    filter::{
        filter_entropy_and_safelist, filter_hash_dedup, filter_inline_ignore, filter_overlap_dedup,
        process_captures_pipeline, FilterContext, ZeroCopyFilterFn,
    },
    match_structs::RawMatch,
    producer::{
        Base64Producer, HaystackProducer, ProducerContext, RawScanProducer, ScanTarget,
        TreeSitterProducer,
    },
    util::get_language_and_queries,
};

const MAX_CHUNK_SIZE: usize = 1 << 30; // 1 GiB per scan segment
const CHUNK_OVERLAP: usize = 64 * 1024; // 64 KiB overlap to catch boundary matches
const BASE64_SCAN_LIMIT: usize = 64 * 1024 * 1024; // skip expensive Base64 pass on huge blobs
const TREE_SITTER_MAX_LIMIT: usize = 64 * 1024; // only run tree-sitter on blobs <= 64 KiB
const TREE_SITTER_MIN_LIMIT: usize = 1 * 1024; // only run tree-sitter on blobs >= 1 KiB

#[derive(Clone)]
struct UserData {
    /// A scratch vector for raw matches from Vectorscan, to minimize allocation
    raw_matches_scratch: Vec<RawMatch>,

    /// The length of the input being scanned
    input_len: u64,
}

// -------------------------------------------------------------------------------------------------
// Matcher
// -------------------------------------------------------------------------------------------------
/// A `Matcher` is able to scan inputs for matches from rules in a
/// `RulesDatabase`.
///
/// If doing multi-threaded scanning, use a separate `Matcher` for each thread.
/// ★ 修正 #2：'Matcher' 仍然是 'Clone' 的 ★
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

    /// REFACTOR: 可插拔的、零拷贝的生产者列表
    /// ★ 修正 #2：使用 'Arc' 使 'producers' 字段可 'Clone' ★
    producers: Arc<Vec<Box<dyn HaystackProducer>>>,
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
        // REFACTOR: 允许在创建 Matcher 时配置生产者
        // （这里我们暂时硬编码，但未来可以传入一个 `Vec<Box<dyn HaystackProducer>>`）
        no_base64: bool, // 传入 no_base64 来配置 Base64Producer
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

        // REFACTOR: 初始化生产者列表
        // ★ 修正 #2：将生产者 'Vec' 包装在 'Arc' 中 ★
        let producers: Arc<Vec<Box<dyn HaystackProducer>>> = Arc::new(vec![
            Box::new(RawScanProducer),
            Box::new(TreeSitterProducer),
            Box::new(Base64Producer { no_base64 }),
            // ★ 添加新的生产者 D 就像这样简单：
            // Box::new(MyNewProducerD),
        ]);

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
            producers, // 添加生产者列表
        })
    }

    /// 运行 Vectorscan 来填充 `self.user_data.raw_matches_scratch`
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
    // REFACTOR: `scan_blob` 现在是“协调者”
    // -------------------------------------------------------------------------------------
    pub fn scan_blob(
        &mut self,
        blob: &Blob, // ★ 这是一个常规借用, 没有 'a 或 'b
        origin: &OriginSet,
        lang: Option<String>,
        redact: bool,
        no_dedup: bool,
        no_base64: bool, // 这个参数现在只用于 tree-sitter 检查
    ) -> Result<ScanResult> {
        // 更新本地统计
        self.local_stats.blobs_seen += 1;
        self.local_stats.bytes_seen += blob.bytes().len() as u64;
        self.local_stats.blobs_scanned += 1;
        self.local_stats.bytes_scanned += blob.bytes().len() as u64;

        // 从 origin 提取文件名
        let filename = origin
            .first()
            .blob_path()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .unwrap_or("unknown_file")
            .to_string();

        // ===================================================================================
        // 阶段 1: 准备生产者上下文 (Preparation)
        // ===================================================================================

        // 1a. 运行 Vectorscan (为 RawScanProducer 准备数据)
        // 这会填充 `self.user_data.raw_matches_scratch`
        self.scan_bytes_raw(blob.bytes(), &filename)?;
        let has_raw_matches = !self.user_data.raw_matches_scratch.is_empty();

        // 1b. 运行 Tree-Sitter (为 TreeSitterProducer 准备数据)
        let lang_hint = lang.as_deref();
        let blob_len = blob.len();
        let should_run_tree_sitter = blob_len > 0
            && (TREE_SITTER_MIN_LIMIT..=TREE_SITTER_MAX_LIMIT).contains(&blob_len)
            && has_raw_matches
            && lang_hint.is_some()
            && !no_base64; //tree-sitter parsing is turned off when base64 scanning is disabled

        // ★ 修正 #1：'tree_sitter_result' 现在是 'Option<Vec<parser::MatchResult>>' ★
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
        // (Base64Producer 不需要预先准备，它会在 'produce' 内部自己运行)

        // 1c. 创建生产者上下文
        // ★ 修正 #3：'producer_context' 借用了 'scan_blob' 栈上的变量 ★
        let producer_context = ProducerContext {
            blob,
            filename: &filename,
            lang_hint: &lang,
            raw_matches: &self.user_data.raw_matches_scratch,
            tree_sitter_results: &tree_sitter_result, // ★ 修正 #1
        };

        // ===================================================================================
        // 阶段 2: 准备过滤器和消费者 (Filter & Consumer Setup)
        // ===================================================================================

        // 最终的 `BlobMatch` 列表
        let mut final_matches: Vec<BlobMatch> = Vec::new();

        // 为所有过滤器设置可变状态
        let mut seen_matches = FxHashSet::default();
        let mut previous_matches: FxHashMap<usize, Vec<OffsetSpan>> = FxHashMap::default();

        // 创建一次性的过滤上下文
        let mut filter_context = FilterContext {
            blob_bytes: blob.bytes(),
            inline_ignore_config: &self.inline_ignore_config,
            seen_matches: &mut seen_matches,
            previous_matches: &mut previous_matches,
        };

        // ★ 这就是你的可组合管道！★
        let filters: Vec<ZeroCopyFilterFn> = vec![
            Box::new(filter_entropy_and_safelist), // 阶段 1
            Box::new(filter_inline_ignore),        // 阶段 2 (零拷贝)
            Box::new(filter_overlap_dedup),        // 阶段 2 (零拷贝)
            Box::new(filter_hash_dedup),           // 阶段 2 (零拷贝, 内容感知)
        ];

        // ===================================================================================
        // 阶段 3: 生产与消费 (Production & Consumption)
        // ===================================================================================

        // ★ 定义一个“消费者”闭包 ★
        // 它捕获了运行管道所需的所有状态。
        let mut consumer_closure = |target: ScanTarget<'_>| {
            match target {
                ScanTarget::SpecificRule { haystack, rule_id_usize } => {
                    let rule = Arc::clone(&self.rules_db.rules[rule_id_usize]);
                    let re = &self.rules_db.anchored_regexes[rule_id_usize];

                    process_captures_pipeline(
                        blob.id(),
                        rule,
                        re,
                        rule_id_usize,
                        redact,
                        haystack.data, // ★ 零拷贝切片
                        haystack.start_offset_in_blob,
                        haystack.is_base64,
                        &filename,
                        self.profiler.as_ref(),
                        &mut final_matches,
                        &mut filter_context,
                        &filters,
                    );
                }
                ScanTarget::AllRules(haystack) => {
                    for (rule_id_usize, rule) in self.rules_db.rules.iter().enumerate() {
                        let re = &self.rules_db.anchored_regexes[rule_id_usize];

                        process_captures_pipeline(
                            blob.id(),
                            rule.clone(),
                            re,
                            rule_id_usize,
                            redact,
                            haystack.data, // ★ 零拷贝切片
                            haystack.start_offset_in_blob,
                            haystack.is_base64,
                            &filename,
                            self.profiler.as_ref(),
                            &mut final_matches,
                            &mut filter_context,
                            &filters,
                        );
                    }
                }
            }
        };

        // ★ 运行所有生产者 ★
        // ★ 修正 #2：迭代 'self.producers.iter()' ★
        for producer in self.producers.iter() {
            producer.produce(&producer_context, &mut consumer_closure);
        }

        // ===================================================================================
        // 阶段 4: 清理 (Finalize)
        // ===================================================================================

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
    use crate::matcher::match_structs::{BlobMatch, Match, OwnedBlobMatch, RawMatch};
    use crate::rules::rule::Confidence;
    use crate::rules::RulesDatabase;
    use crate::scanner_pool::ScannerPool;
    use crate::{
        blob::{Blob, BlobIdMap},
        entropy::calculate_shannon_entropy,
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
                false
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
    use super::util::get_base64_strings;
    use crate::rules::rule::Rule;

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
        // "foo " is 4 bytes, so the start offset is 4
        assert_eq!((item.pos_start, item.pos_end), (4, 4 + item.original.len()));
    }

    /// `compute_finding_fingerprint` must be stable (same input ⇒ same output)
    /// and sensitive to any input component.
    #[test]
    fn test_finding_fingerprint_stability_and_uniqueness() {
        let a = util::compute_finding_fingerprint("secret", "fileA", 0, 6);
        let b = util::compute_finding_fingerprint("secret", "fileA", 0, 6);
        assert_eq!(a, b, "fingerprint should be deterministic");

        // changing any parameter should perturb the hash
        let c = util::compute_finding_fingerprint("secret", "fileA", 1, 7); // offsets differ
        let d = util::compute_finding_fingerprint("secret", "fileB", 0, 6); // file id differs
        let e = util::compute_finding_fingerprint("different", "fileA", 0, 6); // content differs
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(a, e);
    }

    /// The (private) `compute_match_key` helper is the linchpin of the raw-dedup
    /// path.  It should return identical keys for identical inputs and different
    /// keys as soon as *anything* changes.
    #[test]
    fn test_compute_match_key_uniqueness() {
        use super::util::compute_match_key;

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
        let mut m =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, false)?;

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
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, false)?;

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
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, false)?;

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
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, false)?;
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
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &extra, false, false)?;
        match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
            ScanResult::New(matches) => assert!(matches.is_empty()),
            _ => panic!("unexpected scan result"),
        }

        Ok(())
    }
}

