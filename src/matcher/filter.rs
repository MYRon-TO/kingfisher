use std::sync::Arc;

use regex::bytes::{Captures, Regex};
use rustc_hash::{FxHashMap, FxHashSet};
use tracing::debug;

use crate::{
    blob::{BlobId, BlobIdMap},
    entropy::calculate_shannon_entropy,
    inline_ignore::InlineIgnoreConfig,
    location::OffsetSpan,
    rule_profiling::{ConcurrentRuleProfiler, RuleTimer},
    rules::rule::Rule,
    safe_list::{is_safe_match, is_user_match},
};

use super::{
    captures::SerializableCaptures,
    match_structs::BlobMatch,
    util::{compute_match_key, record_match},
};

// -------------------------------------------------------------------------------------------------
// REFACTOR: 过滤管道 (Filtering Pipeline) 定义
// -------------------------------------------------------------------------------------------------

/// 一个临时的、零拷贝的匹配候选者，用于在过滤管道中高效传递。
///
/// `LightweightCandidate` 的核心设计理念是 **零拷贝 (zero-copy)**。
/// 它通过持有对原始数据（如 `Blob` 的字节内容或解码后的 Base64 字符串）的 **引用 (references/slices)**，
/// 而不是复制数据本身，来避免在过滤阶段产生不必要的内存分配和拷贝开销。
///
/// 只有当一个 `LightweightCandidate` 成功通过所有过滤规则后，它才会被“提升”（promote）
/// 为一个拥有自己数据的 `BlobMatch` 结构体。
///
/// 它的生命周期 `'a` 绑定到其引用的 `haystack` 的生命周期。
pub(crate) struct LightweightCandidate<'a> {
    // --- 零拷贝数据 (引用) ---
    /// **最关键的匹配内容**，通常是正则表达式的 **第一个捕获组 (group 1)**。
    ///
    /// 这代表着我们真正关心的“秘密”（secret）本身。如果第一个捕获组不存在，
    /// 它会回退到使用整个匹配（group 0）。它是计算熵、检查安全列表等操作的主要对象。
    /// `finding_bytes` 是 `haystack` 的一个子切片。
    pub(crate) finding_bytes: &'a [u8],

    /// 正则表达式的 **完整匹配内容 (group 0)**。
    ///
    /// 它提供了比 `finding_bytes` 更广泛的上下文，可用于需要查看秘密周围字符的场景
    /// （例如，在 `is_user_match` 中）。`full_capture_bytes` 也是 `haystack` 的一个子切片。
    pub(crate) full_capture_bytes: &'a [u8],

    /// `regex` 包返回的原始捕获组对象。
    ///
    /// 这是一个低级结构，包含了所有捕获组（包括命名和未命名的）的详细信息
    /// （如位置和内容），其本身也是对 `haystack` 的引用。
    pub(crate) captures: &'a Captures<'a>,

    /// **被正则表达式搜索的文本块**，即“干草堆”。
    ///
    /// 它是一个数据切片（slice），其内容可能是原始 `blob` 的一部分，
    /// 也可能是一个解码后的 Base64 字符串。`finding_bytes` 和 `full_capture_bytes`
    /// 都是 `haystack` 的子切片。
    pub(crate) haystack: &'a [u8],

    /// 指向用于查找此候选者的那个已编译的正则表达式的引用。
    pub(crate) re: &'a Regex,

    // --- 上下文 (廉价拷贝) ---
    /// 指向触发这次匹配的 `Rule` 对象的原子引用计数指针。
    ///
    /// 使用 `Arc` 可以在多个线程和结构体之间安全、廉价地共享规则的所有权。
    pub(crate) rule: Arc<Rule>,

    /// 规则的数字 ID。
    ///
    /// 在 `HashMap` 或 `Vec` 中用作键或索引，比使用字符串 ID 更高效。
    pub(crate) rule_id_usize: usize,

    /// 当前正在扫描的 `Blob` 的唯一标识符。这是一个可以廉价拷贝的类型。
    pub(crate) blob_id: BlobId,

    /// 一个布尔标志，如果 `haystack` 是从 Base64 字符串解码而来的，则为 `true`。
    pub(crate) is_base64: bool,

    /// 一个布尔标志，指示在最终报告中是否应将匹配值编辑或遮盖掉。
    pub(crate) redact: bool,

    // --- 预计算数据 ---
    /// `finding_bytes` 在 **整个原始 `Blob`** 中的绝对字节偏移范围（起始和结束位置）。
    ///
    /// 这对于后续的定位、去重和应用行内忽略规则（inline ignore）至关重要。
    pub(crate) finding_span_in_blob: OffsetSpan,

    /// 预先计算好的 `finding_bytes` 的香农熵。
    ///
    /// 由于熵计算相对耗时，预先计算可以避免在过滤管道的多个步骤中重复计算。
    pub(crate) calculated_entropy: f32,
}

/// 包含所有过滤器可能需要的上下文和可变状态。
/// 它的生命周期 'ctx 绑定到 `scan_blob` 的作用域。
pub(crate) struct FilterContext<'ctx> {
    /// 原始 Blob 的字节，用于 inline_ignore 等检查
    pub(crate) blob_bytes: &'ctx [u8],
    pub(crate) inline_ignore_config: &'ctx InlineIgnoreConfig,
    /// 可变的状态，用于有状态的过滤器
    pub(crate) seen_matches: &'ctx mut FxHashSet<u64>,
    pub(crate) previous_matches: &'ctx mut FxHashMap<usize, Vec<OffsetSpan>>,
}

/// “统一风格的函数”：一个可组合的、零拷贝的过滤器函数。
pub(crate) type ZeroCopyFilterFn =
    Box<dyn for<'a, 'ctx> Fn(&LightweightCandidate<'a>, &mut FilterContext<'ctx>) -> bool>;

// -------------------------------------------------------------------------------------------------
// REFACTOR: 阶段 1 & 2: 零拷贝管道执行
// -------------------------------------------------------------------------------------------------

/// 取代 filter_match。
/// 在 `captures_iter` 循环内部执行完整的零拷贝过滤管道。
/// 只有通过所有过滤的候选者才会被“提升”为 `BlobMatch`。
pub(crate) fn process_captures_pipeline<'a, 'ctx>(
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
    filters: &[ZeroCopyFilterFn],
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
        // REFACTOR: 阶段 3: 提升 (代价高昂)
        // -----------------------------------------------------------------
        let final_match = promote_to_blob_match(&candidate);
        matches.push(final_match);
    }

    if let Some(t) = timer.take() {
        let new_count = (matches.len() - initial_len) as u64;
        t.end(new_count > 0, new_count, 0);
    }
}

/// 将零拷贝的候选者转换为拥有的 `BlobMatch`。
/// 这只在所有过滤器都通过后才被调用。
fn promote_to_blob_match(cand: &LightweightCandidate) -> BlobMatch {
    // let owned_matching_input = cand.finding_bytes.to_vec();

    // WARNING: 非常昂贵的操作，优化重点
    let groups =
        SerializableCaptures::from_captures(cand.captures, cand.haystack, cand.re, cand.redact);

    BlobMatch {
        rule: cand.rule.clone(),
        blob_id: cand.blob_id,
        // matching_input: owned_matching_input,
        matching_input_offset_span: cand.finding_span_in_blob,
        captures: groups,
        validation_response_body: String::new(),
        validation_response_status: http::StatusCode::from_u16(0).unwrap_or(http::StatusCode::CONTINUE),
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
pub(crate) fn filter_entropy_and_safelist(
    candidate: &LightweightCandidate,
    _ctx: &mut FilterContext,
) -> bool {
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
pub(crate) fn filter_inline_ignore(candidate: &LightweightCandidate, ctx: &mut FilterContext) -> bool {
    if ctx
        .inline_ignore_config
        .should_ignore(ctx.blob_bytes, &candidate.finding_span_in_blob)
    {
        debug!("Skipping match due to inline ignore directive");
        false // 丢弃
    } else {
        true // 保留
    }
}

/// 过滤器 (阶段 2): 执行基于哈希的去重 (零拷贝)
#[inline]
pub(crate) fn filter_hash_dedup(candidate: &LightweightCandidate, ctx: &mut FilterContext) -> bool {
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
pub(crate) fn filter_overlap_dedup(candidate: &LightweightCandidate, ctx: &mut FilterContext) -> bool {
    record_match(
        ctx.previous_matches,
        candidate.rule_id_usize,
        candidate.finding_span_in_blob,
    )
    // record_match() 返回 'true' 如果是新 span
}
