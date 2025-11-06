use std::str::FromStr;
use tree_sitter::StreamingIterator;

use rustc_hash::{FxHashMap, FxHashSet};
use tree_sitter::{Parser, Query, QueryCursor};

use crate::entropy::calculate_shannon_entropy;
use crate::matcher::producer::ast::{
    get_ast_language_pack, parse_expression_recursive, resolve_value, SymbolInfo,
};
use crate::parser::Language;
use crate::{blob::Blob, location::OffsetSpan, parser};

use super::util::record_match;
use super::{
    match_structs::RawMatch,
    util::{get_base64_strings, DecodedData},
    BASE64_SCAN_LIMIT,
};

mod ast;

// -------------------------------------------------------------------------------------------------
// REFACTOR: 生产者 (Producer) 抽象
// -------------------------------------------------------------------------------------------------

/// 生产者“生产”出的零拷贝 haystack。
/// 'a 是 haystack 切片所借用的数据的生命周期。
pub struct Haystack<'a> {
    /// 零拷贝的数据切片 (可能是原始 blob 的一部分，或解码后的字符串)。
    pub data: &'a [u8],
    /// `data` 在 *整个原始 Blob* 中的绝对起始字节偏移量。
    pub start_offset_in_blob: usize,
    /// 此数据是否来自 Base64 解码？
    pub is_base64: bool,
}

/// 生产者“生产”出的扫描目标。
/// 'a 的生命周期同上。
pub enum ScanTarget<'a> {
    /// 针对此 haystack 运行 *所有规则*。
    /// (用于 Tree-Sitter, Base64, 和未来的 Producer D, E, F)
    AllRules(Haystack<'a>),
    /// 仅针对此 haystack 运行 *特定规则*。
    /// (主要用于 Vectorscan 的 RawMatch)
    SpecificRule { haystack: Haystack<'a>, rule_id_usize: usize },
}

/// 传递给每个生产者的只读上下文。
/// 'ctx 生命周期绑定到 `scan_blob` 的局部变量。
pub struct ProducerContext<'ctx> {
    pub(crate) blob: &'ctx Blob,
    pub(crate) filename: &'ctx str,
    pub(crate) lang_hint: &'ctx Option<String>,
    /// Vectorscan 的原始匹配结果，供 RawScanProducer 使用。
    pub(crate) raw_matches: &'ctx [RawMatch],
    /// Tree-Sitter 的解析结果，供 TreeSitterProducer 使用。
    /// ★ 修正 #1：使用 'parser::MatchResult' ★
    pub(crate) tree_sitter_results: &'ctx Option<Vec<parser::MatchResult>>,
}

/// 任何“秘密发现机制”都必须实现的 Trait（零拷贝版本）
pub trait HaystackProducer: Send + Sync {
    /// 生产者的名字 (用于调试/日志)。
    fn name(&self) -> &'static str;

    /// 生产 haystacks 并 *立即* 将它们（作为切片）喂给消费者。
    /// ★ 修正 #3：简化 'produce' 签名 ★
    fn produce<'ctx>(
        &self,
        context: &'ctx ProducerContext<'ctx>,
        consumer: &mut dyn FnMut(ScanTarget<'_>),
    );
}

// --- 生产者 A: RawScanProducer ---
pub(crate) struct RawScanProducer;
impl HaystackProducer for RawScanProducer {
    fn name(&self) -> &'static str {
        "RawScan"
    }

    fn produce<'ctx>(
        &self,
        context: &'ctx ProducerContext<'ctx>,
        consumer: &mut dyn FnMut(ScanTarget<'_>),
    ) {
        let mut previous_raw_matches: FxHashMap<usize, Vec<OffsetSpan>> = FxHashMap::default();

        for &RawMatch { rule_id, start_idx, end_idx } in context.raw_matches.iter().rev() {
            let rule_id_usize: usize = rule_id as usize;
            let start_idx_usize = start_idx as usize;
            let end_idx_usize = end_idx as usize;

            // 在生产者内部进行 Vectorscan 级别的去重
            let current_span = OffsetSpan::from_range(start_idx_usize..end_idx_usize);
            if !record_match(&mut previous_raw_matches, rule_id_usize, current_span) {
                continue;
            }

            // ★ 零拷贝 ★：'data' 是 'context.blob' 的一个切片
            consumer(ScanTarget::SpecificRule {
                haystack: Haystack {
                    data: &context.blob.bytes()[start_idx_usize..end_idx_usize],
                    start_offset_in_blob: start_idx_usize,
                    is_base64: false,
                },
                rule_id_usize,
            });
        }
    }
}

// --- 生产者 B: TreeSitterProducer ---
pub(crate) struct TreeSitterProducer;
impl HaystackProducer for TreeSitterProducer {
    fn name(&self) -> &'static str {
        "TreeSitter"
    }

    fn produce<'ctx>(
        &self,
        context: &'ctx ProducerContext<'ctx>,
        consumer: &mut dyn FnMut(ScanTarget<'_>),
    ) {
        // ★ 修正 #1：使用 'context.tree_sitter_results' ★
        if let Some(ref ts_results) = context.tree_sitter_results {
            // ★ 修正 #1：迭代 'parser::MatchResult' ★
            for match_result in ts_results.iter() {
                if match_result.is_base64_decoded {
                    // ★ 零拷贝 ★：'data' 借用了 'match_result.text' (一个 String)
                    consumer(ScanTarget::AllRules(Haystack {
                        data: match_result.text.as_bytes(),
                        start_offset_in_blob: match_result.range.start,
                        is_base64: true,
                    }));
                }
            }
        }
    }
}

// --- 生产者 C: Base64Producer ---
pub(crate) struct Base64Producer {
    pub(crate) no_base64: bool, // 允许此生产者根据配置跳过
}
impl HaystackProducer for Base64Producer {
    fn name(&self) -> &'static str {
        "StandaloneBase64"
    }

    fn produce<'ctx>(
        &self,
        context: &'ctx ProducerContext<'ctx>,
        consumer: &mut dyn FnMut(ScanTarget<'_>),
    ) {
        // 根据配置或 Blob 大小跳过
        if self.no_base64 || context.blob.len() > BASE64_SCAN_LIMIT {
            return;
        }

        const MAX_B64_DEPTH: usize = 2;
        let b64_items = get_base64_strings(context.blob.bytes());
        let mut b64_stack: Vec<(DecodedData, usize)> =
            b64_items.into_iter().map(|d| (d, 0)).collect();

        while let Some((item, depth)) = b64_stack.pop() {
            // ★ 零拷贝 ★：'data' 借用了 'item.decoded' (一个 String)
            let haystack_slice = item.decoded.as_bytes();
            consumer(ScanTarget::AllRules(Haystack {
                data: haystack_slice,
                start_offset_in_blob: item.pos_start,
                is_base64: true,
            }));

            // 处理嵌套的 Base64
            if depth + 1 < MAX_B64_DEPTH {
                for nested in get_base64_strings(haystack_slice) {
                    b64_stack.push((
                        DecodedData {
                            original: nested.original,
                            decoded: nested.decoded,
                            pos_start: item.pos_start, // 偏移量保持为父级的
                            pos_end: item.pos_end,
                        },
                        depth + 1,
                    ));
                }
            }
        }
    }
}

// --- 生产者 D: ASTProducer ---
pub(crate) struct ASTProducer;
impl HaystackProducer for ASTProducer {
    fn name(&self) -> &'static str {
        "AST"
    }

    fn produce<'ctx>(
        &self,
        context: &'ctx ProducerContext<'ctx>,
        consumer: &mut dyn FnMut(ScanTarget<'_>),
    ) {
        // 1. 确定语言
        let Some(lang_str) = context.lang_hint.as_deref() else {
            return;
        };
        let Ok(language_enum) = Language::from_str(lang_str) else {
            return;
        };

        // --- ★ 逻辑顺序修复 ★ ---

        // 2. ★ (原 步骤 3) 先获取 ts_language (借用 language_enum)
        let Ok(ts_language) = language_enum.get_ts_language() else {
            return;
        };

        // 3. ★ (原 步骤 2) 再获取“分析包” (移动 language_enum)
        let Some(lang_pack) = get_ast_language_pack(language_enum) else {
            // 此语言不支持 AST 构造分析
            return;
        };

        // 4. 获取 AST 解析器
        let mut ts_parser = Parser::new();
        if ts_parser.set_language(&ts_language).is_err() {
            return;
        }

        // ★ 关键: `tree` 必须在 `source_bytes` 之前声明
        // 尽管 Rust 不强制，但这更清晰
        let Some(tree) = ts_parser.parse(context.blob.bytes(), None) else { return };
        let root_node = tree.root_node();
        let source_bytes = context.blob.bytes();

        // 5. 动态编译查询
        let Ok(assign_query) = Query::new(&ts_language, lang_pack.assignment_query) else {
            return; // 查询编译失败
        };

        // --- 阶段 1: 构建符号依赖图 (Symbol Table) ---

        let mut symbol_table: FxHashMap<String, SymbolInfo> = FxHashMap::default();
        let mut query_cursor = QueryCursor::new();

        let mut matches_iterator = query_cursor.matches(&assign_query, root_node, source_bytes);

        while let Some(m) = matches_iterator.next() {
            let mut name_node = None;
            let mut value_node = None;

            for capture in m.captures {
                let capture_name = assign_query.capture_names()[capture.index as usize];
                if capture_name == "name" {
                    name_node = Some(capture.node);
                } else if capture_name == "value" {
                    value_node = Some(capture.node);
                }
            }

            if let (Some(name_node), Some(value_node)) = (name_node, value_node) {
                if let Ok(name) = name_node.utf8_text(source_bytes) {
                    // ★ 现在 `parse_expression_recursive` 的生命周期解耦了 ★
                    // node(value_node) 的生命周期 ('tree) 和
                    // source(source_bytes) 的生命周期 ('ctx)
                    // 不再被强制要求相同。
                    let value = parse_expression_recursive(value_node, source_bytes, &lang_pack);

                    let info = SymbolInfo {
                        name: name.to_string(),
                        defined_at_offset: name_node.start_byte(),
                        value,
                    };
                    symbol_table.insert(name.to_string(), info);
                }
            }
        }

        // --- 阶段 2: 使用图（启发式推断）---
        // (此阶段完全不变)
        for symbol in symbol_table.values() {
            if is_suspicious_var_name(&symbol.name) {
                let mut visited = FxHashSet::default();
                if let Some(resolved_string) =
                    resolve_value(&symbol.value, &symbol_table, &mut visited)
                {
                    if resolved_string.len() > 10
                        && calculate_shannon_entropy(resolved_string.as_bytes()) > 3.0
                    {
                        consumer(ScanTarget::AllRules(Haystack {
                            data: resolved_string.as_bytes(),
                            start_offset_in_blob: symbol.defined_at_offset,
                            is_base64: false,
                        }));
                    }
                }
            }
        }
    }
}

/// TODO: 辅助函数：实现你的“额外状态”推断
fn is_suspicious_var_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    // 这是一个简单的启发式，可以扩展
    lower.contains("key")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("auth")
        || lower.contains("pass")
}
