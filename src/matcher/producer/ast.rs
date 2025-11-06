use rustc_hash::{FxHashMap, FxHashSet};
use tree_sitter::Node;

use crate::parser::Language;

mod bash;
mod python;

use bash::*;
use python::*;

pub enum SymbolValue {
    /// 基础值（图的“源节点”）
    /// e.g., a = "sk-..."
    StringLiteral(String),

    /// 依赖重定向（图的“指针边”）
    /// e.g., b = a
    Identifier(String), // 存储它所依赖的变量名

    /// 这是一个有序列表，代表所有需要按顺序拼接在一起的部分。
    /// e.g., a + b + c
    /// e.g., format!("{},{}", a, b)
    Join(Vec<SymbolValue>),

    /// 依赖“黑洞”（我们无法或不关心的值）
    /// e.g., num = 123  或  result = some_func()
    Other,
}

pub struct SymbolInfo {
    pub name: String,
    pub defined_at_offset: usize,
    pub value: SymbolValue,
}

// --- 你的“极限抽象”：AstLanguagePack ---

/// “微型解析器”的函数签名
type MicroParser = for<'a, 'b> fn(Node<'a>, &'b [u8], &AstLanguagePack) -> SymbolValue;

/// 包含“微型解析器”注册表的语言包
pub(crate) struct AstLanguagePack {
    pub(crate) assignment_query: &'static str,
    constructor_parsers: FxHashMap<&'static str, MicroParser>,
}

/// 辅助宏，用于轻松创建 FxHashMap
/// ★ 修正：移除 'a 生命周期
macro_rules! map {
    ( $($key:expr => $value:expr),* $(,)? ) => {
        {
            let mut m = FxHashMap::default();
            $(
                m.insert($key, $value as MicroParser);
            )*
            m
        }
    };
}

/// 注册表函数：动态获取语言包
pub(crate) fn get_ast_language_pack(language: Language) -> Option<AstLanguagePack> {
    match language {
        Language::Python => Some(AstLanguagePack {
            assignment_query: r#"
                (assignment
                  left: (identifier) @name
                  right: (_) @value)
            "#,
            constructor_parsers: map! {
                "binary_operator" => parse_python_binary_op,
                "string" => parse_python_string_or_fstring,
                "f_string" => parse_python_string_or_fstring,
                "identifier" => parse_python_identifier,
            },
        }),
        Language::Bash => Some(AstLanguagePack {
            // 查询 Bash 的变量赋值: VAR="value" 或 VAR=value
            assignment_query: r#"
                (variable_assignment
                  name: (variable_name) @name
                  value: (_) @value)
            "#,
            // 注册 Bash 的微型解析器
            constructor_parsers: map! {
                "string" => parse_bash_string,
                "concatenation" => parse_bash_concatenation,
                "expansion" => parse_bash_expansion,
                "simple_expansion" => parse_bash_expansion, // ★ 新增：处理 $var
                "variable_name" => parse_bash_variable_name,
            },
        }),
        _ => None,
    }
}

// --- 3. 通用分发器 (替换旧的 parse_expression) ---

/// 辅助函数：通用的“统一解析器”（分发器）
pub fn parse_expression_recursive<'a, 'b>(
    node: Node<'a>,
    source: &'b [u8],
    lang_pack: &AstLanguagePack,
) -> SymbolValue {
    if let Some(parser_func) = lang_pack.constructor_parsers.get(node.kind()) {
        parser_func(node, source, lang_pack)
    } else {
        SymbolValue::Other
    }
}

// 辅助函数：递归“图遍历”来解析最终的字符串
pub fn resolve_value(
    value_to_resolve: &SymbolValue,
    symbol_table: &FxHashMap<String, SymbolInfo>,
    visited: &mut FxHashSet<String>,
) -> Option<String> {
    match value_to_resolve {
        SymbolValue::StringLiteral(s) => Some(s.clone()),
        SymbolValue::Identifier(name) => {
            if !visited.insert(name.clone()) {
                return None;
            }
            let result = symbol_table
                .get(name)
                .and_then(|info| resolve_value(&info.value, symbol_table, visited));
            visited.remove(name);
            result
        }
        SymbolValue::Join(parts) => {
            let mut resolved_string = String::new();
            for part in parts {
                if let Some(part_str) = resolve_value(part, symbol_table, visited) {
                    resolved_string.push_str(&part_str);
                } else {
                    return None; // 链条中断
                }
            }
            Some(resolved_string)
        }

        SymbolValue::Other => None,
    }
}
