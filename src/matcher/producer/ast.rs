use rustc_hash::{FxHashMap, FxHashSet};
use tree_sitter::Node;

use crate::parser::Language;

mod bash;
mod go;
mod java;
mod php;
mod python;

use bash::*;
use go::*;
use java::*;
use php::*;
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

/// ★ 新增：“调用名称提取器”的函数签名
/// 它知道如何从 (call_expression) 节点中提取函数名 (e.g., "fmt.Sprintf")
type CallNameExtractor = for<'a, 'b> fn(Node<'a>, &'b [u8]) -> Option<String>;
/// 包含“微型解析器”注册表的语言包
pub(crate) struct AstLanguagePack {
    pub(crate) assignment_query: &'static str,
    constructor_parsers: FxHashMap<&'static str, MicroParser>,
    call_parsers: FxHashMap<&'static str, MicroParser>,
    call_name_extractor: CallNameExtractor,
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
            call_parsers: FxHashMap::default(),
            call_name_extractor: extract_no_calls,
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
            call_parsers: FxHashMap::default(),
            call_name_extractor: extract_no_calls,
        }),
        Language::Go => Some(AstLanguagePack {
            // Go 的赋值查询：
            // 1. (var_spec name: ... value: (expression_list (_)))
            // 2. (short_var_declaration left: (identifier) right: (expression_list (_)))
            //    (我们添加 short_var_declaration 以提高覆盖率)
            assignment_query: r#"
                [
                  (var_spec
                    name: (identifier) @name
                    value: (expression_list
                      (_) @value
                    )
                  )
                  (short_var_declaration
                    left: (expression_list
                      (identifier) @name
                    )
                    right: (expression_list
                      (_) @value
                    )
                  )
                ]
            "#,
            // 注册 Go 的微型解析器
            constructor_parsers: map! {
                "binary_expression" => parse_go_binary_expression,
                "interpreted_string_literal" => parse_go_string_literal,
                "raw_string_literal" => parse_go_string_literal,
                "identifier" => parse_go_identifier,
                "call_expression" => parse_generic_call_expression,
            },
            call_parsers: map! {
                "fmt.Sprintf" => parse_go_sprintf,
            },
            call_name_extractor: extract_go_call_name,
        }),
        Language::Java => Some(AstLanguagePack {
            // ★ 修正：基于你提供的 AST 重写查询
            assignment_query: r#"
                [
                  (local_variable_declaration
                    declarator: (variable_declarator
                      name: (identifier) @name
                      value: (_) @value
                    )
                  )
                  (assignment_expression
                    left: (identifier) @name
                    right: (_) @value
                  )
                ]
            "#,
            // 注册 Java 的 L1 解析器
            constructor_parsers: map! {
                "binary_expression" => parse_java_binary_expression,
                "string_literal" => parse_java_string_literal,
                "identifier" => parse_java_identifier,
                "method_invocation" => parse_generic_call_expression, // 注册 L2 分发器
            },
            // 注册 Java 的 L2 解析器
            call_parsers: map! {
                "String.format" => parse_java_string_format,
            },
            // 注册 Java 的 L2 名称提取器
            call_name_extractor: extract_java_call_name,
        }),
        Language::Php => Some(AstLanguagePack {
            // ★ 基于你的 AST
            assignment_query: r#"
                (assignment_expression
                  left: (variable_name) @name
                  right: (_) @value)
            "#,
            // 注册 PHP 的 L1 解析器
            constructor_parsers: map! {
                "binary_expression" => parse_php_binary_expression, // . 拼接
                "encapsed_string" => parse_php_string,         // "hello" 或 "hello $world"
                "variable_name" => parse_php_identifier,       // $other_key
                "function_call_expression" => parse_generic_call_expression, // sprintf
            },
            // 注册 PHP 的 L2 解析器
            call_parsers: map! {
                "sprintf" => parse_php_sprintf,
            },
            // 注册 PHP 的 L2 名称提取器
            call_name_extractor: extract_php_call_name,
        }),

        // Language::Perl => Some(AstLanguagePack {
        //     // ★ 基于你的 AST
        //     assignment_query: r#"
        //         (assignment_expression
        //           left: (scalar) @name
        //           right: (_) @value)
        //     "#,
        //     // 注册 Perl 的 L1 解析器
        //     constructor_parsers: map! {
        //         "binary_expression" => parse_perl_binary_expression, // . 拼接
        //         "interpolated_string_literal" => parse_perl_string_literal, // "hello" 或 "hello $world"
        //         "scalar" => parse_perl_identifier, // $other_key
        //         "call_expression" => parse_generic_call_expression, // sprintf
        //     },
        //     // 注册 Perl 的 L2 解析器
        //     call_parsers: map! {
        //         "sprintf" => parse_perl_sprintf,
        //     },
        //     // 注册 Perl 的 L2 名称提取器
        //     call_name_extractor: extract_perl_call_name,
        // }),
        //
        _ => None,
    }
}

// --- 3. 通用分发器 (替换旧的 parse_expression) ---

// 这是一个“分发器的分发器”
pub fn parse_generic_call_expression<'a, 'b>(
    node: Node<'a>, // (call_expression) 节点
    source: &'b [u8],
    lang_pack: &AstLanguagePack,
) -> SymbolValue {
    // 1. ★ 抽象：使用“名称提取器”获取函数名
    let Some(func_name) = (lang_pack.call_name_extractor)(node, source) else {
        return SymbolValue::Other; // 无法提取函数名
    };

    // println!("函数名：{func_name}");

    // 2. ★ 通用：在 L2 注册表中查找
    if let Some(parser_func) = lang_pack.call_parsers.get(func_name.as_str()) {
        // 3. 找到了！委托给 L3 解析器 (e.g., parse_go_sprintf)
        return parser_func(node, source, lang_pack);
    }

    // 未注册的函数调用
    SymbolValue::Other
}

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

fn extract_no_calls<'a, 'b>(_node: Node<'a>, _source: &'b [u8]) -> Option<String> {
    None
}
