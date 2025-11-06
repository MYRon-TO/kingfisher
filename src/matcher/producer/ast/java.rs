/* [ast.rs 或 ast/java_parser.rs] */

use super::{parse_expression_recursive, AstLanguagePack, SymbolValue}; // 假设在子模块中
use rustc_hash::FxHashMap;
use std::iter::Peekable;
use std::str::Chars;
use tree_sitter::Node;

// --- 1f. “微型解析器” (特定于 Java 的逻辑) ---

/// 微型解析器：处理 Java 的 `(binary_expression)` 节点
/// e.g., part_a + part_b
/// (基于你提供的 AST，它有 left 和 right 字段)
pub fn parse_java_binary_expression<'a, 'b>(
    node: Node<'a>,
    source: &'b [u8],
    lang_pack: &AstLanguagePack,
) -> SymbolValue {
    if let (Some(left), Some(right)) =
        (node.child_by_field_name("left"), node.child_by_field_name("right"))
    {
        let left_val = parse_expression_recursive(left, source, lang_pack);
        let right_val = parse_expression_recursive(right, source, lang_pack);

        // 扁平化 Join
        let mut parts = Vec::new();
        match left_val {
            SymbolValue::Join(mut p) => parts.append(&mut p),
            _ => parts.push(left_val),
        }
        match right_val {
            SymbolValue::Join(mut p) => parts.append(&mut p),
            _ => parts.push(right_val),
        }
        SymbolValue::Join(parts)
    } else {
        SymbolValue::Other
    }
}

/// 微型解析器：处理 Java 的 `(string_literal)`
/// e.g., "hello"
pub fn parse_java_string_literal<'a, 'b>(
    node: Node<'a>,
    source: &'b [u8],
    _lang_pack: &AstLanguagePack,
) -> SymbolValue {
    if let Ok(s) = node.utf8_text(source) {
        // 移除 Java 的引号 "..."
        let s_val = s.trim_matches('"');
        SymbolValue::StringLiteral(s_val.to_string())
    } else {
        SymbolValue::Other
    }
}

/// 微型解析器：处理 Java 的 `(identifier)`
pub fn parse_java_identifier<'a, 'b>(
    node: Node<'a>,
    source: &'b [u8],
    _lang_pack: &AstLanguagePack,
) -> SymbolValue {
    if let Ok(name) = node.utf8_text(source) {
        SymbolValue::Identifier(name.to_string())
    } else {
        SymbolValue::Other
    }
}

/// 微型解析器：处理 Java 的 String.format("...%s...", var1, var2)
/// (与 Go 的 Sprintf 逻辑几乎相同)
pub fn parse_java_string_format<'a, 'b>(
    node: Node<'a>, // (method_invocation) 节点
    source: &'b [u8],
    lang_pack: &AstLanguagePack,
) -> SymbolValue {
    let Some(arg_list) = node.child_by_field_name("arguments") else {
        return SymbolValue::Other;
    };
    let mut arg_cursor = arg_list.walk();
    let mut args = arg_list.named_children(&mut arg_cursor).peekable();

    let Some(format_string_node) = args.next() else {
        return SymbolValue::Other;
    };
    let SymbolValue::StringLiteral(format_string) =
        parse_expression_recursive(format_string_node, source, lang_pack)
    else {
        return SymbolValue::Other; // 格式化字符串是变量，放弃
    };

    let mut parts = Vec::new();
    let mut current_literal = String::new();
    let mut chars = format_string.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.peek() {
                Some('s') => {
                    // 找到了 %s
                    chars.next(); // 消耗 's'
                    if !current_literal.is_empty() {
                        parts.push(SymbolValue::StringLiteral(current_literal));
                        current_literal = String::new();
                    }
                    if let Some(arg_node) = args.next() {
                        parts.push(parse_expression_recursive(arg_node, source, lang_pack));
                    } else {
                        return SymbolValue::Other; // 参数数量不匹配
                    }
                }
                Some('%') => {
                    // 找到了 %%
                    chars.next(); // 消耗 '%'
                    current_literal.push('%');
                }
                _ => {
                    current_literal.push(c);
                }
            }
        } else {
            current_literal.push(c);
        }
    }
    if !current_literal.is_empty() {
        parts.push(SymbolValue::StringLiteral(current_literal));
    }
    SymbolValue::Join(parts)
}

pub fn extract_java_call_name<'a, 'b>(node: Node<'a>, source: &'b [u8]) -> Option<String> {
    // 预期 (method_invocation) 节点
    let object_node = node.child_by_field_name("object");
    let name_node = node.child_by_field_name("name");

    if let (Some(obj), Some(name)) = (object_node, name_node) {
        if obj.kind() == "identifier" && name.kind() == "identifier" {
            if let (Ok(obj_str), Ok(name_str)) = (obj.utf8_text(source), name.utf8_text(source)) {
                // 返回 "String.format"
                return Some(format!("{}.{}", obj_str, name_str));
            }
        }
    }
    None
}
