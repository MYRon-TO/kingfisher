// 假设在子模块中，需要导入
use super::{parse_expression_recursive, AstLanguagePack, SymbolValue};
use rustc_hash::FxHashMap;
use std::iter::Peekable;
use std::str::Chars;
use tree_sitter::Node;

// --- 1g. “微型解析器” (特定于 PHP 的逻辑) ---

/// 微型解析器：处理 PHP 的 `(binary_expression)` 节点
/// e.g., $part_a . $part_b
/// (与 C#, Go, Python 的逻辑完全相同)
pub fn parse_php_binary_expression<'a, 'b>(
    node: Node<'a>,
    source: &'b [u8],
    lang_pack: &AstLanguagePack,
) -> SymbolValue {
    // 假设它是 `.` 运算符
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

/// 微型解析器：处理 PHP 的 `(encapsed_string)`
/// e.g., "hello" (简单字符串)
/// e.g., "hello $world" (插值字符串)
pub fn parse_php_string<'a, 'b>(
    node: Node<'a>,
    source: &'b [u8],
    lang_pack: &AstLanguagePack,
) -> SymbolValue {
    let mut parts = Vec::new();
    let mut has_interpolation = false;
    let mut cursor = node.walk();

    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "string_content" => {
                if let Ok(s) = child.utf8_text(source) {
                    parts.push(SymbolValue::StringLiteral(s.to_string()));
                }
            }
            // ★ 处理 "hello $world" 或 "hello {$world}"
            "variable_name" | "encapsed_variable" => {
                has_interpolation = true;
                parts.push(parse_expression_recursive(child, source, lang_pack));
            }
            _ => {}
        }
    }

    if !parts.is_empty() && has_interpolation {
        SymbolValue::Join(parts)
    } else {
        // 这是一个没有插值的简单字符串
        if let Ok(s) = node.utf8_text(source) {
            // 移除 PHP 的引号 "..." 或 '...'
            let s_val = s.trim_matches(|c| c == '"' || c == '\'');
            SymbolValue::StringLiteral(s_val.to_string())
        } else {
            SymbolValue::Other
        }
    }
}

/// 微型解析器：处理 PHP 的 `(variable_name)`
/// e.g., $part_a
pub fn parse_php_identifier<'a, 'b>(
    node: Node<'a>,
    source: &'b [u8],
    _lang_pack: &AstLanguagePack,
) -> SymbolValue {
    // (variable_name (name))
    if let Some(name_node) = node.named_child(0) {
        if name_node.kind() == "name" {
            if let Ok(name) = name_node.utf8_text(source) {
                // 返回 $part_a (包含 $ 符号)
                return SymbolValue::Identifier(format!("${}", name));
            }
        }
    }
    // 独立 $var
    if let Ok(name) = node.utf8_text(source) {
        SymbolValue::Identifier(name.to_string())
    } else {
        SymbolValue::Other
    }
}

/// 微型解析器：处理 PHP 的 `sprintf("...%s...", $var1)`
/// (与 Go/Java 的逻辑几乎相同)
pub fn parse_php_sprintf<'a, 'b>(
    node: Node<'a>, // (function_call_expression) 节点
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

pub fn extract_php_call_name<'a, 'b>(node: Node<'a>, source: &'b [u8]) -> Option<String> {
    // 预期 (function_call_expression) 节点
    // e.g., sprintf(...)
    let name_node = node.child_by_field_name("name")?;
    // (name (identifier "sprintf"))
    if name_node.kind() == "name" {
        if let Some(id_node) = name_node.named_child(0) {
            if id_node.kind() == "identifier" {
                return id_node.utf8_text(source).ok().map(|s| s.to_string());
            }
        }
    }
    None
}
