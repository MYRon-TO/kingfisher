use tree_sitter::Node;

use crate::matcher::producer::ast::{AstLanguagePack, SymbolValue, parse_expression_recursive};

/// 微型解析器：处理 Python 的 `+` 运算符
/// ★ 修正：解耦生命周期 'a 和 'b
pub fn parse_python_binary_op<'a, 'b>(
    node: Node<'a>,
    source: &'b [u8],
    lang_pack: &AstLanguagePack, // lang_pack 现在是 'static
) -> SymbolValue {
    if node.child_by_field_name("operator").is_some_and(|n| n.kind() == "+") {
        let left = node.child_by_field_name("left").unwrap();
        let right = node.child_by_field_name("right").unwrap();

        // ★ 递归调用 *通用* 解析器
        let left_val = parse_expression_recursive(left, source, lang_pack);
        let right_val = parse_expression_recursive(right, source, lang_pack);

        // ... (扁平化 Join 的逻辑不变) ...
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

/// 微型解析器：处理 Python 的 "string" 和 "f_string" 节点
/// ★ 修正：解耦生命周期 'a 和 'b
pub fn parse_python_string_or_fstring<'a, 'b>(
    node: Node<'a>,
    source: &'b [u8],
    lang_pack: &AstLanguagePack, // lang_pack 现在是 'static
) -> SymbolValue {
    let mut has_interpolation = false;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "interpolation" {
            has_interpolation = true;
            break;
        }
    }

    if has_interpolation {
        // --- f-string 逻辑 ---
        let mut parts = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "string_content" => {
                    if let Ok(s) = child.utf8_text(source) {
                        parts.push(SymbolValue::StringLiteral(s.to_string()));
                    }
                }
                "interpolation" => {
                    if let Some(expr) = child.named_child(0) {
                        // ★ 递归调用 *通用* 解析器
                        parts.push(parse_expression_recursive(expr, source, lang_pack));
                    }
                }
                _ => {}
            }
        }
        SymbolValue::Join(parts)
    } else {
        // --- 简单字符串逻辑 ---
        if let Ok(s) = node.utf8_text(source) {
            let s_val = s
                .trim_start_matches(|c: char| c.is_alphabetic())
                .trim_matches(|c| c == '\'' || c == '"');
            SymbolValue::StringLiteral(s_val.to_string())
        } else {
            SymbolValue::Other
        }
    }
}

/// 微型解析器：处理 Python 的 "identifier"
/// ★ 修正：解耦生命周期 'a 和 'b
pub fn parse_python_identifier<'a, 'b>(
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

