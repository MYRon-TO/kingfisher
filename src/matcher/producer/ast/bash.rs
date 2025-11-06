use tree_sitter::Node;

use crate::matcher::producer::ast::{parse_expression_recursive, AstLanguagePack, SymbolValue};

// --- 1b. “微型解析器” (特定于 Bash 的逻辑) ---
/// 微型解析器：处理 Bash 的 `(string)` 节点
/// e.g., "hello${WORLD}" 或 "hello$WORLD"
pub fn parse_bash_string<'a, 'b>(
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
            "expansion" | "command_substitution" | "simple_expansion" => {
                has_interpolation = true;
                parts.push(parse_expression_recursive(child, source, lang_pack));
            }
            _ => {}
        }
    }
    // 其余部分不变
    if !parts.is_empty() && has_interpolation {
        SymbolValue::Join(parts)
    } else if let Ok(s) = node.utf8_text(source) {
        SymbolValue::StringLiteral(s.trim_matches('"').to_string())
    } else {
        SymbolValue::Other
    }
}

/// 微型解析器：处理 Bash 的 `(concatenation)` 节点
/// e.g., VAR="hello""world"
pub fn parse_bash_concatenation<'a, 'b>(
    node: Node<'a>,
    source: &'b [u8],
    lang_pack: &AstLanguagePack,
) -> SymbolValue {
    let mut parts = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        // 递归解析每一个部分 (可能是 "string", "variable_name" 等)
        parts.push(parse_expression_recursive(child, source, lang_pack));
    }
    SymbolValue::Join(parts)
}

/// 微型解析器：处理 Bash 的 `(expansion)` 节点
/// e.g., ${WORLD}
pub fn parse_bash_expansion<'a, 'b>(
    node: Node<'a>,
    source: &'b [u8],
    lang_pack: &AstLanguagePack,
) -> SymbolValue {
    // 找到 `expansion` 节点内的 (variable_name)
    if let Some(var_node) = node.named_child(0) {
        if var_node.kind() == "variable_name" {
            // 递归调用（虽然我们知道它会匹配 "variable_name"，
            // 但这更符合抽象）
            return parse_expression_recursive(var_node, source, lang_pack);
        }
    }
    // 如果不是简单的 ${VAR}，比如 ${VAR:-default}，我们目前不处理
    SymbolValue::Other
}

/// 微型解析器：处理 Bash 的 `(variable_name)` 节点
/// e.g., $WORLD (当它独立作为值时)
pub fn parse_bash_variable_name<'a, 'b>(
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
