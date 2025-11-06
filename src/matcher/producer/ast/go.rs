use tree_sitter::Node;

use crate::matcher::producer::ast::{parse_expression_recursive, AstLanguagePack, SymbolValue};

/// 微型解析器：处理 Go 的 `(binary_expression)` 节点
pub fn parse_go_binary_expression<'a, 'b>(
    node: Node<'a>,
    source: &'b [u8],
    lang_pack: &AstLanguagePack,
) -> SymbolValue {
    // 假设它是 `+` 运算符。
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

/// 微型解析器：处理 Go 的 `(interpreted_string_literal)` 和 `(raw_string_literal)`
/// e.g., "hello" 或 `hello`
pub fn parse_go_string_literal<'a, 'b>(
    node: Node<'a>,
    source: &'b [u8],
    _lang_pack: &AstLanguagePack,
) -> SymbolValue {
    if let Ok(s) = node.utf8_text(source) {
        // 移除 Go 的引号 "..." 或 `...`
        let s_val = s.trim_matches(|c| c == '"' || c == '`');
        SymbolValue::StringLiteral(s_val.to_string())
    } else {
        SymbolValue::Other
    }
}

/// 微型解析器：处理 Go 的 `(identifier)`
pub fn parse_go_identifier<'a, 'b>(
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

pub fn parse_go_sprintf<'a, 'b>(
    node: Node<'a>, // (call_expression) 节点
    source: &'b [u8],
    lang_pack: &AstLanguagePack,
) -> SymbolValue {
    let Some(arg_list) = node.child_by_field_name("arguments") else {
        return SymbolValue::Other;
    };
    let mut arg_cursor = arg_list.walk();
    let mut args = arg_list.named_children(&mut arg_cursor).peekable();

    // 1. 获取格式化字符串
    let Some(format_string_node) = args.next() else {
        return SymbolValue::Other;
    };

    // 2. 尝试将格式化字符串解析为字面量
    let format_string_val = parse_expression_recursive(format_string_node, source, lang_pack);
    let SymbolValue::StringLiteral(format_string) = format_string_val else {
        // 如果格式化字符串本身是一个变量 (e.g., fmt.Sprintf(var, ...))
        // 那么分析过于复杂，我们放弃
        return SymbolValue::Other;
    };

    // 3. 解析格式化字符串，并将其与参数 zip 起来
    let mut parts = Vec::new();
    let mut current_literal = String::new();
    let mut chars = format_string.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.peek() {
                Some('s') => {
                    // 找到了 %s
                    chars.next(); // 消耗 's'
                                  // 将累积的字面量推入
                    if !current_literal.is_empty() {
                        parts.push(SymbolValue::StringLiteral(current_literal));
                        current_literal = String::new();
                    }
                    // 推入参数
                    if let Some(arg_node) = args.next() {
                        parts.push(parse_expression_recursive(arg_node, source, lang_pack));
                    } else {
                        // 参数数量与 %s 不匹配，分析失败
                        return SymbolValue::Other;
                    }
                }
                Some('%') => {
                    // 找到了 %% (转义)
                    chars.next(); // 消耗 '%'
                    current_literal.push('%');
                }
                _ => {
                    // 其他占位符 (e.g., %d, %v)，我们不处理
                    current_literal.push(c);
                }
            }
        } else {
            current_literal.push(c);
        }
    }

    // 4. 推入最后一个字面量
    if !current_literal.is_empty() {
        parts.push(SymbolValue::StringLiteral(current_literal));
    }

    SymbolValue::Join(parts)
}

pub fn extract_go_call_name<'a, 'b>(node: Node<'a>, source: &'b [u8]) -> Option<String> {
    let func_node = node.child_by_field_name("function")?;
    match func_node.kind() {
        // e.g., myFunc()
        "identifier" => func_node.utf8_text(source).ok().map(|s| s.to_string()),
        // e.g., fmt.Sprintf()
        "selector_expression" => {
            let pkg = func_node.child_by_field_name("operand").and_then(|n| n.utf8_text(source).ok());
            let field = func_node.child_by_field_name("field").and_then(|n| n.utf8_text(source).ok());
            if let (Some(pkg_name), Some(field_name)) = (pkg, field) {
                Some(format!("{}.{}", pkg_name, field_name))
            } else {
                None
            }
        }
        _ => None,
    }
}
