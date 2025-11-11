use std::collections::HashSet;

// 核心敏感词汇集合
const CORE_SECRETS: &[&str] = &[
    // 核心凭证
    "secret",
    "password",
    "pwd",
    "token",
    "key",
    "credential",
    "cert",
    "private",
    "publickey",
    "privatekey",
    "passphrase",
    "apikey",
    "auth",
    // 连接与配置
    "connect",
    "conn",
    "db",
    "host",
    "username",
    "user",
    "serviceaccount",
    "config",
    "configfile",
    "endpoint",
    "uri",
    "url",
    // 平台/服务相关
    "aws",
    "azure",
    "gcp",
    "stripe",
    "github",
    "jwt",
    "bearer",
];

fn split_identifier(identifier: &str) -> Vec<String> {
    if identifier.is_empty() {
        return Vec::new();
    }

    // 1. 按下划线分割，并过滤空字符串
    let parts: Vec<&str> = identifier.split('_').filter(|p| !p.is_empty()).collect();
    let mut final_words = Vec::new();

    for part in parts {
        let mut current_word = String::new();
        let mut chars = part.chars().peekable();

        // 状态跟踪：用于处理 ALL_CAPS 和缩写序列 (如 HTTP)
        let mut prev_char_was_upper = false;
        let mut prev_char_was_digit = false;

        while let Some(current_char) = chars.next() {
            let current_is_upper = current_char.is_uppercase();
            let current_is_digit = current_char.is_digit(10);
            let next_char_is_lower = chars.peek().map_or(false, |&c| c.is_lowercase());

            // 检查是否应该开始一个新的单词 (即分割点)

            // 分割条件 A: 小写 -> 大写 (AppKey)
            let is_lower_to_upper =
                current_is_upper && !prev_char_was_upper && !current_word.is_empty();

            // 分割条件 B: 大写序列结束 (HTTPRequest -> HTTP | Request)
            // 当我们处于大写序列中，且下一个是小写时，我们需要分割 (但当前大写字母属于新单词)
            let is_upper_sequence_end =
                prev_char_was_upper && next_char_is_lower && !current_is_upper;

            // 分割条件 C: 数字边界 (V2Key)
            let is_digit_boundary =
                (current_is_digit != prev_char_was_digit) && !current_word.is_empty();

            if is_lower_to_upper || is_upper_sequence_end || is_digit_boundary {
                // 如果是 大写序列结束，则需要回退一个字符，让它成为新单词的开头
                // 为了简化逻辑，我们直接在 current_word 已经有内容时进行分割
                if !current_word.is_empty() {
                    // 对于 B 类分割，current_char 属于新单词。
                    // 为了简化，这里直接推入当前积累的单词。
                    // 对于 "HTTPRequest"，在 R 处分割。current_word=HTT，R是下一个字符。
                    // 修正：我们不使用复杂的 peek/pop，而是依赖于状态机：

                    // 如果是大写序列结束（例如从 T 到 R，R是下一个字符），
                    // 且当前字符是大写，但前一个也是大写，
                    // 并且下一个是小写，这表示我们到了缩写词的最后一个大写字母
                    if prev_char_was_upper && is_upper_sequence_end {
                        // 如果 current_word 有多个字符，说明我们正在处理缩写词。
                        // 将最后一个大写字母剥离出来，作为新词的开头。
                        let last_char = current_word.pop().unwrap();
                        final_words.push(current_word.to_ascii_lowercase());
                        current_word.clear();
                        current_word.push(last_char);
                    } else if is_lower_to_upper || is_digit_boundary {
                        // 正常的小写到大写，或数字边界
                        final_words.push(current_word.to_ascii_lowercase());
                        current_word.clear();
                    }
                }
            }

            // 确保当前字符被推入
            current_word.push(current_char);

            // 更新状态
            prev_char_was_upper = current_is_upper;
            prev_char_was_digit = current_is_digit;
        }

        if !current_word.is_empty() {
            final_words.push(current_word.to_ascii_lowercase());
        }
    }

    final_words
}

pub fn is_suspicious_var_name(identifier: &str) -> bool {
    if identifier.is_empty() {
        return false;
    }

    let split_words = split_identifier(identifier);
    let secret_set: HashSet<&str> = CORE_SECRETS.iter().copied().collect();

    for word in split_words {
        // 确保精确匹配
        if secret_set.contains(word.as_str()) {
            return true;
        }
    }

    false
}
