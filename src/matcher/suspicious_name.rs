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

    // 先按下滑线分割
    let parts: Vec<&str> = identifier.split('_').collect();
    let mut final_words = Vec::new();

    for part in parts {
        if part.is_empty() {
            continue;
        }

        // 处理驼峰命名：在大小写边界处分割
        let mut current_word = String::new();
        let mut chars = part.chars().peekable();

        while let Some(current_char) = chars.next() {
            current_word.push(current_char.to_ascii_lowercase());

            // 检查下一个字符是否是大写（驼峰边界）
            if let Some(&next_char) = chars.peek() {
                if next_char.is_uppercase() {
                    final_words.push(current_word.clone());
                    current_word.clear();
                }
            }
        }

        if !current_word.is_empty() {
            final_words.push(current_word);
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
        for &secret in &secret_set {
            // 核心检测逻辑：如果敏感词是词汇的子串，或者词汇是敏感词的子串
            if word.contains(secret) || secret.contains(&word) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_identifiers() {
        assert!(is_suspicious_var_name("apiKey"));
        assert!(is_suspicious_var_name("secret_token"));
        assert!(is_suspicious_var_name("dbPassword"));
        assert!(is_suspicious_var_name("aws_credential"));
        assert!(is_suspicious_var_name("connectionString"));
        assert!(is_suspicious_var_name("jwtToken"));
    }

    #[test]
    fn test_safe_identifiers() {
        assert!(!is_suspicious_var_name("username"));
        assert!(!is_suspicious_var_name("database"));
        assert!(!is_suspicious_var_name("apiEndpoint"));
        assert!(!is_suspicious_var_name("normal_var"));
        assert!(!is_suspicious_var_name(""));
    }
}
