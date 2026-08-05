//! 引擎版本与 `min_engine` 语义比较。

/// 解析 `major.minor.patch`（多余后缀忽略）；失败返回 `None`。
pub fn parse_semver(s: &str) -> Option<(u32, u32, u32)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let core = s.split('-').next()?.split('+').next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().unwrap_or(0);
    let patch = parts.next().unwrap_or("0").parse().unwrap_or(0);
    Some((major, minor, patch))
}

/// `engine >= required`。
pub fn version_satisfies(engine: &str, required: &str) -> bool {
    let Some(req) = parse_semver(required) else {
        // 未写或无法解析 → 不强制
        return true;
    };
    let Some(eng) = parse_semver(engine) else {
        return false;
    };
    eng >= req
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmp() {
        assert!(version_satisfies("0.1.0", "0.1.0"));
        assert!(version_satisfies("0.2.0", "0.1.0"));
        assert!(!version_satisfies("0.1.0", "0.2.0"));
        assert!(version_satisfies("1.0.0", ""));
    }
}
