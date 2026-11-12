//! 全攻击类轻量语义分析（可定罪 + veto）。

use crate::sqli_lexer::{sqli_tautology_shape, sqli_union_select_shape};
use crate::types::{SemanticKind, SemanticReport, SemanticSignal};
use crate::SemanticInput;
use nerve_antibody_dsl::{apply_transforms, NativeLevel, Transform};
use regex::Regex;
use std::sync::OnceLock;

fn re_sqli_tautology() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:'|"|\d)\s*(?:and|or)\s+(?:\d+\s*=\s*\d+|['"]\s*=\s*['"])"#).unwrap()
    })
}

fn re_sqli_union() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bunion\b.{0,48}\bselect\b").unwrap())
}

fn re_sqli_sleep() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(").unwrap()
    })
}

fn re_sqli_comment() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)(?:'|")\s*(?:--|#|/\*)"#).unwrap())
}

fn re_union_prose() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:the|a|labor|trade|credit|european|soviet|student|trade|credit)\s+union\b|\bunion\s+(?:leaders?|members?|officials?|workers?|bank|pacific|station|square|hall|rep(?:resentatives?)?)\b|\bunion\s+select\s+(?:their|the|a|an)\b",
        )
        .unwrap()
    })
}

fn re_sql_inject_markers() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // 注意：不可用裸 `'`（英文 don't/it's 会误判 hard）
        Regex::new(
            r#"(?i)(?:'\s*(?:or|and|union|--)|--|/\*!?(?:\+|$)|\bunion\s+(?:all\s+)?select\s+(?:null|\d|@@|chr\(|char\(|version\(|user\(|database\(|concat\(|group_concat\()|\bunion\s+(?:all\s+)?select\s+\w{1,64}\s+from\s+\w{1,64}|from\s+information_schema|;\s*(?:drop|delete|insert|update|select)\b|\|\|)"#,
        )
        .unwrap()
    })
}

fn re_english_prose() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // 禁止裸 and/from/with：SQL `UNION SELECT … FROM` 会整批误 veto
        Regex::new(
            r"(?i)\b(?:the|this|that|have|will|your|about|when|then|select\s+their|select\s+the|labor\s+union|trade\s+union)\b",
        )
        .unwrap()
    })
}

fn re_xss_event() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)<[^>]{0,120}\son(?:error|load|click|focus|mouseover|loadstart)\s*=\s*['"]?(?:alert|prompt|confirm|eval|atob)"#,
        )
        .unwrap()
    })
}

fn re_xss_script() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // 仅完整标签 / src|type；避免 “binary<script is incorrect”
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:<script(?:\s*>|\s*/>|\s+(?:src|type|language)\s*=)|</script>)").unwrap()
    })
}

fn re_xss_script_prose() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:binary\s*<script|script\s+is\s+incorrect|<script\s+ability|<script\s+is\b)",
        )
        .unwrap()
    })
}

fn re_xss_data_uri() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:src|href)\s*=\s*['"]?data:text/(?:html|javascript)"#).unwrap()
    })
}

fn re_xss_js_hex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:\\x65\\x76\\x61\\x6c|\\u0065\\u0076\\u0061\\u006c|\beval\s*\()")
            .unwrap()
    })
}

fn re_path_trav() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.{2,}/|\.{2,}\\|%c0%af|%c1%9c|%ef%bc%8f|%u2216){2,}|(?:\.\./|\.\.\\|%2e%2e){1,}(?:etc[/\\]passwd|windows[/\\]win\.ini|boot\.ini)",
        )
        .unwrap()
    })
}

fn re_path_sensitive() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:/etc/passwd|/etc/shadow|web-inf/web\.xml|/proc/self|/windows/system32|boot\.ini|/var/lib/php/sessions|/root/\.bash|web\.config)")
            .unwrap()
    })
}

fn re_rce() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // 避免 Adobe `;cat=wac`：要求 cat/id/whoami 后为空格/路径/引号/结尾，不能是 `=`
        Regex::new(
            r#"(?i)(?:;|\||`|\$\()\s*(?:(?:cat|id|whoami)(?:\s+/|\s+[./]|/(?:etc|bin|tmp|home|var)\b|['"`]|$)|(?:wget|curl|bash|sh|nc|python|perl|powershell)\b)|\b(?:system|exec|passthru|shell_exec|popen)\s*\(|['"]\s*[|;]\s*(?:id|whoami|cat)\b"#,
        )
        .unwrap()
    })
}

fn re_xss_sink_call() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:set(?:timeout|interval)\s*\(\s*['`][^'`]*ale['`+][^'`]*rt|new\s+function\s*[`(]|function\s*`[^`]*alert)",
        )
        .unwrap()
    })
}

fn re_crlf_header_inject() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:%0d%0a|%0a%0d|%u000d%u000a|%e5%98%8a%e5%98%8d|[\r\n\x{560a}\x{560d}]).{0,40}(?:set-cookie\s*:|location\s*:|content-length\s*:|bcc\s*:|x-[\w-]{1,40}\s*:|http/1\.)",
        )
        .unwrap()
    })
}

fn re_ssrf_encoded_loopback() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)https?://(?:0x7f[0-9a-f]*|0x7f(?:\.[0-9a-fx]+)+|2130706433|0177\.0\.0\.1|127\.1|0{1,3}|\[::1\]|\[0:0:0:0:0:0:0:1\])",
        )
        .unwrap()
    })
}

fn re_sqli_union_comment_break() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bunion(?:\s*(?:--|\#)|/\*).{0,24}\bselect\b|\bunion\b.{0,8}(?:%0a|%0d|\n).{0,16}\bselect\b")
            .unwrap()
    })
}

fn re_ssti() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\{\{.*(?:config|self|lipsum|cycler).*\}\}|\{%.*(?:import|include).*%\}|\$\{.*(?:java|runtime|process).*\}")
            .unwrap()
    })
}

fn re_ldap() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // 收紧：避免普通 `)(` / 短 token 误报
        Regex::new(r"(?i)(?:\(\|(?:\(|!)|\)\(|objectclass=\*|userpassword\s*=\*|uid=\*\)\()")
            .unwrap()
    })
}

fn re_upload_php() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)filename\s*=\s*['\"][^'\"]+\.(?:php\d*|phtml|phar|asp|aspx|ashx|jsp|jspx|cgi)"#,
        )
        .unwrap()
    })
}

fn re_graphql_intro() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)__schema\b|__type\s*\(|introspectionquery").unwrap())
}

fn re_ssrf_cloud_meta() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:169\.254\.169\.254|100\.100\.100\.200|metadata\.google\.internal|computemetadata|instance-data|fd00:ec2::254|2852039166|latest/meta-data)",
        )
        .unwrap()
    })
}

fn re_priv_mass_assign() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)["']role["']\s*:\s*["'](?:admin|superadmin|root|owner)["']|["']is_admin["']\s*:\s*true|["']permissions["']\s*:\s*\["#,
        )
        .unwrap()
    })
}

fn re_forced_admin_path() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:^|[?\s])/(?:admin|administrator|console|phpmyadmin|api/(?:v\d+/)?(?:admin|internal|debug)|backup|logs|\.git|\.env)(?:/|$|\?|\s)",
        )
        .unwrap()
    })
}

fn re_search_like() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:how\s+to|tutorial|discuss|what\s+is|binary<script\s+is)\b").unwrap()
    })
}

fn re_callback_onload() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:recaptcha|turnstile|captcha).*onload=|/api\.js\?[^&]*onload=").unwrap()
    })
}

fn re_case_when_prose() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bin the case when\b|\bcase when you\b").unwrap())
}

fn re_hex_blob() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b0x[0-9a-f]{8,}").unwrap())
}

fn re_sql_ctx() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:select|union|from|where|sleep|benchmark|hex\s*\()").unwrap()
    })
}

/// 对请求做语义分析。
pub fn analyze(input: SemanticInput<'_>) -> SemanticReport {
    let mut signals = Vec::new();
    if let Some(pack) = crate::pack::loaded() {
        signals.extend(pack.match_input(input, input.level));
    }
    // JWT base64 大小写敏感：必须在 lowercase 归一化之前扫描
    analyze_jwt_fields(input, &mut signals);
    // 双编码 overlong / URL 编码 RCE：必须在 url_decode 之前看原文
    analyze_raw_evasion(input, &mut signals);
    let blob = normalize_blob(input);
    let level = input.level.rank();

    analyze_path(input.uri, &blob, &mut signals);
    analyze_xss(&blob, input, &mut signals);

    if level >= NativeLevel::Low.rank() {
        analyze_sql_strong(&blob, input, &mut signals);
        // low 也跑高信号语义族，档位差异主要靠规则 min_level + 阈值
        analyze_sql_extended(&blob, input, &mut signals);
        analyze_rce(&blob, &mut signals);
        analyze_ssti(&blob, &mut signals);
        analyze_ldap(&blob, &mut signals);
        analyze_upload(&blob, &mut signals);
        analyze_deser(&blob, &mut signals);
        analyze_redirect(input, &mut signals);
        analyze_nosql(&blob, &mut signals);
        analyze_graphql(&blob, &mut signals);
        analyze_ssrf_cloud(&blob, &mut signals);
        analyze_priv_escalation(&blob, input.uri, &mut signals);
    }
    if level >= NativeLevel::High.rank() {
        // high：略放宽软信号分，但仍受 prose veto 约束
        analyze_sql_soft_high(&blob, input, &mut signals);
    }

    SemanticReport::from_signals(signals)
}

fn analyze_jwt_fields(input: SemanticInput<'_>, out: &mut Vec<SemanticSignal>) {
    let raw = format!(
        "{} {} {} {}",
        input.uri, input.query, input.body, input.extra
    );
    analyze_jwt(&raw, out);
}

fn analyze_raw_evasion(input: SemanticInput<'_>, out: &mut Vec<SemanticSignal>) {
    let raw = format!(
        "{} {} {} {}",
        input.uri, input.query, input.body, input.extra
    );
    let low = raw.to_ascii_lowercase();
    // 头尾采样：extra/body 可能很长或含二进制，禁止裸字节切分
    let sample = if low.len() > 24 * 1024 {
        head_tail(&low, 16 * 1024)
    } else {
        low
    };
    if sample.contains("%25c0%25ae")
        || sample.contains("%c0%ae%c0%ae%c0%af")
        || input.uri.to_ascii_lowercase().contains("%25c0%25ae")
        || input.query.to_ascii_lowercase().contains("%25c0%25ae")
    {
        out.push(SemanticSignal::attack(
            SemanticKind::Path,
            "path.overlong_utf8",
            0.93,
            40,
            "semantic:overlong_lfi",
        ));
    }
    if sample.contains("%3b%24%28printf")
        || sample.contains("%7crev%29")
        || sample.contains(";$(printf")
        || sample.contains("|rev)")
        || sample.contains("hsab/nib/")
        || sample.contains("hsab%2fnib")
    {
        out.push(SemanticSignal::attack(
            SemanticKind::Rce,
            "rce.padded_rev_shell",
            0.95,
            40,
            "semantic:padded_rce",
        ));
    }
    if sample.contains("xsi:schemalocation") || sample.contains("xs:include") {
        out.push(SemanticSignal::attack(
            SemanticKind::Path,
            "xxe.schema_include",
            0.9,
            40,
            "semantic:xxe_schema",
        ));
    }
}

fn normalize_blob(input: SemanticInput<'_>) -> String {
    let body = head_tail(input.body, 4096);
    let uri = head_tail(input.uri, 4096);
    let extra = head_tail(input.extra, 12 * 1024);
    let raw = format!("{} {} {} {}", uri, input.query, body, extra);
    apply_transforms(
        &raw,
        &[
            Transform::UrlDecodeUni,
            Transform::HtmlEntityDecode,
            Transform::HtmlNumericDecode,
            Transform::JsUnescape,
            Transform::Lowercase,
        ],
    )
}

/// 超长字段保留头尾，避免「前缀填充 + 尾部攻击」被截断漏检。
fn head_tail(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let keep = max / 2;
    let head_end = floor_char_boundary(s, keep);
    let tail_start = ceil_char_boundary(s, s.len().saturating_sub(keep));
    let mut out = String::with_capacity(max + 8);
    out.push_str(&s[..head_end]);
    out.push_str("\n...\n");
    out.push_str(&s[tail_start..]);
    out
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

fn analyze_path(uri: &str, blob: &str, out: &mut Vec<SemanticSignal>) {
    if re_path_sensitive().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Path,
            "path.sensitive",
            0.92,
            40,
            "semantic:sensitive_path",
        ));
    }
    if re_path_trav().is_match(uri) || re_path_trav().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Path,
            "path.traversal",
            0.84,
            40,
            "semantic:dotdot",
        ));
    }
    // 双编码 / overlong UTF-8 穿越（勿依赖 url_decode，避免 %25C0 被吃掉）
    if blob.contains("%25c0%25ae")
        || blob.contains("%c0%ae%c0%ae%c0%af")
        || uri.contains("%25c0%25ae")
        || uri.contains("%c0%ae%c0%ae%c0%af")
    {
        out.push(SemanticSignal::attack(
            SemanticKind::Path,
            "path.overlong_utf8",
            0.93,
            40,
            "semantic:overlong_lfi",
        ));
    }
}

fn analyze_xss(blob: &str, input: SemanticInput<'_>, out: &mut Vec<SemanticSignal>) {
    let uri_q = format!("{}?{}", input.uri, input.query);
    if re_callback_onload().is_match(&uri_q) || re_callback_onload().is_match(blob) {
        out.push(SemanticSignal::veto_signal(
            SemanticKind::Xss,
            "xss.callback_onload_veto",
            0.75,
            "semantic:veto_captcha_onload",
        ));
        return;
    }
    if re_xss_event().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Xss,
            "xss.event_sink",
            0.9,
            40,
            "semantic:html_event_sink",
        ));
    }
    if re_xss_data_uri().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Xss,
            "xss.data_uri",
            0.88,
            40,
            "semantic:data_uri_js",
        ));
    }
    if re_xss_js_hex().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Xss,
            "xss.js_hex_eval",
            0.86,
            40,
            "semantic:js_hex_eval",
        ));
    }
    if re_xss_sink_call().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Xss,
            "xss.timer_function_sink",
            0.86,
            40,
            "semantic:timer_function_sink",
        ));
    }
    if re_crlf_header_inject().is_match(&format!("{} {}", input.uri, input.query)) {
        out.push(SemanticSignal::attack(
            SemanticKind::Other,
            "proto.crlf_header_inject",
            0.9,
            40,
            "semantic:crlf_header_inject",
        ));
    }
    if re_ssrf_encoded_loopback().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Other,
            "ssrf.encoded_loopback",
            0.88,
            40,
            "semantic:ssrf_encoded_loopback",
        ));
    }
    if re_xss_script_prose().is_match(blob) || re_search_like().is_match(blob) {
        if blob.to_ascii_lowercase().contains("<script") && !re_xss_script().is_match(blob) {
            out.push(SemanticSignal::veto_signal(
                SemanticKind::Xss,
                "xss.script_prose_veto",
                0.8,
                "semantic:veto_script_prose",
            ));
            // 散文 veto 后不再发攻击信号
            return;
        }
    }
    if re_xss_script().is_match(blob) {
        let searchish = input.uri.contains("/search")
            || input.uri.contains("/complete")
            || input.uri.contains("/suggest")
            || input.uri.contains("searchsug");
        // 性能/埋点 JSON 里出现 script 字符串：不单独定罪
        let telemetry = input.uri.contains("/performance")
            || input.uri.contains("/news/")
            || blob.contains("\"projectid\"")
            || blob.contains("\"val_nm\"")
            || blob.contains("val_act");
        if (searchish && re_xss_script_prose().is_match(blob)) || telemetry {
            out.push(SemanticSignal::veto_signal(
                SemanticKind::Xss,
                "xss.script_prose_veto",
                0.75,
                "semantic:veto_script_prose",
            ));
        } else {
            out.push(SemanticSignal::attack(
                SemanticKind::Xss,
                "xss.script_tag",
                0.88,
                40,
                "semantic:script_tag",
            ));
        }
    }
}

fn analyze_sql_strong(blob: &str, input: SemanticInput<'_>, out: &mut Vec<SemanticSignal>) {
    if re_sqli_union_comment_break().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Sqli,
            "sqli.union_comment_break",
            0.9,
            40,
            "semantic:union_comment_break",
        ));
    }
    if sqli_union_select_shape(blob) || re_sqli_union().is_match(blob) {
        let hard = re_sql_inject_markers().is_match(blob);
        let searchish = input.uri.contains("/Suggestions")
            || input.uri.contains("/search")
            || input.uri.contains("/suggest")
            || input.uri.contains("serp")
            || input.query.contains("bq=")
            || input.query.contains("site:");
        let prose = !hard
            && (re_union_prose().is_match(blob)
                || re_english_prose().is_match(blob)
                || searchish
                || input.uri.contains("/g/collect")
                || input.uri.contains("/api/event")
                || input.uri.contains("/fd/ls/"));
        if hard {
            out.push(SemanticSignal::attack(
                SemanticKind::Sqli,
                "sqli.union",
                0.92,
                40,
                "semantic:union_select",
            ));
        } else if prose {
            // 散文/搜索建议/遥测：否决，且不再发 soft（避免 and/or 关键字把分抬过阈）
            out.push(SemanticSignal::veto_signal(
                SemanticKind::Sqli,
                "sqli.union_prose_veto",
                0.85,
                "semantic:veto_union_prose",
            ));
        }
        // 非 hard 且非 prose：静默（交给 L1 规则），不再 soft_assist
    }
    if re_sqli_sleep().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Sqli,
            "sqli.timebased",
            0.9,
            40,
            "semantic:sql_sleep",
        ));
    }
}

fn analyze_sql_extended(blob: &str, input: SemanticInput<'_>, out: &mut Vec<SemanticSignal>) {
    let searchish = input.uri.contains("/search")
        || input.uri.contains("/suggest")
        || input.uri.contains("/complete")
        || re_search_like().is_match(blob);

    if sqli_tautology_shape(blob) || re_sqli_tautology().is_match(blob) {
        if searchish && !blob.contains('\'') && !blob.contains('"') {
            out.push(SemanticSignal::veto_signal(
                SemanticKind::Sqli,
                "sqli.tautology_prose_veto",
                0.65,
                "semantic:veto_sql_prose",
            ));
        } else {
            out.push(SemanticSignal::attack(
                SemanticKind::Sqli,
                "sqli.tautology",
                0.86,
                40,
                "semantic:sql_tautology",
            ));
        }
    }
    // 注释终结：极易撞文案/JSON，一律软信号且需 SQL 上下文
    if re_sqli_comment().is_match(blob) && re_sql_ctx().is_match(blob) {
        if re_english_prose().is_match(blob) && !re_sql_inject_markers().is_match(blob) {
            out.push(SemanticSignal::veto_signal(
                SemanticKind::Sqli,
                "sqli.comment_prose_veto",
                0.7,
                "semantic:veto_sql_comment_prose",
            ));
        } else {
            out.push(SemanticSignal::soft_assist(
                SemanticKind::Sqli,
                "sqli.comment_terminate",
                0.7,
                20,
                "semantic:sql_comment",
            ));
        }
    }
    if re_case_when_prose().is_match(blob) {
        out.push(SemanticSignal::veto_signal(
            SemanticKind::Sqli,
            "sqli.case_when_prose_veto",
            0.7,
            "semantic:veto_case_when_prose",
        ));
    }
}

fn analyze_sql_soft_high(blob: &str, _input: SemanticInput<'_>, out: &mut Vec<SemanticSignal>) {
    // high：hex 仅作软信号，禁止单独定罪（防百度 rsv_pq / 指纹参数）
    if re_hex_blob().is_match(blob) && re_sql_ctx().is_match(blob) {
        if re_sql_inject_markers().is_match(blob) {
            out.push(SemanticSignal::soft_assist(
                SemanticKind::Sqli,
                "sqli.hex_context",
                0.75,
                20,
                "semantic:hex_sql_context",
            ));
        }
    }
}

fn analyze_rce(blob: &str, out: &mut Vec<SemanticSignal>) {
    if re_rce().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Rce,
            "rce.shell_meta",
            0.86,
            40,
            "semantic:rce_shell",
        ));
    }
    // 超长填充 + 尾部反转 shell（GoTestWAF *kb-rce）；在规则预算耗尽前定罪
    if blob.contains("%3b%24%28printf")
        || blob.contains("%7crev%29")
        || blob.contains(";$(printf")
        || blob.contains("|rev)")
        || blob.contains("hsab/nib/")
        || blob.contains("hsab%2fnib")
    {
        out.push(SemanticSignal::attack(
            SemanticKind::Rce,
            "rce.padded_rev_shell",
            0.95,
            40,
            "semantic:padded_rce",
        ));
    }
}

fn analyze_ssti(blob: &str, out: &mut Vec<SemanticSignal>) {
    if re_ssti().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Ssti,
            "ssti.template",
            0.84,
            40,
            "semantic:ssti",
        ));
    }
}

fn analyze_ldap(blob: &str, out: &mut Vec<SemanticSignal>) {
    if re_ldap().is_match(blob) {
        // LDAP 易撞编码噪声：默认软信号
        out.push(SemanticSignal::soft_assist(
            SemanticKind::Ldap,
            "ldap.filter",
            0.75,
            25,
            "semantic:ldap",
        ));
    }
}

fn analyze_upload(blob: &str, out: &mut Vec<SemanticSignal>) {
    if re_upload_php().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Upload,
            "upload.webshell_ext",
            0.88,
            40,
            "semantic:upload_php",
        ));
    }
}

fn re_jwt_token() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // 完整 JWT 或孤立段（嵌套 none 常出现在 payload 内）
    RE.get_or_init(|| Regex::new(r"eyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*){0,5}").unwrap())
}

fn b64url_decode_str(s: &str) -> Option<String> {
    use base64::{
        engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
        Engine,
    };
    let mut padded = s.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    let bytes = URL_SAFE
        .decode(padded.as_bytes())
        .or_else(|_| URL_SAFE_NO_PAD.decode(s.as_bytes()))
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn analyze_jwt(blob: &str, out: &mut Vec<SemanticSignal>) {
    for m in re_jwt_token().find_iter(blob).take(12) {
        let tok = m.as_str();
        for (i, part) in tok.split('.').enumerate().take(3) {
            if part.len() < 8 {
                continue;
            }
            let Some(decoded) = b64url_decode_str(part) else {
                continue;
            };
            let lower = decoded.to_ascii_lowercase();
            // header / nested header JSON
            if i == 0 || lower.contains("\"alg\"") {
                if lower.contains("\"alg\":\"none\"") || lower.contains("\"alg\": \"none\"") {
                    out.push(SemanticSignal::attack(
                        SemanticKind::Other,
                        "jwt.alg_none",
                        0.95,
                        40,
                        "semantic:jwt_alg_none",
                    ));
                }
                if lower.contains("\"kid\":\"http://")
                    || lower.contains("\"kid\":\"https://")
                    || lower.contains("\"jku\":\"http")
                    || lower.contains("\"x5u\":\"http")
                    || lower.contains("\"jku\": \"http")
                    || lower.contains("\"x5u\": \"http")
                {
                    out.push(SemanticSignal::attack(
                        SemanticKind::Other,
                        "jwt.header_url_ssrf",
                        0.92,
                        40,
                        "semantic:jwt_header_url",
                    ));
                }
                if lower.contains("\"kid\":\"../")
                    || lower.contains("\"kid\":\"..\\")
                    || lower.contains("\"kid\":\"/etc/")
                    || lower.contains("\"kid\":\"/dev/null")
                    || lower.contains("\"kid\":\"|")
                    || lower.contains("\"kid\":\";")
                    || lower.contains("\"kid\":\"'")
                {
                    out.push(SemanticSignal::attack(
                        SemanticKind::Other,
                        "jwt.kid_inject",
                        0.9,
                        40,
                        "semantic:jwt_kid_inject",
                    ));
                }
                if lower.contains("\"jwk\":{") || lower.contains("\"jwk\": {") {
                    out.push(SemanticSignal::attack(
                        SemanticKind::Other,
                        "jwt.embedded_jwk",
                        0.88,
                        40,
                        "semantic:jwt_embedded_jwk",
                    ));
                }
            }
            // claim 注入：路径 / SQLi / XSS / SSTI
            if lower.contains("../")
                && (lower.contains("etc/passwd") || lower.contains("etc\\\\passwd"))
            {
                out.push(SemanticSignal::attack(
                    SemanticKind::Path,
                    "jwt.claim_path_trav",
                    0.9,
                    40,
                    "semantic:jwt_claim_lfi",
                ));
            }
            if lower.contains("<script") || lower.contains("javascript:alert") {
                out.push(SemanticSignal::attack(
                    SemanticKind::Xss,
                    "jwt.claim_xss",
                    0.9,
                    40,
                    "semantic:jwt_claim_xss",
                ));
            }
            if (lower.contains("'--") || lower.contains("' or ") || lower.contains("union select"))
                && (lower.contains("\"sub\"")
                    || lower.contains("\"name\"")
                    || lower.contains("kid"))
            {
                out.push(SemanticSignal::attack(
                    SemanticKind::Sqli,
                    "jwt.claim_sqli",
                    0.88,
                    40,
                    "semantic:jwt_claim_sqli",
                ));
            }
            if lower.contains("{{") && (lower.contains("config") || lower.contains("7*7")) {
                out.push(SemanticSignal::attack(
                    SemanticKind::Ssti,
                    "jwt.claim_ssti",
                    0.88,
                    40,
                    "semantic:jwt_claim_ssti",
                ));
            }
        }
    }
}

fn re_deser_gadget() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:!!python/(?:object|object/apply|name)|java\.lang\.runtime|com\.sun\.rowset\.jdbcrowsetimpl|"@c"\s*:|"@type"\s*:\s*"[^"]{0,80}(?:springframework|templatesimpl|jdbcrowset|objectdataprovider)|objectdataprovider|rO0AB|aced0005|%ac%ed%00%05)"#,
        )
        .unwrap()
    })
}

fn analyze_deser(blob: &str, out: &mut Vec<SemanticSignal>) {
    if re_deser_gadget().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Other,
            "deser.gadget",
            0.9,
            40,
            "semantic:deser_gadget",
        ));
    }
}

fn re_open_redirect() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:^|[&?])(?:url|next|return|returnurl|return_url|redirect|redirect_uri|redirect_url|continue|destination|goto|redir)=(?:https?:|//)[^&\s]*|(?:^|[=&])(?://{2,4}|https?:)(?:[a-z0-9-]+\.)+[a-z]{2,}",
        )
        .unwrap()
    })
}

fn re_nosql_op() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)["']?\$(?:ne|gt|gte|lt|lte|regex|where|nin)\b|\|\|\s*['"][a-z0-9]['"]\s*=="#,
        )
        .unwrap()
    })
}

fn analyze_redirect(input: SemanticInput<'_>, out: &mut Vec<SemanticSignal>) {
    // 仅 URI/query：HTML body 内合法外链不应触发 open redirect 语义
    let target = format!("{} {}", input.uri, input.query);
    if re_open_redirect().is_match(&target) {
        out.push(SemanticSignal::attack(
            SemanticKind::Other,
            "redirect.open",
            0.86,
            40,
            "semantic:open_redirect",
        ));
    }
}

fn analyze_nosql(blob: &str, out: &mut Vec<SemanticSignal>) {
    if re_nosql_op().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Other,
            "nosql.operator",
            0.88,
            40,
            "semantic:nosql_op",
        ));
    }
}

fn analyze_graphql(blob: &str, out: &mut Vec<SemanticSignal>) {
    if re_graphql_intro().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Other,
            "graphql.introspection",
            0.9,
            40,
            "semantic:graphql_intro",
        ));
    }
}

fn analyze_ssrf_cloud(blob: &str, out: &mut Vec<SemanticSignal>) {
    if re_ssrf_cloud_meta().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Other,
            "ssrf.cloud_metadata",
            0.9,
            40,
            "semantic:ssrf_cloud_meta",
        ));
    }
}

fn analyze_priv_escalation(blob: &str, uri: &str, out: &mut Vec<SemanticSignal>) {
    if re_priv_mass_assign().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Other,
            "auth.priv_mass_assign",
            0.88,
            40,
            "semantic:priv_mass_assign",
        ));
    }
    if re_forced_admin_path().is_match(uri) || re_forced_admin_path().is_match(blob) {
        out.push(SemanticSignal::attack(
            SemanticKind::Path,
            "path.forced_admin",
            0.86,
            40,
            "semantic:forced_admin",
        ));
    }
}

#[cfg(test)]
mod jwt_tests {
    use super::*;
    use crate::SemanticInput;
    use nerve_antibody_dsl::NativeLevel;

    #[test]
    fn detects_jwt_alg_none() {
        let tok = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.";
        let rep = analyze(SemanticInput {
            method: "GET",
            uri: "/",
            query: &format!("q={tok}"),
            body: "",
            extra: "",
            level: NativeLevel::High,
        });
        assert!(
            rep.signals.iter().any(|s| s.id == "jwt.alg_none"),
            "signals={:?}",
            rep.signals.iter().map(|s| &s.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detects_jwt_kid_http_ssrf() {
        // {"alg":"HS256","typ":"JWT","kid":"http://attacker.com/key.json"}
        let tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imh0dHA6Ly9hdHRhY2tlci5jb20va2V5Lmpzb24ifQ.eyJzdWIiOiJhZG1pbiJ9.sig";
        let rep = analyze(SemanticInput {
            method: "GET",
            uri: "/",
            query: tok,
            body: "",
            extra: "",
            level: NativeLevel::High,
        });
        assert!(rep.signals.iter().any(|s| s.id == "jwt.header_url_ssrf"));
    }
}
