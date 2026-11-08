//! Filename hardening.
//!
//! Every name that comes from the network (`Content-Disposition`, URL path) is
//! attacker-controlled. This module turns it into a single, harmless path
//! component that is valid on Windows, macOS and Linux.

use percent_encoding::percent_decode_str;
use serde::Serialize;
use unicode_normalization::UnicodeNormalization;

/// Maximum size of a delivered file name, in UTF-8 bytes (all three OSes
/// accept 255; we keep headroom for the " (n)" de-duplication suffix).
pub const MAX_NAME_BYTES: usize = 200;
const FALLBACK_NAME: &str = "download";

/// Something noteworthy that was found (and neutralised) in a file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameWarning {
    /// Directory components (`../`, `C:\`, `/etc/`) were stripped.
    PathComponentsRemoved,
    /// ASCII / C1 control characters were removed.
    ControlCharsRemoved,
    /// Bidirectional overrides (RTLO…) or invisible characters were removed.
    BidiOrInvisibleCharsRemoved,
    /// The name was a reserved Windows device name (CON, NUL, COM1…).
    ReservedName,
    /// A decoy extension hid the real one (`invoice.pdf.exe`).
    DeceptiveDoubleExtension,
    /// The real extension is directly executable or a script.
    ExecutableExtension,
    /// The name was too long and has been shortened.
    Truncated,
    /// Nothing usable was left; a generic name was used.
    Empty,
}

/// A cleaned file name plus what had to be changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SanitizedName {
    pub name: String,
    pub warnings: Vec<NameWarning>,
}

impl SanitizedName {
    fn warn(&mut self, w: NameWarning) {
        if !self.warnings.contains(&w) {
            self.warnings.push(w);
        }
    }
}

/// Extensions that run code when opened on at least one supported OS.
const EXECUTABLE_EXTENSIONS: &[&str] = &[
    // Windows
    "exe",
    "scr",
    "com",
    "pif",
    "bat",
    "cmd",
    "msi",
    "msp",
    "mst",
    "msix",
    "msixbundle",
    "appx",
    "appxbundle",
    "appref-ms",
    "js",
    "jse",
    "vbs",
    "vbe",
    "vb",
    "wsf",
    "wsh",
    "ws",
    "wsc",
    "ps1",
    "psm1",
    "psd1",
    "ps1xml",
    "psc1",
    "hta",
    "cpl",
    "jar",
    "lnk",
    "url",
    "reg",
    "inf",
    "scf",
    "gadget",
    "application",
    "chm",
    "dll",
    "sys",
    "ocx",
    "sct",
    "msc",
    "settingcontent-ms",
    "library-ms",
    "search-ms",
    "iso",
    "img",
    "vhd",
    "vhdx",
    "xll",
    "xlam",
    "docm",
    "xlsm",
    "pptm",
    // macOS
    "app",
    "command",
    "pkg",
    "mpkg",
    "terminal",
    "workflow",
    "scpt",
    "applescript",
    "tool",
    // Linux / cross-platform
    "msh",
    "cab",
    "dmg",
    "jnlp",
    "xpi",
    "crx",
    "apk",
    "deb",
    "rpm",
    "sh",
    "bash",
    "zsh",
    "csh",
    "ksh",
    "run",
    "bin",
    "appimage",
    "desktop",
    "py",
    "pyw",
    "pl",
    "rb",
];

/// Extensions commonly used as a decoy in front of an executable one.
const DECOY_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "txt", "csv",
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg", "heic", "mp3", "wav", "flac", "mp4", "avi",
    "mkv", "mov", "wmv", "zip", "rar", "7z", "tar", "gz", "html", "htm", "xml", "json", "eml",
];

/// Returns true if `ext` (without dot, any case) is executable on some OS.
pub fn is_executable_extension(ext: &str) -> bool {
    let ext = ext.to_ascii_lowercase();
    EXECUTABLE_EXTENSIONS.contains(&ext.as_str())
}

/// Unicode Default_Ignorable_Code_Point + format (Cf) characters + characters
/// that render as blank. Covers the bidi overrides (RTLO) and every invisible
/// filler an attacker can use to push the real extension out of view.
fn is_bidi_or_invisible(c: char) -> bool {
    matches!(c,
        // --- Default_Ignorable_Code_Point (Unicode DerivedCoreProperties) ---
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}'
        | '\u{17B4}' | '\u{17B5}' | '\u{180B}'..='\u{180F}'
        | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}'
        | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFA0}' | '\u{FFF0}'..='\u{FFF8}'
        | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}' | '\u{E0000}'..='\u{E0FFF}'
        // --- other format (Cf) characters ---
        | '\u{0600}'..='\u{0605}' | '\u{06DD}' | '\u{070F}' | '\u{0890}' | '\u{0891}' | '\u{08E2}'
        | '\u{FFF9}'..='\u{FFFB}' | '\u{110BD}' | '\u{110CD}' | '\u{13430}'..='\u{1343F}'
        // --- visible-as-blank characters ---
        | '\u{2800}'    // Braille pattern blank
        | '\u{FFFC}'    // object replacement character
        | '\u{1CBC}'    // Georgian filler (blank glyph)
        | '\u{1D159}'   // musical symbol null notehead
        | '\u{2028}' | '\u{2029}' // line / paragraph separators
    )
}

fn is_windows_reserved(stem: &str) -> bool {
    let base = stem.trim_end_matches([' ', '.']).to_ascii_lowercase();
    match base.as_str() {
        "con" | "prn" | "aux" | "nul" | "conin$" | "conout$" | "clock$" => true,
        b if b.len() == 4 && (b.starts_with("com") || b.starts_with("lpt")) => {
            b.as_bytes()[3].is_ascii_digit()
        }
        _ => false,
    }
}

/// Clean an untrusted file name so that it is a single, safe path component.
pub fn sanitize_filename(raw: &str) -> SanitizedName {
    let mut out = SanitizedName {
        name: String::new(),
        warnings: Vec::new(),
    };

    // 1. NFKC folds look-alikes such as fullwidth "．ｅｘｅ" or "／" into ASCII,
    //    so they are handled by the rules below instead of slipping through.
    let normalized: String = raw.nfkc().collect();

    // 2. Keep only the last path component (both separators, any OS).
    let parts: Vec<&str> = normalized
        .split(['/', '\\'])
        .filter(|p| !p.is_empty())
        .collect();
    if parts.len() > 1 || normalized.starts_with(['/', '\\']) {
        out.warn(NameWarning::PathComponentsRemoved);
    }
    let last = parts.last().copied().unwrap_or("");

    // 3. Drop control, bidi and invisible characters; neutralise characters
    //    that are illegal on Windows (':' also blocks NTFS alternate streams).
    let mut cleaned = String::with_capacity(last.len());
    for c in last.chars() {
        if c.is_control() {
            out.warn(NameWarning::ControlCharsRemoved);
        } else if is_bidi_or_invisible(c) {
            out.warn(NameWarning::BidiOrInvisibleCharsRemoved);
        } else if matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') {
            cleaned.push('_');
        } else if c.is_whitespace() {
            cleaned.push(' ');
        } else {
            cleaned.push(c);
        }
    }

    // 4. Collapse whitespace runs and remove spaces around dots, so
    //    "invoice.pdf          .exe" cannot push the real extension out of view.
    let mut collapsed = String::with_capacity(cleaned.len());
    for c in cleaned.chars() {
        if c == ' ' && collapsed.ends_with(' ') {
            continue;
        }
        collapsed.push(c);
    }
    while collapsed.contains(" .") || collapsed.contains(". ") || collapsed.contains("..") {
        collapsed = collapsed
            .replace(" .", ".")
            .replace(". ", ".")
            .replace("..", ".");
    }

    // 5. No leading dots (hidden files, "..") and no trailing dots/spaces
    //    (silently stripped by Windows, which would change the extension).
    let mut name = collapsed
        .trim_start_matches(['.', ' '])
        .trim_end_matches(['.', ' '])
        .to_string();

    // 6. Deceptive double extension: "invoice.pdf.exe" -> "invoice_pdf.exe".
    if let Some((stem, ext)) = name.rsplit_once('.') {
        if is_executable_extension(ext) {
            out.warn(NameWarning::ExecutableExtension);
            // Ignore filler between the decoy and the real extension
            // ("facture.pdf_.exe", "facture.pdf - .exe").
            let stem = stem.trim_end_matches(['_', ' ', '.', '-']);
            if let Some((inner_stem, inner_ext)) = stem.rsplit_once('.') {
                if DECOY_EXTENSIONS.contains(&inner_ext.to_ascii_lowercase().as_str()) {
                    out.warn(NameWarning::DeceptiveDoubleExtension);
                    name = format!("{inner_stem}_{inner_ext}.{ext}");
                }
            }
        }
    }

    // 7. Windows reserved device names (checked on the part before the first dot).
    let first_stem = name.split('.').next().unwrap_or("");
    if is_windows_reserved(first_stem) {
        out.warn(NameWarning::ReservedName);
        name.insert(0, '_');
    }

    // 8. Length limit, preserving a reasonable extension.
    if name.len() > MAX_NAME_BYTES {
        out.warn(NameWarning::Truncated);
        let (stem, ext) = match name.rsplit_once('.') {
            Some((s, e)) if !e.is_empty() && e.len() <= 16 => (s.to_string(), format!(".{e}")),
            _ => (name.clone(), String::new()),
        };
        let mut budget = MAX_NAME_BYTES - ext.len();
        while !stem.is_char_boundary(budget) {
            budget -= 1;
        }
        name = format!("{}{}", stem[..budget].trim_end_matches([' ', '.']), ext);
    }

    if name.is_empty() {
        out.warn(NameWarning::Empty);
        name = FALLBACK_NAME.to_string();
    }
    out.name = name;
    out
}

/// Extract the file name from a `Content-Disposition` header value.
/// `filename*` (RFC 5987/6266) takes precedence over `filename`.
/// The result is NOT sanitized; pass it through [`sanitize_filename`].
pub fn filename_from_content_disposition(value: &str) -> Option<String> {
    let mut plain: Option<String> = None;
    let mut extended: Option<String> = None;
    for param in split_params(value).into_iter().skip(1) {
        let Some((key, val)) = param.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let val = val.trim();
        match key.as_str() {
            "filename*" => {
                // charset'lang'percent-encoded
                let mut it = val.splitn(3, '\'');
                let (charset, _lang, encoded) = (it.next()?, it.next(), it.next());
                if let Some(encoded) = encoded {
                    let bytes: Vec<u8> = percent_decode_str(encoded).collect();
                    let decoded = if charset.eq_ignore_ascii_case("utf-8") {
                        String::from_utf8_lossy(&bytes).into_owned()
                    } else {
                        // ISO-8859-1 (the only other charset RFC 5987 mandates).
                        bytes.iter().map(|&b| b as char).collect()
                    };
                    extended = Some(decoded);
                }
            }
            "filename" => plain = Some(unquote(val)),
            _ => {}
        }
    }
    extended.or(plain).filter(|s| !s.trim().is_empty())
}

/// Split a header value on ';' while respecting quoted strings.
fn split_params(value: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for c in value.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => {
                cur.push(c);
                escaped = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            ';' if !in_quotes => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    parts
}

fn unquote(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        let inner = &v[1..v.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            } else {
                out.push(c);
            }
        }
        out
    } else {
        v.to_string()
    }
}

/// Last path segment of a URL, percent-decoded. NOT sanitized.
pub fn filename_from_url(url: &url::Url) -> Option<String> {
    let seg = url.path_segments()?.rfind(|s| !s.is_empty())?;
    let decoded = percent_decode_str(seg).decode_utf8_lossy().into_owned();
    Some(decoded).filter(|s| !s.trim().is_empty())
}

/// Choose and sanitize the best available name for a download.
pub fn choose_name(
    content_disposition: Option<&str>,
    final_url: &url::Url,
    original_url: &url::Url,
) -> SanitizedName {
    let raw = content_disposition
        .and_then(filename_from_content_disposition)
        .or_else(|| filename_from_url(final_url))
        .or_else(|| filename_from_url(original_url))
        .unwrap_or_default();
    sanitize_filename(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(raw: &str) -> String {
        sanitize_filename(raw).name
    }

    #[test]
    fn plain_names_are_kept() {
        assert_eq!(s("report.pdf"), "report.pdf");
        assert_eq!(
            s("Ubuntu 24.04 desktop amd64.iso"),
            "Ubuntu 24.04 desktop amd64.iso"
        );
        assert_eq!(s("photo été.jpg"), "photo été.jpg");
    }

    #[test]
    fn path_traversal_is_removed() {
        for raw in [
            "../../etc/passwd",
            "..\\..\\Windows\\System32\\evil.dll",
            "/etc/passwd",
            "C:\\Users\\x\\file.txt",
            "a/../../b.txt",
            "..",
            ".",
            "....//....//x",
        ] {
            let r = sanitize_filename(raw);
            assert!(
                !r.name.contains('/') && !r.name.contains('\\'),
                "{raw} -> {}",
                r.name
            );
            assert!(!r.name.starts_with('.'), "{raw} -> {}", r.name);
            assert_ne!(r.name, "..");
        }
        let r = sanitize_filename("../../etc/passwd");
        assert_eq!(r.name, "passwd");
        assert!(r.warnings.contains(&NameWarning::PathComponentsRemoved));
        assert_eq!(s("C:\\Users\\x\\file.txt"), "file.txt");
        assert_eq!(s(".."), FALLBACK_NAME);
    }

    #[test]
    fn fullwidth_separators_are_folded_then_removed() {
        // U+FF0F FULLWIDTH SOLIDUS and U+FF0E FULLWIDTH FULL STOP
        assert_eq!(s("．．／．．／secret"), "secret");
    }

    #[test]
    fn control_characters_are_removed() {
        let r = sanitize_filename("bad\u{0000}na\u{0007}me\u{001b}[31m.txt\u{0085}");
        assert_eq!(r.name, "badname[31m.txt");
        assert!(r.warnings.contains(&NameWarning::ControlCharsRemoved));
        assert_eq!(s("line\nbreak\r.txt"), "linebreak.txt");
    }

    #[test]
    fn rtlo_is_removed_and_real_extension_revealed() {
        // Displays as "invoicefdp.exe" reversed => "invoiceexe.pdf" to a human.
        let r = sanitize_filename("invoice\u{202E}fdp.exe");
        assert_eq!(r.name, "invoicefdp.exe");
        assert!(r
            .warnings
            .contains(&NameWarning::BidiOrInvisibleCharsRemoved));
        assert!(r.warnings.contains(&NameWarning::ExecutableExtension));
        for c in ['\u{200B}', '\u{2066}', '\u{FEFF}', '\u{E0041}', '\u{061C}'] {
            assert_eq!(s(&format!("a{c}b.txt")), "ab.txt");
        }
    }

    #[test]
    fn deceptive_double_extension_is_rewritten() {
        let r = sanitize_filename("facture.pdf.exe");
        assert_eq!(r.name, "facture_pdf.exe");
        assert!(r.warnings.contains(&NameWarning::DeceptiveDoubleExtension));
        assert_eq!(s("photo.JPG.scr"), "photo_JPG.scr");
        assert_eq!(s("facture.pdf      .exe"), "facture_pdf.exe");
        assert_eq!(s("facture.pdf.  .exe"), "facture_pdf.exe");
        // Legit multi-dot names are untouched.
        assert_eq!(s("archive.tar.gz"), "archive.tar.gz");
        assert_eq!(s("setup-1.2.3.exe"), "setup-1.2.3.exe");
    }

    #[test]
    fn trailing_dots_and_spaces_are_removed() {
        assert_eq!(s("evil.exe. . ."), "evil.exe");
        assert_eq!(s("  name.txt  "), "name.txt");
        assert_eq!(s(".bashrc"), "bashrc");
    }

    #[test]
    fn windows_reserved_names_are_prefixed() {
        for raw in [
            "CON",
            "con.txt",
            "NUL",
            "Aux.tar.gz",
            "COM1",
            "lpt9.log",
            "COM¹.txt",
            "CONIN$",
        ] {
            let r = sanitize_filename(raw);
            assert!(r.name.starts_with('_'), "{raw} -> {}", r.name);
            assert!(r.warnings.contains(&NameWarning::ReservedName));
        }
        assert_eq!(s("console.txt"), "console.txt");
        assert_eq!(s("COM10.txt"), "COM10.txt");
    }

    #[test]
    fn illegal_windows_characters_are_replaced() {
        assert_eq!(s("a<b>c:d\"e|f?g*h.txt"), "a_b_c_d_e_f_g_h.txt");
        // ':' would otherwise address an NTFS alternate data stream.
        assert_eq!(s("file.txt:Zone.Identifier"), "file.txt_Zone.Identifier");
    }

    #[test]
    fn long_names_are_truncated_keeping_extension() {
        let raw = format!("{}.pdf", "é".repeat(300));
        let r = sanitize_filename(&raw);
        assert!(r.name.len() <= MAX_NAME_BYTES);
        assert!(r.name.ends_with(".pdf"));
        assert!(r.warnings.contains(&NameWarning::Truncated));
    }

    #[test]
    fn empty_names_get_a_fallback() {
        for raw in ["", "   ", "\u{202E}", "/", "...", "\u{0000}"] {
            assert_eq!(s(raw), FALLBACK_NAME, "{raw:?}");
        }
    }

    #[test]
    fn content_disposition_parsing() {
        assert_eq!(
            filename_from_content_disposition("attachment; filename=\"report.pdf\"").as_deref(),
            Some("report.pdf")
        );
        assert_eq!(
            filename_from_content_disposition("attachment; filename=plain.txt").as_deref(),
            Some("plain.txt")
        );
        // filename* wins and is percent-decoded UTF-8.
        assert_eq!(
            filename_from_content_disposition(
                "attachment; filename=\"fallback.txt\"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf"
            )
            .as_deref(),
            Some("résumé.pdf")
        );
        // ISO-8859-1
        assert_eq!(
            filename_from_content_disposition("attachment; filename*=iso-8859-1'en'%E9t%E9.txt")
                .as_deref(),
            Some("été.txt")
        );
        // Semicolons and escaped quotes inside a quoted string.
        assert_eq!(
            filename_from_content_disposition(r#"attachment; filename="a;b \"c\".txt""#).as_deref(),
            Some("a;b \"c\".txt")
        );
        assert_eq!(filename_from_content_disposition("inline"), None);
        // Malicious values are only extracted here; sanitizing happens after.
        let raw = filename_from_content_disposition("attachment; filename*=UTF-8''..%2F..%2Fx.sh")
            .unwrap_or_default();
        assert_eq!(sanitize_filename(&raw).name, "x.sh");
    }

    #[test]
    fn url_names() {
        let u = url::Url::parse("https://example.com/dl/My%20File.zip?token=abc").unwrap();
        assert_eq!(filename_from_url(&u).as_deref(), Some("My File.zip"));
        let u = url::Url::parse("https://example.com/").unwrap();
        assert_eq!(filename_from_url(&u), None);
        let u = url::Url::parse("https://example.com/a/..%2F..%2Fevil.exe").unwrap();
        let name = choose_name(None, &u, &u);
        assert_eq!(name.name, "evil.exe");
    }

    #[test]
    fn choose_name_prefers_content_disposition() {
        let u = url::Url::parse("https://example.com/download.php?id=1").unwrap();
        let n = choose_name(Some("attachment; filename=\"real.zip\""), &u, &u);
        assert_eq!(n.name, "real.zip");
        let n = choose_name(None, &u, &u);
        assert_eq!(n.name, "download.php");
    }

    #[test]
    fn invisible_padding_cannot_hide_the_real_extension() {
        // Audit F4: Braille blanks between the decoy and the real extension.
        let r = sanitize_filename(&format!("facture.pdf{}.exe", "\u{2800}".repeat(8)));
        assert_eq!(r.name, "facture_pdf.exe");
        assert!(r.warnings.contains(&NameWarning::DeceptiveDoubleExtension));
        let r = sanitize_filename("invoice.pdf.dmg");
        assert_eq!(r.name, "invoice_pdf.dmg");
    }

    #[test]
    fn reaudit_padding_variants() {
        for pad in [
            "\u{1CBC}",
            "\u{180B}",
            "\u{1BCA0}",
            "\u{1D159}",
            "_\u{2800}",
            "_",
        ] {
            let r = sanitize_filename(&format!("facture.pdf{pad}.exe"));
            assert_eq!(r.name, "facture_pdf.exe", "{pad:?}");
            assert!(r.warnings.contains(&NameWarning::DeceptiveDoubleExtension));
        }
        assert!(is_executable_extension("msh") && is_executable_extension("cab"));
    }
}
