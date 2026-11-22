//! Real file type vs. extension (magic bytes).
//!
//! Only the first bytes of the file are read, like hashing: the file is never
//! interpreted, previewed or executed. The goal is to catch the classic trick
//! of a program disguised as a document (`invoice.pdf` that is really a
//! Windows executable).
//!
//! Rules (kept deliberately narrow to avoid false alarms):
//! - a check happens only when the name has an extension listed below;
//! - a **program** (PE/ELF/Mach-O/shortcut) behind a document, media, archive
//!   or text extension ⇒ the verdict becomes Suspect;
//! - any other mismatch between two known kinds (a `.jpg` that is a PNG, a
//!   `.zip` that is a 7-Zip) is only reported, without changing the verdict.

use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Bytes read from the start of the file (enough for ISO 9660 at 0x9001).
pub const SNIFF_LEN: usize = 0x9006;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    WindowsProgram,
    LinuxProgram,
    MacProgram,
    WindowsShortcut,
    Zip,
    Rar,
    SevenZip,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Cab,
    Pdf,
    Ole,
    Rtf,
    Png,
    Jpeg,
    Gif,
    Bmp,
    Webp,
    Iso,
    Mp4,
    Matroska,
    Mp3,
    Wav,
    Flac,
    Ogg,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::WindowsProgram => "a Windows program (PE executable)",
            Kind::LinuxProgram => "a Linux program (ELF executable)",
            Kind::MacProgram => "a macOS program (Mach-O executable)",
            Kind::WindowsShortcut => "a Windows shortcut (.lnk)",
            Kind::Zip => "a ZIP archive",
            Kind::Rar => "a RAR archive",
            Kind::SevenZip => "a 7-Zip archive",
            Kind::Gzip => "a gzip archive",
            Kind::Bzip2 => "a bzip2 archive",
            Kind::Xz => "an xz archive",
            Kind::Zstd => "a Zstandard archive",
            Kind::Cab => "a Windows cabinet archive",
            Kind::Pdf => "a PDF document",
            Kind::Ole => "an old Microsoft Office / MSI file",
            Kind::Rtf => "an RTF document",
            Kind::Png => "a PNG image",
            Kind::Jpeg => "a JPEG image",
            Kind::Gif => "a GIF image",
            Kind::Bmp => "a BMP image",
            Kind::Webp => "a WebP image",
            Kind::Iso => "a disk image (ISO 9660)",
            Kind::Mp4 => "an MP4/QuickTime video",
            Kind::Matroska => "a Matroska/WebM video",
            Kind::Mp3 => "an MP3 audio file",
            Kind::Wav => "a WAV audio file",
            Kind::Flac => "a FLAC audio file",
            Kind::Ogg => "an Ogg audio/video file",
        }
    }

    pub fn is_program(self) -> bool {
        matches!(
            self,
            Kind::WindowsProgram | Kind::LinuxProgram | Kind::MacProgram | Kind::WindowsShortcut
        )
    }

    /// Extensions under which this content is normal.
    fn extensions(self) -> &'static [&'static str] {
        match self {
            Kind::WindowsProgram => &[
                "exe", "dll", "sys", "scr", "com", "ocx", "cpl", "efi", "drv", "mui", "ax", "pif",
                "msstyles", "tlb", "node", "pyd", "winmd", "xll", "msp", "mun",
            ],
            Kind::LinuxProgram => &["so", "ko", "o", "elf", "bin", "run", "appimage", "out"],
            Kind::MacProgram => &["dylib", "bundle", "so", "o"],
            Kind::WindowsShortcut => &["lnk"],
            Kind::Zip => &[
                "zip",
                "jar",
                "war",
                "ear",
                "apk",
                "aab",
                "xapk",
                "ipa",
                "docx",
                "docm",
                "xlsx",
                "xlsm",
                "pptx",
                "pptm",
                "odt",
                "ods",
                "odp",
                "odg",
                "epub",
                "xpi",
                "nupkg",
                "whl",
                "msix",
                "msixbundle",
                "appx",
                "appxbundle",
                "vsix",
                "aar",
                "kmz",
                "3mf",
                "crx",
                "cbz",
                "sketch",
                "pages",
                "numbers",
                "key",
                "xps",
                "oxps",
                "egg",
                "aia",
            ],
            Kind::Rar => &["rar", "cbr"],
            Kind::SevenZip => &["7z", "cb7"],
            Kind::Gzip => &["gz", "tgz", "svgz", "gzip"],
            Kind::Bzip2 => &["bz2", "tbz", "tbz2"],
            Kind::Xz => &["xz", "txz"],
            Kind::Zstd => &["zst", "tzst"],
            Kind::Cab => &["cab", "msu"],
            Kind::Pdf => &["pdf", "ai"],
            Kind::Ole => &[
                "doc", "dot", "xls", "xlt", "ppt", "pot", "pps", "msi", "msp", "mst", "msg", "pub",
                "vsd", "mpp", "wps",
            ],
            Kind::Rtf => &["rtf", "doc"],
            Kind::Png => &["png", "apng"],
            Kind::Jpeg => &["jpg", "jpeg", "jpe", "jfif"],
            Kind::Gif => &["gif"],
            Kind::Bmp => &["bmp", "dib"],
            Kind::Webp => &["webp"],
            Kind::Iso => &["iso", "img", "udf"],
            Kind::Mp4 => &[
                "mp4", "m4v", "m4a", "mov", "3gp", "3g2", "heic", "heif", "avif",
            ],
            Kind::Matroska => &["mkv", "webm", "mka"],
            Kind::Mp3 => &["mp3"],
            Kind::Wav => &["wav"],
            Kind::Flac => &["flac"],
            Kind::Ogg => &["ogg", "oga", "ogv", "opus"],
        }
    }
}

/// Extensions a person expects to be harmless when opened (documents,
/// media, archives, plain text). A program behind one of these is a lure.
const HARMLESS_LOOKING: &[&str] = &[
    // documents
    "pdf", "doc", "docx", "docm", "dot", "xls", "xlsx", "xlsm", "ppt", "pptx", "pps", "odt", "ods",
    "odp", "rtf", "txt", "csv", "md", "epub", "xps", "pages", "numbers", "key", "log", "nfo",
    // images
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg", "tif", "tiff", "heic", "ico", "psd",
    // audio / video
    "mp3", "wav", "flac", "ogg", "m4a", "aac", "mp4", "m4v", "mkv", "webm", "avi", "mov", "wmv",
    // archives / images
    "zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "zst", "iso", "img", "dmg",
    // text / web / data
    "html", "htm", "xml", "json", "yaml", "yml", "ini", "cfg", "conf", "eml",
];

/// Identify the content from its first bytes.
pub fn sniff(h: &[u8]) -> Option<Kind> {
    let starts = |m: &[u8]| h.starts_with(m);
    let at = |off: usize, m: &[u8]| h.len() >= off + m.len() && &h[off..off + m.len()] == m;
    let kind = if starts(b"MZ") {
        Kind::WindowsProgram
    } else if starts(&[0x7f, b'E', b'L', b'F']) {
        Kind::LinuxProgram
    } else if starts(&[0xcf, 0xfa, 0xed, 0xfe])
        || starts(&[0xce, 0xfa, 0xed, 0xfe])
        || starts(&[0xfe, 0xed, 0xfa, 0xcf])
        || starts(&[0xfe, 0xed, 0xfa, 0xce])
        // Universal binary; also the Java class magic, told apart by the
        // architecture count (a class file has a version number ≥ 45 there).
        || (starts(&[0xca, 0xfe, 0xba, 0xbe]) && h.len() >= 8 && u32::from_be_bytes([h[4], h[5], h[6], h[7]]) < 30)
    {
        Kind::MacProgram
    } else if starts(&[0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0]) {
        Kind::WindowsShortcut
    } else if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") || starts(b"PK\x07\x08") {
        Kind::Zip
    } else if starts(b"Rar!\x1a\x07") {
        Kind::Rar
    } else if starts(&[b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c]) {
        Kind::SevenZip
    } else if starts(&[0x1f, 0x8b]) {
        Kind::Gzip
    } else if starts(b"BZh") {
        Kind::Bzip2
    } else if starts(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        Kind::Xz
    } else if starts(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Kind::Zstd
    } else if starts(b"MSCF") {
        Kind::Cab
    } else if starts(b"%PDF-") {
        Kind::Pdf
    } else if starts(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
        Kind::Ole
    } else if starts(b"{\\rtf") {
        Kind::Rtf
    } else if starts(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        Kind::Png
    } else if starts(&[0xff, 0xd8, 0xff]) {
        Kind::Jpeg
    } else if starts(b"GIF87a") || starts(b"GIF89a") {
        Kind::Gif
    } else if starts(b"BM") && h.len() >= 26 && at(6, &[0, 0, 0, 0]) {
        Kind::Bmp
    } else if starts(b"RIFF") && at(8, b"WEBP") {
        Kind::Webp
    } else if starts(b"RIFF") && at(8, b"WAVE") {
        Kind::Wav
    } else if at(0x8001, b"CD001") || at(0x8801, b"CD001") || at(0x9001, b"CD001") {
        Kind::Iso
    } else if at(4, b"ftyp") {
        Kind::Mp4
    } else if starts(&[0x1a, 0x45, 0xdf, 0xa3]) {
        Kind::Matroska
    } else if starts(b"ID3") {
        Kind::Mp3
    } else if starts(b"fLaC") {
        Kind::Flac
    } else if starts(b"OggS") {
        Kind::Ogg
    } else {
        return None;
    };
    Some(kind)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeMismatch {
    /// Extension of the file name (lowercase, without the dot).
    pub extension: String,
    /// What the content really is.
    pub detected: Kind,
    /// Human description of the detected kind.
    pub detected_label: String,
    /// A program disguised as a harmless-looking file.
    pub disguised_program: bool,
}

/// Compare the name's extension with the content.
pub fn check(file_name: &str, head: &[u8]) -> Option<TypeMismatch> {
    let (_, ext) = file_name.rsplit_once('.')?;
    let ext = ext.trim().to_ascii_lowercase();
    if ext.is_empty() {
        return None;
    }
    let detected = sniff(head)?;
    if detected.extensions().contains(&ext.as_str()) {
        return None;
    }
    let disguised_program = detected.is_program() && HARMLESS_LOOKING.contains(&ext.as_str());
    // A non-program mismatch is reported only when the extension itself names
    // a known kind (otherwise `.dat`, `.bin`, `.part`… would be noise).
    let ext_is_known = HARMLESS_LOOKING.contains(&ext.as_str())
        || ALL_KINDS
            .iter()
            .any(|k| k.extensions().contains(&ext.as_str()));
    if !disguised_program && (detected.is_program() || !ext_is_known) {
        return None;
    }
    Some(TypeMismatch {
        extension: ext,
        detected,
        detected_label: detected.label().to_string(),
        disguised_program,
    })
}

/// Read the first bytes of a file and run [`check`].
pub fn check_file(path: &Path, file_name: &str) -> Option<TypeMismatch> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut head = Vec::with_capacity(SNIFF_LEN);
    (&mut f)
        .take(SNIFF_LEN as u64)
        .read_to_end(&mut head)
        .ok()?;
    check(file_name, &head)
}

const ALL_KINDS: &[Kind] = &[
    Kind::WindowsProgram,
    Kind::LinuxProgram,
    Kind::MacProgram,
    Kind::WindowsShortcut,
    Kind::Zip,
    Kind::Rar,
    Kind::SevenZip,
    Kind::Gzip,
    Kind::Bzip2,
    Kind::Xz,
    Kind::Zstd,
    Kind::Cab,
    Kind::Pdf,
    Kind::Ole,
    Kind::Rtf,
    Kind::Png,
    Kind::Jpeg,
    Kind::Gif,
    Kind::Bmp,
    Kind::Webp,
    Kind::Iso,
    Kind::Mp4,
    Kind::Matroska,
    Kind::Mp3,
    Kind::Wav,
    Kind::Flac,
    Kind::Ogg,
];

#[cfg(test)]
mod tests {
    use super::*;

    const PE: &[u8] = b"MZ\x90\x00\x03\x00\x00\x00";
    const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0];

    #[test]
    fn program_disguised_as_document_is_flagged() {
        for name in [
            "facture.pdf",
            "photo.JPG",
            "notes.txt",
            "archive.zip",
            "x.docx",
        ] {
            let m = check(name, PE).unwrap_or_else(|| panic!("{name}"));
            assert!(m.disguised_program, "{name}");
            assert_eq!(m.detected, Kind::WindowsProgram);
        }
        let elf = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        assert!(check("video.mp4", &elf).unwrap().disguised_program);
        let lnk = [0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0];
        assert!(check("document.pdf", &lnk).unwrap().disguised_program);
    }

    #[test]
    fn matching_or_unknown_names_are_not_flagged() {
        assert_eq!(check("setup.exe", PE), None);
        assert_eq!(check("lib.DLL", PE), None);
        assert_eq!(check("tool", PE), None); // no extension: no claim made
        assert_eq!(check("blob.dat", PE), None); // unknown extension
        assert_eq!(check("image.png", PNG), None);
        assert_eq!(check("report.docx", b"PK\x03\x04rest"), None);
        assert_eq!(check("old.doc", b"{\\rtf1"), None);
        assert_eq!(check("notes.txt", b"plain text"), None); // unknown content
        assert_eq!(check("program.bin", &[0x7f, b'E', b'L', b'F']), None);
        // Java class files share the Mach-O universal magic.
        assert_eq!(
            sniff(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52]),
            None,
            "class file"
        );
        assert_eq!(
            sniff(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]),
            Some(Kind::MacProgram)
        );
    }

    #[test]
    fn other_mismatches_are_informational() {
        let m = check("photo.jpg", PNG).unwrap();
        assert!(!m.disguised_program);
        assert_eq!(m.detected, Kind::Png);
        let m = check("backup.zip", &[b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c]).unwrap();
        assert!(!m.disguised_program);
        // A program behind a program-ish but unusual extension: not a lure.
        assert_eq!(check("driver.msi", PE), None);
    }

    #[test]
    fn iso_detection_needs_the_offset() {
        let mut iso = vec![0u8; 0x8006];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_eq!(sniff(&iso), Some(Kind::Iso));
        assert!(check("movie.mp4", &iso).is_some());
    }
}
