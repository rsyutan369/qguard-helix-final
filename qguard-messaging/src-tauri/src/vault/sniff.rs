//! Content-type detection for Quantum Vault Storage.
//!
//! The vault never trusts a file's extension or a picker-supplied MIME type:
//! the type shown in the vault, the category a file is filed under and whether
//! it may be previewed all come from the file's own leading bytes. The
//! extension is only used to tell apart formats that share one container
//! (DOCX / XLSX / PPTX are all ZIP files) and to report a mismatch when the
//! name claims one thing and the content is another.
//!
//! This is classification, not malware scanning: a correctly identified PDF is
//! not thereby a safe PDF.

use serde::Serialize;

/// How many leading bytes [`sniff`] looks at.
pub const SNIFF_LEN: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Image,
    Video,
    Audio,
    Document,
    Archive,
    Other,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Image => "image",
            Category::Video => "video",
            Category::Audio => "audio",
            Category::Document => "document",
            Category::Archive => "archive",
            Category::Other => "other",
        }
    }

    pub fn parse(value: &str) -> Category {
        match value {
            "image" => Category::Image,
            "video" => Category::Video,
            "audio" => Category::Audio,
            "document" => Category::Document,
            "archive" => Category::Archive,
            _ => Category::Other,
        }
    }
}

/// Whether the name's extension agrees with the detected content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TypeCheck {
    /// The content was recognised and the extension agrees with it.
    Match,
    /// The content was recognised and the extension claims something else.
    Mismatch,
    /// The content was not recognised (or there is no extension to compare).
    Unknown,
}

impl TypeCheck {
    pub fn as_str(self) -> &'static str {
        match self {
            TypeCheck::Match => "match",
            TypeCheck::Mismatch => "mismatch",
            TypeCheck::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detected {
    pub content_type: String,
    pub category: Category,
    pub type_check: TypeCheck,
}

/// The lowercase extension of `name`, without the dot. Empty when there is none.
pub fn extension_of(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() && ext.len() <= 12 => ext.to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// Content type implied by an extension alone. Used only to compare with what
/// the content says, never as the answer.
fn content_type_for_extension(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" | "heif" => "image/heic",
        "bmp" => "image/bmp",
        "pdf" => "application/pdf",
        "doc" | "xls" | "ppt" => "application/x-ole-storage",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt" | "ods" | "odp" | "zip" => "application/zip",
        "txt" | "md" | "log" => "text/plain",
        "csv" => "text/csv",
        "json" => "application/json",
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "aac" => "audio/aac",
        "m4a" => "audio/mp4",
        "flac" => "audio/flac",
        "ogg" | "oga" => "audio/ogg",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/vnd.rar",
        "gz" | "tgz" => "application/gzip",
        _ => return None,
    })
}

fn category_for(content_type: &str) -> Category {
    if content_type.starts_with("image/") {
        Category::Image
    } else if content_type.starts_with("video/") {
        Category::Video
    } else if content_type.starts_with("audio/") {
        Category::Audio
    } else if content_type == "application/pdf"
        || content_type.starts_with("text/")
        || content_type == "application/json"
        || content_type == "application/x-ole-storage"
        || content_type.starts_with("application/vnd.openxmlformats-officedocument")
        || content_type.starts_with("application/vnd.oasis.opendocument")
    {
        Category::Document
    } else if matches!(
        content_type,
        "application/zip" | "application/x-7z-compressed" | "application/vnd.rar" | "application/gzip"
    ) {
        Category::Archive
    } else {
        Category::Other
    }
}

/// ISO-BMFF (`ftyp` box) brand: MP4/MOV video, M4A audio, HEIC/AVIF images.
fn iso_bmff(head: &[u8]) -> Option<&'static str> {
    if head.len() < 12 || &head[4..8] != b"ftyp" {
        return None;
    }
    let brand = &head[8..12];
    Some(match brand {
        b"heic" | b"heix" | b"hevc" | b"heim" | b"heis" | b"mif1" | b"msf1" => "image/heic",
        b"avif" | b"avis" => "image/avif",
        b"qt  " => "video/quicktime",
        b"M4A " | b"M4B " => "audio/mp4",
        _ => "video/mp4",
    })
}

/// Plain text: valid UTF-8 (a multi-byte sequence cut off at the sniff
/// boundary is allowed) without control bytes other than whitespace.
fn looks_like_text(head: &[u8]) -> bool {
    if head.is_empty() {
        return false;
    }
    let valid = match std::str::from_utf8(head) {
        Ok(_) => true,
        Err(error) => error.error_len().is_none() && error.valid_up_to() + 4 > head.len(),
    };
    valid && !head.iter().any(|&b| b < 0x20 && !matches!(b, b'\n' | b'\r' | b'\t' | 0x0c))
}

/// What the content itself says it is, or `None` when unrecognised.
fn content_type_from_magic(head: &[u8], ext: &str) -> Option<&'static str> {
    let starts = |magic: &[u8]| head.len() >= magic.len() && &head[..magic.len()] == magic;
    if starts(b"\xFF\xD8\xFF") {
        return Some("image/jpeg");
    }
    if starts(b"\x89PNG\r\n\x1a\n") {
        return Some("image/png");
    }
    if starts(b"GIF87a") || starts(b"GIF89a") {
        return Some("image/gif");
    }
    if starts(b"BM") && head.len() >= 14 && ext == "bmp" {
        return Some("image/bmp");
    }
    if starts(b"%PDF-") {
        return Some("application/pdf");
    }
    if head.len() >= 12 && starts(b"RIFF") {
        return match &head[8..12] {
            b"WEBP" => Some("image/webp"),
            b"WAVE" => Some("audio/wav"),
            b"AVI " => Some("video/x-msvideo"),
            _ => None,
        };
    }
    if let Some(found) = iso_bmff(head) {
        return Some(found);
    }
    if starts(b"\x1A\x45\xDF\xA3") {
        // Matroska and WebM share EBML; the DocType says which.
        let window = &head[..head.len().min(64)];
        let is_webm = window.windows(4).any(|w| w == b"webm");
        return Some(if is_webm { "video/webm" } else { "video/x-matroska" });
    }
    if starts(b"ID3") {
        return Some("audio/mpeg");
    }
    if starts(b"fLaC") {
        return Some("audio/flac");
    }
    if starts(b"OggS") {
        return Some("audio/ogg");
    }
    if head.len() >= 2 && head[0] == 0xFF && (head[1] & 0xF6) == 0xF0 {
        return Some("audio/aac"); // ADTS
    }
    if head.len() >= 2 && head[0] == 0xFF && (head[1] & 0xE0) == 0xE0 {
        return Some("audio/mpeg"); // MPEG audio frame sync, no ID3 tag
    }
    if starts(b"7z\xBC\xAF\x27\x1C") {
        return Some("application/x-7z-compressed");
    }
    if starts(b"Rar!\x1A\x07") {
        return Some("application/vnd.rar");
    }
    if starts(b"\x1F\x8B") {
        return Some("application/gzip");
    }
    if starts(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
        return Some("application/x-ole-storage"); // legacy .doc / .xls / .ppt
    }
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") {
        // Office Open XML and OpenDocument are ZIP files; only the name can
        // narrow a ZIP down, and only to a format that is a ZIP.
        return Some(match ext {
            "docx" | "xlsx" | "pptx" => content_type_for_extension(ext).unwrap_or("application/zip"),
            "odt" => "application/vnd.oasis.opendocument.text",
            "ods" => "application/vnd.oasis.opendocument.spreadsheet",
            "odp" => "application/vnd.oasis.opendocument.presentation",
            _ => "application/zip",
        });
    }
    if looks_like_text(head) {
        return Some(match ext {
            "csv" => "text/csv",
            "json" => "application/json",
            _ => "text/plain",
        });
    }
    None
}

/// Same family: the extension and the content name the same kind of thing even
/// if the precise subtype differs (an `.m4v` that is `video/mp4`, a `.zip`
/// holding a DOCX, a `.log` that is text).
fn compatible(ext_type: &str, detected: &str) -> bool {
    if ext_type == detected {
        return true;
    }
    let zip_family = |t: &str| t == "application/zip" || t.starts_with("application/vnd.openxmlformats") || t.starts_with("application/vnd.oasis");
    if zip_family(ext_type) && zip_family(detected) {
        return true;
    }
    let text_family = |t: &str| t.starts_with("text/") || t == "application/json";
    if text_family(ext_type) && text_family(detected) {
        return true;
    }
    // An ISO-BMFF brand is a hint, not a guarantee: .mp4 / .m4a / .mov overlap.
    let bmff = |t: &str| matches!(t, "video/mp4" | "video/quicktime" | "audio/mp4");
    bmff(ext_type) && bmff(detected)
}

/// Classify a file from its first bytes (see [`SNIFF_LEN`]) and its name.
pub fn sniff(head: &[u8], name: &str) -> Detected {
    let ext = extension_of(name);
    match content_type_from_magic(head, &ext) {
        Some(content_type) => {
            let type_check = match content_type_for_extension(&ext) {
                Some(claimed) if compatible(claimed, content_type) => TypeCheck::Match,
                Some(_) => TypeCheck::Mismatch,
                None => TypeCheck::Unknown,
            };
            Detected {
                content_type: content_type.to_string(),
                category: category_for(content_type),
                type_check,
            }
        }
        None => Detected {
            content_type: "application/octet-stream".to_string(),
            category: Category::Other,
            type_check: TypeCheck::Unknown,
        },
    }
}

/// Whether the vault will decrypt this type into memory for an in-app preview.
/// Everything else can only be exported. PDFs, Office files and archives are
/// never rendered in-app: the app's content security policy (rightly) allows no
/// framed documents, the Android WebView has no PDF renderer, and nothing is
/// ever sent to an external preview service. Images, audio and video play from
/// an in-memory blob; text is shown as text.
pub fn previewable(content_type: &str) -> bool {
    matches!(
        content_type,
        "image/jpeg" | "image/png" | "image/gif" | "image/webp" | "image/bmp" | "image/avif"
            | "video/mp4" | "video/webm" | "video/quicktime"
            | "audio/mpeg" | "audio/wav" | "audio/aac" | "audio/mp4" | "audio/flac" | "audio/ogg"
            | "text/plain" | "text/csv" | "application/json"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_decides_the_type_not_the_extension() {
        let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
        let detected = sniff(png, "holiday.png");
        assert_eq!(detected.content_type, "image/png");
        assert_eq!(detected.category, Category::Image);
        assert_eq!(detected.type_check, TypeCheck::Match);

        // A PNG named as a PDF is a PNG, and the disagreement is reported.
        let disguised = sniff(png, "invoice.pdf");
        assert_eq!(disguised.content_type, "image/png");
        assert_eq!(disguised.type_check, TypeCheck::Mismatch);

        // An executable renamed to .jpg is not an image.
        let exe = sniff(b"MZ\x90\0\x03\0\0\0\x04\0\0\0\xFF\xFF\0\0", "cat.jpg");
        assert_eq!(exe.category, Category::Other);
        assert_eq!(exe.content_type, "application/octet-stream");
        assert!(!previewable(&exe.content_type));
    }

    #[test]
    fn recognises_the_supported_families() {
        let cases: &[(&[u8], &str, &str, Category)] = &[
            (b"\xFF\xD8\xFF\xE0\0\x10JFIF", "a.jpeg", "image/jpeg", Category::Image),
            (b"RIFF\0\0\0\0WEBPVP8 ", "a.webp", "image/webp", Category::Image),
            (b"\0\0\0\x18ftypheic\0\0\0\0", "a.heic", "image/heic", Category::Image),
            (b"%PDF-1.7\n", "a.pdf", "application/pdf", Category::Document),
            (b"\0\0\0\x20ftypisom\0\0\x02\0", "a.mp4", "video/mp4", Category::Video),
            (b"\0\0\0\x14ftypqt  \0\0\0\0", "a.mov", "video/quicktime", Category::Video),
            (b"RIFF\0\0\0\0AVI LIST", "a.avi", "video/x-msvideo", Category::Video),
            (b"\x1A\x45\xDF\xA3\x9F\x42\x86\x81\x01\x42\x82\x84webm", "a.webm", "video/webm", Category::Video),
            (b"\x1A\x45\xDF\xA3\x9F\x42\x86\x81\x01\x42\x82\x88matroska", "a.mkv", "video/x-matroska", Category::Video),
            (b"ID3\x04\0\0\0\0\0\0", "a.mp3", "audio/mpeg", Category::Audio),
            (b"RIFF\0\0\0\0WAVEfmt ", "a.wav", "audio/wav", Category::Audio),
            (b"fLaC\0\0\0\x22", "a.flac", "audio/flac", Category::Audio),
            (b"\xFF\xF1\x50\x80", "a.aac", "audio/aac", Category::Audio),
            (b"7z\xBC\xAF\x27\x1C\0\x04", "a.7z", "application/x-7z-compressed", Category::Archive),
            (b"Rar!\x1A\x07\x01\0", "a.rar", "application/vnd.rar", Category::Archive),
            (b"PK\x03\x04\x14\0\x06\0", "a.zip", "application/zip", Category::Archive),
            (b"name,amount\nalice,3\n", "a.csv", "text/csv", Category::Document),
            (b"plain notes\r\n", "a.txt", "text/plain", Category::Document),
            (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\0\0", "a.doc", "application/x-ole-storage", Category::Document),
        ];
        for (head, name, content_type, category) in cases {
            let detected = sniff(head, name);
            assert_eq!(detected.content_type, *content_type, "{name}");
            assert_eq!(detected.category, *category, "{name}");
            assert_eq!(detected.type_check, TypeCheck::Match, "{name}");
        }
    }

    #[test]
    fn office_open_xml_is_named_only_when_the_content_is_a_zip() {
        let zip = b"PK\x03\x04\x14\0\x06\0";
        let docx = sniff(zip, "report.docx");
        assert_eq!(docx.category, Category::Document);
        assert_eq!(docx.type_check, TypeCheck::Match);
        // A ".docx" that is not a ZIP is not a Word document.
        let fake = sniff(b"%PDF-1.4", "report.docx");
        assert_eq!(fake.content_type, "application/pdf");
        assert_eq!(fake.type_check, TypeCheck::Mismatch);
    }

    #[test]
    fn unknown_content_is_never_guessed_from_the_name() {
        let detected = sniff(&[0u8, 1, 2, 3, 0xFE, 0xFD], "song.mp3");
        assert_eq!(detected.content_type, "application/octet-stream");
        assert_eq!(detected.category, Category::Other);
        assert_eq!(detected.type_check, TypeCheck::Unknown);
        assert_eq!(sniff(&[], "empty.txt").category, Category::Other);
    }

    #[test]
    fn extensions_are_parsed_conservatively() {
        assert_eq!(extension_of("a.PDF"), "pdf");
        assert_eq!(extension_of(".env"), "");
        assert_eq!(extension_of("noext"), "");
        assert_eq!(extension_of("archive.tar.gz"), "gz");
    }
}
