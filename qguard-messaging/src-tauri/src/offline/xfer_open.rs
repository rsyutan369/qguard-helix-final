//! Open only an export that belongs to an authorized, integrity-verified receipt.
//! The renderer supplies a record ID and file index, never a path or a URI.

use std::{io::Read, path::Path};

use serde::Deserialize;
use tauri::{AppHandle, Manager};
use uuid::Uuid;

use crate::{
    crypto::provider::{self, Sha3_256Hasher},
    error::{QGuardError, Result},
    state::AppState,
};

use super::{
    profile::local_owner,
    transfer,
    xfer::{Direction, FileManifest, Record, Status},
};

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum XferOpenTarget {
    File,
    Folder,
}

struct SavedExport<'a> {
    manifest: &'a FileManifest,
    display: &'a str,
    #[cfg(target_os = "android")]
    uri: &'a str,
}

fn saved_export(record: &Record, index: usize) -> Option<SavedExport<'_>> {
    if record.direction != Direction::Incoming || record.status != Status::Verified {
        return None;
    }
    let manifest = record.manifest.files.get(index)?;
    let display = record.destinations.get(index)?.as_deref()?;
    #[cfg(not(target_os = "android"))]
    if !absolute_local_path(Path::new(display)) {
        return None;
    }
    #[cfg(target_os = "android")]
    let uri = record.android_destinations.get(&(index as u32))?.as_str();
    #[cfg(target_os = "android")]
    if !valid_download_uri(uri) {
        return None;
    }
    Some(SavedExport {
        manifest,
        display,
        #[cfg(target_os = "android")]
        uri,
    })
}

/// Snapshot hint only. Opening rechecks the saved object, bytes and account.
pub(super) fn export_actions(record: &Record, index: usize) -> (bool, bool) {
    saved_export(record, index).map_or((false, false), |saved| (saved.viewer().is_some(), true))
}

impl SavedExport<'_> {
    fn viewer(&self) -> Option<ViewerFormat> {
        let format = ViewerFormat::for_path(Path::new(self.display))?;
        (ViewerFormat::for_path(Path::new(&self.manifest.path)) == Some(format)).then_some(format)
    }
}

#[tauri::command]
pub(crate) async fn offline_xfer_open(
    app: AppHandle,
    id: Uuid,
    file: u32,
    target: XferOpenTarget,
    expected_account: String,
) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        require_owner(&app, &expected_account)?;
        let record = transfer::with_store(&app, &expected_account, |store| store.get(id))?;
        let saved = saved_export(&record, file as usize).ok_or_else(|| {
            QGuardError::Trust("Save a verified copy to your device before opening it.".into())
        })?;
        let viewer = match target {
            XferOpenTarget::Folder => None,
            XferOpenTarget::File => Some(saved.viewer().ok_or_else(unsupported_format)?),
        };
        launch_export(&app, &expected_account, saved, viewer)
    })
    .await
    .map_err(|_| QGuardError::Storage("Could not open the saved transfer export.".into()))?
}

fn require_owner(app: &AppHandle, expected: &str) -> Result<()> {
    if local_owner(&app.state::<AppState>())? != expected {
        return Err(QGuardError::Trust("The local account changed.".into()));
    }
    Ok(())
}

fn unsupported_format() -> QGuardError {
    QGuardError::InvalidInput(
        "This file type cannot be opened from XFER. Use Open folder to find the saved copy.".into(),
    )
}

fn missing_export() -> QGuardError {
    QGuardError::NotFound("The saved copy was moved or removed. Save a new copy to open it.".into())
}

fn changed_export() -> QGuardError {
    QGuardError::Trust(
        "The saved copy has changed since verification. Save a fresh copy before opening it."
            .into(),
    )
}

#[cfg(not(target_os = "android"))]
fn absolute_local_path(path: &Path) -> bool {
    use std::path::Component;
    #[cfg(windows)]
    {
        use std::path::Prefix;
        if !matches!(
            path.components().next(),
            Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        ) {
            return false;
        }
    }
    // An exact destination never needs `.` or `..`. Reject them before any
    // filesystem call: Win32 resolves `..` lexically and verbatim (`\\?\`)
    // paths do not resolve it at all.
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

#[cfg(not(target_os = "android"))]
fn checked_export_path(path: &Path) -> Result<std::fs::Metadata> {
    use super::xfer::{checked_metadata, validate_relative_path};

    if !absolute_local_path(path) {
        return Err(missing_export());
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(missing_export)?;
    validate_relative_path(name).map_err(|_| missing_export())?;
    let metadata = checked_metadata(path).map_err(|_| missing_export())?;
    if !metadata.is_file() || path.canonicalize().map_err(|_| missing_export())? != path {
        return Err(missing_export());
    }
    Ok(metadata)
}

#[cfg(not(target_os = "android"))]
fn launch_export(
    app: &AppHandle,
    owner: &str,
    saved: SavedExport<'_>,
    viewer: Option<ViewerFormat>,
) -> Result<()> {
    use tauri_plugin_shell::ShellExt;

    let file = Path::new(saved.display);
    let metadata = checked_export_path(file)?;
    let target = if let Some(format) = viewer {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 != 0 {
                return Err(unsupported_format());
            }
        }
        let input = super::xfer::read_file(file, &metadata).map_err(|_| changed_export())?;
        verify_copy(input, saved.manifest, format)?;
        file
    } else {
        file.parent().ok_or_else(missing_export)?
    };

    require_owner(app, owner)?;
    // A pathname is handed to the OS, so check again after hashing the opened file.
    checked_export_path(file)?;
    let target = target.to_str().ok_or_else(missing_export)?;
    #[cfg(windows)]
    let target = target.strip_prefix(r"\\?\").unwrap_or(target);
    #[allow(deprecated)]
    app.shell().open(target, None).map_err(|_| {
        QGuardError::Storage("The system could not open the saved transfer export.".into())
    })
}

#[cfg(any(target_os = "android", test))]
fn valid_download_uri(value: &str) -> bool {
    let Some(tail) = value.strip_prefix("content://media/") else {
        return false;
    };
    let mut segments = tail.split('/');
    matches!(segments.next(), Some("external" | "external_primary"))
        && segments.next() == Some("downloads")
        && segments.next().is_some_and(|id| {
            id.bytes().all(|byte| byte.is_ascii_digit()) && id.parse::<u64>().is_ok_and(|id| id > 0)
        })
        && segments.next().is_none()
}

#[cfg(target_os = "android")]
fn launch_export(
    app: &AppHandle,
    owner: &str,
    saved: SavedExport<'_>,
    viewer: Option<ViewerFormat>,
) -> Result<()> {
    use crate::security::{
        android_bridge::{call_static_string, in_band},
        content_uri,
    };

    fn call(method: &str, args: &[&str]) -> Result<()> {
        let result = call_static_string("com.qguard.messaging.DownloadsStore", method, args)
            .map_err(QGuardError::Storage)?;
        in_band(result).map_err(QGuardError::Storage)?;
        Ok(())
    }

    if let Some(format) = viewer {
        call("checkXferExport", &[saved.uri, saved.display])?;
        verify_copy(content_uri::open_read(saved.uri)?, saved.manifest, format)?;
    }
    require_owner(app, owner)?;
    call(
        "openXferExport",
        &[
            saved.uri,
            saved.display,
            viewer.map(ViewerFormat::mime).unwrap_or(""),
        ],
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewerFormat {
    Pdf,
    Png,
    Jpeg,
    Gif,
    WebP,
    Text,
    Wav,
    Mp3,
    Mp4,
}

impl ViewerFormat {
    fn for_path(path: &Path) -> Option<Self> {
        Some(
            match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
                "pdf" => Self::Pdf,
                "png" => Self::Png,
                "jpg" | "jpeg" => Self::Jpeg,
                "gif" => Self::Gif,
                "webp" => Self::WebP,
                "txt" => Self::Text,
                "wav" => Self::Wav,
                "mp3" => Self::Mp3,
                "mp4" | "m4v" => Self::Mp4,
                _ => return None,
            },
        )
    }

    fn matches_header(self, bytes: &[u8]) -> bool {
        match self {
            Self::Pdf => bytes.starts_with(b"%PDF-"),
            Self::Png => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
            Self::Jpeg => bytes.starts_with(b"\xff\xd8\xff"),
            Self::Gif => bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
            Self::WebP => bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP"),
            Self::Text => {
                let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
                ![b"#!".as_slice(), b"<", b"[Desktop Entry]"]
                    .iter()
                    .any(|prefix| bytes.starts_with(prefix))
            }
            Self::Wav => bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WAVE"),
            Self::Mp3 => {
                bytes.starts_with(b"ID3")
                    || matches!(bytes, [0xff, marker, ..] if marker & 0xe0 == 0xe0)
            }
            Self::Mp4 => bytes.get(4..8) == Some(b"ftyp"),
        }
    }

    #[cfg(target_os = "android")]
    fn mime(self) -> &'static str {
        match self {
            Self::Pdf => "application/pdf",
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::WebP => "image/webp",
            Self::Text => "text/plain",
            Self::Wav => "audio/wav",
            Self::Mp3 => "audio/mpeg",
            Self::Mp4 => "video/mp4",
        }
    }
}

fn verify_copy(reader: impl Read, file: &FileManifest, viewer: ViewerFormat) -> Result<()> {
    let mut input = reader.take(file.size.saturating_add(1));
    let mut header = Vec::with_capacity(16);
    Read::take(&mut input, 16)
        .read_to_end(&mut header)
        .map_err(|_| changed_export())?;
    if !viewer.matches_header(&header) {
        return Err(unsupported_format());
    }

    let mut verified_bytes = header.len() as u64;
    let mut hash = Sha3_256Hasher::new();
    let mut buffer = vec![0; 64 * 1024];
    let mut block = header.as_slice();
    loop {
        if viewer == ViewerFormat::Text
            && block.iter().any(|byte| {
                byte.is_ascii_control() && !matches!(byte, b'\t' | b'\n' | b'\r' | 0x0c)
            })
        {
            return Err(unsupported_format());
        }
        hash.update(block);
        let count = input.read(&mut buffer).map_err(|_| changed_export())?;
        if count == 0 {
            break;
        }
        verified_bytes += count as u64;
        block = &buffer[..count];
    }
    if verified_bytes != file.size
        || !provider::constant_time_eq(
            hex::encode(hash.finalize()).as_bytes(),
            file.digest.as_bytes(),
        )
    {
        return Err(changed_export());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_executable_suffixes_have_no_viewer() {
        for path in [
            "invoice.pdf.exe",
            "launch.desktop",
            "report.docm",
            "web.svg",
            "sample.pdf ",
        ] {
            assert!(ViewerFormat::for_path(Path::new(path)).is_none());
        }
        assert!(ViewerFormat::for_path(Path::new("photo.JPEG")) == Some(ViewerFormat::Jpeg));
    }

    #[test]
    fn verification_rejects_changed_bytes_and_content_disguised_as_viewable() {
        let bytes = b"%PDF-1.7\nexample";
        let manifest = FileManifest {
            path: "sample.pdf".into(),
            size: bytes.len() as u64,
            chunks: 1,
            digest: hex::encode(provider::sha3_256(bytes)),
        };
        assert!(verify_copy(bytes.as_slice(), &manifest, ViewerFormat::Pdf).is_ok());
        assert!(verify_copy(
            b"%PDF-1.7\ndifferent".as_slice(),
            &manifest,
            ViewerFormat::Pdf
        )
        .is_err());
        assert!(verify_copy(
            b"MZ\x00\x00payload".as_slice(),
            &manifest,
            ViewerFormat::Pdf
        )
        .is_err());
        assert!(verify_copy(b"#!/bin/sh\n".as_slice(), &manifest, ViewerFormat::Text).is_err());
    }

    #[test]
    fn media_uri_requires_an_exact_download_row() {
        assert!(valid_download_uri("content://media/external/downloads/123"));
        assert!(valid_download_uri(
            "content://media/external_primary/downloads/1"
        ));
        for uri in [
            "content://media/external/downloads",
            "content://media/external/downloads/0",
            "content://media/external/downloads/123?foo=1",
            "content://media/external/downloads/%31",
            "content://media/external/images/123",
            "content://other/external/downloads/123",
        ] {
            assert!(!valid_download_uri(uri), "{uri}");
        }
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn desktop_destination_must_be_an_exact_existing_local_file() {
        assert!(checked_export_path(Path::new("relative.pdf")).is_err());
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        assert!(checked_export_path(&root).is_err());
        let file = root.join("report.pdf");
        assert!(checked_export_path(&file).is_err());
        std::fs::write(&file, b"%PDF-1.7").unwrap();
        assert!(checked_export_path(&file).is_ok());
        std::fs::create_dir(root.join("subdir")).unwrap();
        // `PathBuf::join` normalizes `..` away on Windows verbatim (`\\?\`)
        // paths, so build each traversal form from text to keep it intact.
        let separator = std::path::MAIN_SEPARATOR;
        let canonical = root.display().to_string();
        let mut bases = vec![canonical.clone()];
        if let Some(plain) = canonical.strip_prefix(r"\\?\") {
            bases.push(plain.to_owned());
        }
        for base in bases {
            for traversal in [
                format!("{base}{separator}subdir{separator}..{separator}report.pdf"),
                format!("{base}{separator}.{separator}report.pdf"),
            ] {
                assert!(
                    checked_export_path(Path::new(&traversal)).is_err(),
                    "{traversal}"
                );
            }
        }
    }
}
