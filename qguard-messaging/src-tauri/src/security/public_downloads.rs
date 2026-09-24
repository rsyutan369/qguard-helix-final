//! Android public Downloads bridge (MediaStore), driving `DownloadsStore.kt`.
//!
//! Android's WebView silently drops `<a download>` clicks on blob URLs, so every
//! "save to device" action in the app used to report success on Android while
//! writing nothing. This module is the native replacement: it inserts a pending
//! row into `MediaStore.Downloads` (under `Download/QGuard/`), and the caller
//! streams the bytes into that row through the content-resolver fd bridge
//! (`content_uri::open_write_truncate`) before publishing it with [`finish`].
//!
//! Desktop builds get stubs: there the WebView's own download manager already
//! saves into the Downloads folder, so the frontend never calls these.

use crate::error::{QGuardError, Result};

/// A file that is now visible in the public Downloads collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedDownload {
    /// Final name; MediaStore may have de-duplicated the requested one.
    pub name: String,
    /// Folder inside shared storage, e.g. `Download/QGuard`.
    pub relative_path: String,
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))] // used by the android module and tests
fn downloads_err(context: &str, detail: impl std::fmt::Display) -> QGuardError {
    QGuardError::Storage(format!("save to Downloads ({context}): {detail}"))
}

/// Parse `DownloadsStore.finish`'s JSON answer.
#[cfg_attr(not(target_os = "android"), allow(dead_code))] // used by the android module and tests
fn parse_published(raw: &str) -> Result<PublishedDownload> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| downloads_err("read result", e))?;
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .trim()
        .to_string();
    if name.is_empty() {
        return Err(downloads_err("read result", "the saved file reported no name"));
    }
    let relative_path = value
        .get("relativePath")
        .and_then(|v| v.as_str())
        .unwrap_or("Download/QGuard")
        .trim_end_matches('/')
        .to_string();
    Ok(PublishedDownload { name, relative_path })
}

#[cfg(target_os = "android")]
pub use android::{abort, begin, finish};

#[cfg(not(target_os = "android"))]
pub use stubs::{abort, begin, finish};

#[cfg(target_os = "android")]
mod android {
    use super::{downloads_err, parse_published, PublishedDownload};
    use crate::error::Result;
    use crate::security::android_bridge::{call_static_string, in_band};

    const STORE_CLASS: &str = "com.qguard.messaging.DownloadsStore";

    fn call(method: &str, args: &[&str]) -> Result<String> {
        let raw = call_static_string(STORE_CLASS, method, args).map_err(|e| downloads_err(method, e))?;
        in_band(raw).map_err(|reason| downloads_err(method, reason))
    }

    /// Insert a pending row; returns its `content://` URI.
    pub fn begin(display_name: &str, mime_type: &str) -> Result<String> {
        call("begin", &[display_name, mime_type])
    }

    /// Clear the pending flag and report where the file ended up.
    pub fn finish(uri: &str) -> Result<PublishedDownload> {
        parse_published(&call("finish", &[uri])?)
    }

    /// Delete a row that was never completed.
    pub fn abort(uri: &str) -> Result<()> {
        call("abort", &[uri]).map(|_| ())
    }
}

#[cfg(not(target_os = "android"))]
mod stubs {
    use super::PublishedDownload;
    use crate::error::{QGuardError, Result};

    fn unsupported() -> QGuardError {
        QGuardError::InvalidInput(
            "saving through the Android Downloads collection is only available on Android".to_string(),
        )
    }

    pub fn begin(_display_name: &str, _mime_type: &str) -> Result<String> {
        Err(unsupported())
    }

    pub fn finish(_uri: &str) -> Result<PublishedDownload> {
        Err(unsupported())
    }

    pub fn abort(_uri: &str) -> Result<()> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_name_mediastore_settled_on() {
        let published =
            parse_published(r#"{"name":"report (1).pdf","relativePath":"Download/QGuard/"}"#).unwrap();
        assert_eq!(
            published,
            PublishedDownload {
                name: "report (1).pdf".to_string(),
                relative_path: "Download/QGuard".to_string(),
            }
        );
    }

    #[test]
    fn a_result_without_a_name_is_an_error_not_a_blank_success() {
        assert!(parse_published(r#"{"name":"","relativePath":"Download/QGuard"}"#).is_err());
        assert!(parse_published("not json").is_err());
    }

    #[test]
    fn a_missing_folder_falls_back_to_the_folder_begin_uses() {
        let published = parse_published(r#"{"name":"a.txt"}"#).unwrap();
        assert_eq!(published.relative_path, "Download/QGuard");
    }
}
