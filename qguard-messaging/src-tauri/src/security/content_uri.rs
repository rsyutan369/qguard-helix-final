//! Android SAF `content://` URI bridge for vault streaming I/O.
//!
//! The Android file and save pickers (Storage Access Framework, reached through
//! the Tauri dialog plugin) return `content://` document URIs, not filesystem
//! paths — `std::fs` cannot open them (os error 2). This module resolves such
//! URIs to real file descriptors via `ContentResolver.openFileDescriptor` over
//! JNI, detaches the fd and wraps it in `std::fs::File`, so the streaming vault
//! crypto keeps its chunked zero-copy loop on multi-gigabyte files.
//!
//! Desktop builds get stub implementations: content URIs never occur there, so
//! the stubs only exist to keep call sites free of `cfg` branches.

/// True for Android Storage Access Framework document URIs.
pub fn is_content_uri(path: &str) -> bool {
    path.starts_with("content://")
}

/// Last URI path segment, percent-decoded — the fallback display name when the
/// content provider does not answer the DISPLAY_NAME query. Document ids often
/// embed encoded paths (`primary%3ADownload%2Freport.pdf`), so the decoded
/// value is split again to keep only the leaf name.
pub fn uri_tail(path: &str) -> String {
    let tail = path
        .split(['/', '\\'])
        .rev()
        .find(|segment| !segment.is_empty())
        .unwrap_or(path);
    let decoded = percent_decode(tail);
    decoded
        .split(['/', '\\'])
        .rev()
        .find(|segment| !segment.is_empty())
        .unwrap_or(&decoded)
        .to_string()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_content_uris() {
        assert!(is_content_uri(
            "content://com.android.providers.downloads.documents/document/msf%3A33"
        ));
        assert!(!is_content_uri("C:\\Users\\me\\file.txt"));
        assert!(!is_content_uri("/data/user/0/com.qguard.messaging/files/vault/x.qvault"));
    }

    #[test]
    fn uri_tail_decodes_document_ids() {
        assert_eq!(
            uri_tail("content://com.android.providers.downloads.documents/document/msf%3A33"),
            "msf:33"
        );
        assert_eq!(
            uri_tail("content://com.android.externalstorage.documents/document/primary%3ADownload%2Freport.pdf"),
            "primary:Download/report.pdf".split('/').next_back().unwrap()
        );
        assert_eq!(uri_tail("content://provider/doc/"), "doc");
    }
}

#[cfg(target_os = "android")]
pub use android::{open_read, open_write_truncate, stat};

#[cfg(not(target_os = "android"))]
pub use stubs::{open_read, open_write_truncate, stat};

#[cfg(target_os = "android")]
mod android {
    use crate::error::{QGuardError, Result};
    use jni::objects::{JObject, JString, JValue};
    use jni::JNIEnv;
    use std::fs::File;
    use std::os::fd::FromRawFd;

    const DISPLAY_NAME_COLUMN: &str = "_display_name"; // android.provider.OpenableColumns
    const SIZE_COLUMN: &str = "_size";

    fn storage_err(context: &str, detail: impl std::fmt::Display) -> QGuardError {
        QGuardError::Storage(format!("Android content resolver {context}: {detail}"))
    }

    /// Runs `f` with a JNIEnv attached to the current thread (vault streams run
    /// on blocking-pool threads). Tauri initializes `ndk-context` with the app's
    /// JavaVM before any command can run.
    fn with_env<T>(f: impl FnOnce(&mut JNIEnv) -> Result<T>) -> Result<T> {
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| storage_err("attach JavaVM", e))?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|e| storage_err("attach JNI thread", e))?;
        let result = f(&mut env);
        // A pending Java exception left on the thread aborts the process on the
        // next JNI call — always clear it once it has been converted to Err.
        if result.is_err() && env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        result
    }

    fn jni_err(env: &mut JNIEnv, context: &str, error: jni::errors::Error) -> QGuardError {
        let detail = if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
            format!("{error} (java exception)")
        } else {
            error.to_string()
        };
        storage_err(context, detail)
    }

    /// Converts a swallowed JNI failure into `None`, clearing any pending Java
    /// exception so later JNI calls on this thread do not abort the process.
    fn swallow<T>(env: &mut JNIEnv, result: jni::errors::Result<T>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(_) => {
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                None
            }
        }
    }

    fn content_resolver<'a>(env: &mut JNIEnv<'a>) -> Result<JObject<'a>> {
        let ctx = ndk_context::android_context();
        // ndk-context owns this global ref; JObject does not delete on drop.
        let context = unsafe { JObject::from_raw(ctx.context().cast()) };
        env.call_method(
            &context,
            "getContentResolver",
            "()Landroid/content/ContentResolver;",
            &[],
        )
        .and_then(|v| v.l())
        .map_err(|e| jni_err(env, "Context.getContentResolver", e))
    }

    fn parse_uri<'a>(env: &mut JNIEnv<'a>, uri: &str) -> Result<JObject<'a>> {
        let juri = env
            .new_string(uri)
            .map_err(|e| storage_err("alloc uri string", e))?;
        env.call_static_method(
            "android/net/Uri",
            "parse",
            "(Ljava/lang/String;)Landroid/net/Uri;",
            &[JValue::Object(&juri)],
        )
        .and_then(|v| v.l())
        .map_err(|e| jni_err(env, "Uri.parse", e))
    }

    fn open_fd(env: &mut JNIEnv, resolver: &JObject, uri: &JObject, mode: &str) -> Result<File> {
        let jmode = env
            .new_string(mode)
            .map_err(|e| storage_err("alloc mode string", e))?;
        let pfd = env
            .call_method(
                resolver,
                "openFileDescriptor",
                "(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;",
                &[JValue::Object(uri), JValue::Object(&jmode)],
            )
            .and_then(|v| v.l())
            .map_err(|e| jni_err(env, "ContentResolver.openFileDescriptor", e))?;
        if pfd.is_null() {
            return Err(storage_err(
                "openFileDescriptor",
                "provider returned no file descriptor",
            ));
        }
        let fd = env
            .call_method(&pfd, "detachFd", "()I", &[])
            .and_then(|v| v.i())
            .map_err(|e| jni_err(env, "ParcelFileDescriptor.detachFd", e))?;
        // detachFd transfers ownership of the raw fd to us.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Opens a `content://` URI for reading.
    pub fn open_read(uri: &str) -> Result<File> {
        with_env(|env| {
            let resolver = content_resolver(env)?;
            let uri_obj = parse_uri(env, uri)?;
            open_fd(env, &resolver, &uri_obj, "r")
        })
    }

    /// Opens a `content://` URI for writing, truncating existing content.
    /// Providers differ in which write modes they accept, so fall back through
    /// the truncating modes before plain write.
    pub fn open_write_truncate(uri: &str) -> Result<File> {
        with_env(|env| {
            let resolver = content_resolver(env)?;
            let uri_obj = parse_uri(env, uri)?;
            let mut last_error = None;
            for mode in ["wt", "rwt", "w"] {
                match open_fd(env, &resolver, &uri_obj, mode) {
                    Ok(file) => return Ok(file),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error
                .unwrap_or_else(|| storage_err("openFileDescriptor", "no supported write mode")))
        })
    }

    /// Queries the provider for the document's display name and size.
    /// Both are best-effort: providers may answer with nulls or nothing at all.
    pub fn stat(uri: &str) -> Result<(Option<String>, Option<u64>)> {
        with_env(|env| {
            let resolver = content_resolver(env)?;
            let uri_obj = parse_uri(env, uri)?;

            let string_class = env
                .find_class("java/lang/String")
                .map_err(|e| jni_err(env, "find String class", e))?;
            let projection = env
                .new_object_array(2, &string_class, JObject::null())
                .map_err(|e| jni_err(env, "alloc projection array", e))?;
            for (index, column) in [DISPLAY_NAME_COLUMN, SIZE_COLUMN].iter().enumerate() {
                let jcolumn = env
                    .new_string(column)
                    .map_err(|e| storage_err("alloc column name", e))?;
                env.set_object_array_element(&projection, index as i32, jcolumn)
                    .map_err(|e| jni_err(env, "fill projection array", e))?;
            }

            let cursor = env
                .call_method(
                    &resolver,
                    "query",
                    "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;",
                    &[
                        JValue::Object(&uri_obj),
                        JValue::Object(&projection),
                        JValue::Object(&JObject::null()),
                        JValue::Object(&JObject::null()),
                        JValue::Object(&JObject::null()),
                    ],
                )
                .and_then(|v| v.l())
                .map_err(|e| jni_err(env, "ContentResolver.query", e))?;
            if cursor.is_null() {
                return Ok((None, None));
            }

            let mut name = None;
            let mut size = None;
            let move_result = env
                .call_method(&cursor, "moveToFirst", "()Z", &[])
                .and_then(|v| v.z());
            let moved = swallow(env, move_result).unwrap_or(false);
            if moved {
                name = read_string_column(env, &cursor, DISPLAY_NAME_COLUMN);
                size = read_long_column(env, &cursor, SIZE_COLUMN);
            }
            let _ = env.call_method(&cursor, "close", "()V", &[]);
            Ok((name, size))
        })
    }

    fn column_index(env: &mut JNIEnv, cursor: &JObject, column: &str) -> Option<i32> {
        let name_result = env.new_string(column);
        let jcolumn = swallow(env, name_result)?;
        let index_result = env
            .call_method(
                cursor,
                "getColumnIndex",
                "(Ljava/lang/String;)I",
                &[JValue::Object(&jcolumn)],
            )
            .and_then(|v| v.i());
        let index = swallow(env, index_result)?;
        (index >= 0).then_some(index)
    }

    fn column_is_null(env: &mut JNIEnv, cursor: &JObject, index: i32) -> bool {
        let null_result = env
            .call_method(cursor, "isNull", "(I)Z", &[JValue::Int(index)])
            .and_then(|v| v.z());
        swallow(env, null_result).unwrap_or(true)
    }

    fn read_string_column(env: &mut JNIEnv, cursor: &JObject, column: &str) -> Option<String> {
        let index = column_index(env, cursor, column)?;
        if column_is_null(env, cursor, index) {
            return None;
        }
        let value_result = env
            .call_method(
                cursor,
                "getString",
                "(I)Ljava/lang/String;",
                &[JValue::Int(index)],
            )
            .and_then(|v| v.l());
        let value = swallow(env, value_result)?;
        if value.is_null() {
            return None;
        }
        let jstring = JString::from(value);
        let text_result = env.get_string(&jstring);
        let text: String = swallow(env, text_result)?.into();
        (!text.trim().is_empty()).then_some(text)
    }

    fn read_long_column(env: &mut JNIEnv, cursor: &JObject, column: &str) -> Option<u64> {
        let index = column_index(env, cursor, column)?;
        if column_is_null(env, cursor, index) {
            return None;
        }
        let value_result = env
            .call_method(cursor, "getLong", "(I)J", &[JValue::Int(index)])
            .and_then(|v| v.j());
        let value = swallow(env, value_result)?;
        (value >= 0).then_some(value as u64)
    }
}

#[cfg(not(target_os = "android"))]
mod stubs {
    use crate::error::{QGuardError, Result};
    use std::fs::File;

    fn unsupported() -> QGuardError {
        QGuardError::InvalidInput(
            "content:// paths are only supported on Android".to_string(),
        )
    }

    pub fn open_read(_uri: &str) -> Result<File> {
        Err(unsupported())
    }

    pub fn open_write_truncate(_uri: &str) -> Result<File> {
        Err(unsupported())
    }

    pub fn stat(_uri: &str) -> Result<(Option<String>, Option<u64>)> {
        Ok((None, None))
    }
}
