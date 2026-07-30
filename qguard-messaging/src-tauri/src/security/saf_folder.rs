//! Android Storage Access Framework destination-folder bridge.
//!
//! The Tauri dialog plugin ships no mobile folder picker, so the Quantum Vault
//! could not ask "where should I put this file?" on Android. This module drives
//! `VaultFolderPicker.kt` over JNI: it opens the system folder picker, waits for
//! the Activity result, and then creates named documents inside the granted
//! tree. The grant is persisted on the Kotlin side, so a folder chosen once
//! keeps working after an app restart — which is what makes it safe to store
//! registry-tracked `.qvault` containers there.
//!
//! Desktop builds get stubs: there, the frontend uses the native directory
//! dialog and plain filesystem paths, so no call site needs a `cfg`.

/// True for a SAF *tree* URI — a folder the user granted access to, as opposed
/// to a single `content://` document.
pub fn is_tree_uri(value: &str) -> bool {
    value.starts_with("content://") && value.contains("/tree/")
}

/// Outcome of a destination-folder prompt.
pub struct FolderChoice {
    /// SAF tree URI (Android) or filesystem path (desktop).
    pub path: String,
    /// Human-readable location for logs and the UI.
    pub label: String,
}

#[cfg(target_os = "android")]
pub use android::{create_document_in_tree, delete_document, describe_folder, pick_folder};

#[cfg(not(target_os = "android"))]
pub use stubs::{create_document_in_tree, delete_document, describe_folder, pick_folder};

#[cfg(target_os = "android")]
mod android {
    use std::time::{Duration, Instant};

    use jni::objects::{JObject, JString, JValue};
    use jni::JNIEnv;

    use super::FolderChoice;
    use crate::error::{QGuardError, Result};

    const PICKER_CLASS: &str = "com.qguard.messaging.VaultFolderPicker";
    /// The user is choosing a folder by hand — allow a generous window, but
    /// never wait forever (a killed picker Activity would leak the worker).
    const PICK_TIMEOUT: Duration = Duration::from_secs(300);
    const POLL_INTERVAL: Duration = Duration::from_millis(150);

    fn picker_err(context: &str, detail: impl std::fmt::Display) -> QGuardError {
        QGuardError::Storage(format!("vault folder picker {context}: {detail}"))
    }

    fn with_env<T>(f: impl FnOnce(&mut JNIEnv, &JObject) -> Result<T>) -> Result<T> {
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| picker_err("attach JavaVM", e))?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|e| picker_err("attach JNI thread", e))?;
        // ndk-context owns this global ref; JObject does not delete on drop.
        let activity = unsafe { JObject::from_raw(ctx.context().cast()) };
        let result = f(&mut env, &activity);
        // A pending Java exception aborts the process on the next JNI call.
        if result.is_err() && env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        result
    }

    /// Loads the picker class through the APP class loader — `find_class` on a
    /// native (non-Java) thread only ever sees system classes.
    fn load_class<'a>(env: &mut JNIEnv<'a>, activity: &JObject) -> Result<jni::objects::JClass<'a>> {
        let loader = env
            .call_method(activity, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])
            .and_then(|v| v.l())
            .map_err(|e| picker_err("getClassLoader", e))?;
        let name = env
            .new_string(PICKER_CLASS)
            .map_err(|e| picker_err("alloc class name", e))?;
        let class = env
            .call_method(
                &loader,
                "loadClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                &[JValue::Object(&name)],
            )
            .and_then(|v| v.l())
            .map_err(|e| picker_err("loadClass(VaultFolderPicker)", e))?;
        Ok(jni::objects::JClass::from(class))
    }

    fn read_string(env: &mut JNIEnv, value: JObject) -> Result<String> {
        if value.is_null() {
            return Ok(String::new());
        }
        let jstr = JString::from(value);
        let text = env
            .get_string(&jstr)
            .map_err(|e| picker_err("read result string", e))?;
        Ok(text.into())
    }

    /// Static method taking (Context) and returning String.
    fn call_context_string(method: &str) -> Result<String> {
        with_env(|env, activity| {
            let class = load_class(env, activity)?;
            let value = env
                .call_static_method(
                    &class,
                    method,
                    "(Landroid/content/Context;)Ljava/lang/String;",
                    &[JValue::Object(activity)],
                )
                .and_then(|v| v.l())
                .map_err(|e| picker_err(method, e))?;
            read_string(env, value)
        })
    }

    /// Static method taking (Context, String...) and returning String.
    fn call_context_args_string(method: &str, args: &[&str]) -> Result<String> {
        with_env(|env, activity| {
            let class = load_class(env, activity)?;
            let mut locals = Vec::with_capacity(args.len());
            for arg in args {
                locals.push(
                    env.new_string(*arg)
                        .map_err(|e| picker_err("alloc argument", e))?,
                );
            }
            let mut values = vec![JValue::Object(activity)];
            for local in &locals {
                values.push(JValue::Object(local));
            }
            let signature = match args.len() {
                1 => "(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;",
                2 => "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                _ => return Err(picker_err(method, "unsupported argument count")),
            };
            let value = env
                .call_static_method(&class, method, signature, &values)
                .and_then(|v| v.l())
                .map_err(|e| picker_err(method, e))?;
            read_string(env, value)
        })
    }

    /// Kotlin returns `error:<reason>` in-band so a failed call never needs an
    /// exception round trip.
    fn unwrap_result(value: String, context: &str) -> Result<String> {
        match value.strip_prefix("error:") {
            Some(reason) => Err(picker_err(context, reason)),
            None => Ok(value),
        }
    }

    /// Blocking: open the folder picker and wait for the user's choice.
    /// MUST run on a blocking worker (the command layer uses `spawn_blocking`) —
    /// never on the main thread, which is the thread that has to deliver the
    /// Activity result we are waiting for.
    pub fn pick_folder() -> Result<Option<FolderChoice>> {
        let _ = call_context_string("reset")?;
        unwrap_result(call_context_string("launch")?, "launch")?;
        let deadline = Instant::now() + PICK_TIMEOUT;
        loop {
            let raw = call_context_string("getStateJson")?;
            let parsed: serde_json::Value = serde_json::from_str(&raw)
                .map_err(|e| picker_err("parse picker state", e))?;
            match parsed.get("state").and_then(|v| v.as_str()).unwrap_or("idle") {
                "selected" => {
                    let path = parsed
                        .get("uri")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if path.is_empty() {
                        return Err(picker_err("select", "the picker returned no folder"));
                    }
                    let label = parsed
                        .get("label")
                        .and_then(|v| v.as_str())
                        .filter(|value| !value.is_empty())
                        .unwrap_or(path.as_str())
                        .to_string();
                    let _ = call_context_string("reset");
                    return Ok(Some(FolderChoice { path, label }));
                }
                "cancelled" => {
                    let _ = call_context_string("reset");
                    return Ok(None);
                }
                "error" => {
                    let detail = parsed
                        .get("detail")
                        .and_then(|v| v.as_str())
                        .unwrap_or("the folder picker failed")
                        .to_string();
                    let _ = call_context_string("reset");
                    return Err(picker_err("select", detail));
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                let _ = call_context_string("reset");
                return Err(picker_err("select", "timed out waiting for a folder"));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Create `file_name` inside a granted tree; returns its document URI.
    pub fn create_document_in_tree(tree: &str, file_name: &str) -> Result<String> {
        unwrap_result(
            call_context_args_string("createDocument", &[tree, file_name])?,
            "create file",
        )
    }

    pub fn delete_document(document_uri: &str) -> Result<()> {
        unwrap_result(
            call_context_args_string("deleteDocument", &[document_uri])?,
            "delete file",
        )?;
        Ok(())
    }

    pub fn describe_folder(tree: &str) -> String {
        call_context_args_string("describeTree", &[tree]).unwrap_or_else(|_| tree.to_string())
    }
}

#[cfg(not(target_os = "android"))]
mod stubs {
    use super::FolderChoice;
    use crate::error::{QGuardError, Result};

    fn unsupported() -> QGuardError {
        QGuardError::InvalidInput(
            "the Storage Access Framework folder picker is only available on Android".to_string(),
        )
    }

    pub fn pick_folder() -> Result<Option<FolderChoice>> {
        Err(unsupported())
    }

    pub fn create_document_in_tree(_tree: &str, _file_name: &str) -> Result<String> {
        Err(unsupported())
    }

    pub fn delete_document(_document_uri: &str) -> Result<()> {
        Err(unsupported())
    }

    pub fn describe_folder(tree: &str) -> String {
        tree.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_tree_uris_only() {
        assert!(is_tree_uri(
            "content://com.android.externalstorage.documents/tree/primary%3ADownload"
        ));
        // A single-document URI is NOT a folder grant.
        assert!(!is_tree_uri(
            "content://com.android.providers.downloads.documents/document/msf%3A33"
        ));
        assert!(!is_tree_uri("C:\\Users\\me\\Documents"));
        assert!(!is_tree_uri("/storage/emulated/0/Download"));
    }
}
