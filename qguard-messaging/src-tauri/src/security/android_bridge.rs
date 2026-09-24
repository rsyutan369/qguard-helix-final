//! JNI plumbing shared by the app's own Kotlin helpers (`com.qguard.messaging.*`).
//!
//! Every helper is a Kotlin `object` exposing `@JvmStatic` methods shaped
//! `(Context, String...) -> String`. Two rules hold for all of them, and both
//! have already broken a feature once:
//!
//! - App classes are loaded through the ACTIVITY's class loader. `FindClass` on
//!   a native thread only sees framework classes, so it cannot find ours.
//! - The Kotlin method must return String, never Unit. The lookup uses a
//!   String-returning descriptor; a void method has a different one and fails
//!   with NoSuchMethodError (VaultFolderPicker.reset shipped exactly that bug).
//!
//! Failures come back in-band as `error:<reason>` so no Java exception has to
//! cross the boundary; [`in_band`] turns that into an `Err`.

/// `error:<reason>` -> `Err(reason)`; any other value -> `Ok(value)`.
#[cfg_attr(not(target_os = "android"), allow(dead_code))] // used by the android module and tests
pub(crate) fn in_band(value: String) -> std::result::Result<String, String> {
    match value.strip_prefix("error:") {
        Some(reason) => Err(reason.to_string()),
        None => Ok(value),
    }
}

/// JNI descriptor for a `(Context, String x arg_count) -> String` static method.
#[cfg_attr(not(target_os = "android"), allow(dead_code))] // used by the android module and tests
pub(crate) fn context_string_descriptor(arg_count: usize) -> String {
    let mut descriptor = String::from("(Landroid/content/Context;");
    for _ in 0..arg_count {
        descriptor.push_str("Ljava/lang/String;");
    }
    descriptor.push_str(")Ljava/lang/String;");
    descriptor
}

#[cfg(target_os = "android")]
pub(crate) use android::call_static_string;

#[cfg(target_os = "android")]
mod android {
    use jni::objects::{JClass, JObject, JString, JValue};
    use jni::JNIEnv;

    use super::context_string_descriptor;

    /// Run `f` on a JNI-attached thread with the app activity. Commands reach
    /// this from blocking-pool threads; Tauri initialises `ndk-context` with the
    /// app's JavaVM and activity before any command can run.
    fn with_activity<T>(
        f: impl FnOnce(&mut JNIEnv, &JObject) -> std::result::Result<T, String>,
    ) -> std::result::Result<T, String> {
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| format!("attach JavaVM: {e}"))?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|e| format!("attach JNI thread: {e}"))?;
        // ndk-context owns this global ref; JObject does not delete on drop.
        let activity = unsafe { JObject::from_raw(ctx.context().cast()) };
        let result = f(&mut env, &activity);
        // A pending Java exception aborts the process on the next JNI call.
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        result
    }

    fn load_app_class<'a>(
        env: &mut JNIEnv<'a>,
        activity: &JObject,
        class_name: &str,
    ) -> std::result::Result<JClass<'a>, String> {
        let loader = env
            .call_method(activity, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])
            .and_then(|v| v.l())
            .map_err(|e| format!("getClassLoader: {e}"))?;
        let name = env
            .new_string(class_name)
            .map_err(|e| format!("alloc class name: {e}"))?;
        let class = env
            .call_method(
                &loader,
                "loadClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                &[JValue::Object(&name)],
            )
            .and_then(|v| v.l())
            .map_err(|e| format!("loadClass({class_name}): {e}"))?;
        Ok(JClass::from(class))
    }

    /// Call `class_name.method(context, args...)` and return its String result
    /// (a Kotlin null reads as ""). The in-band `error:` convention is left to
    /// the caller, which knows what the failure means.
    pub(crate) fn call_static_string(
        class_name: &str,
        method: &str,
        args: &[&str],
    ) -> std::result::Result<String, String> {
        with_activity(|env, activity| {
            let class = load_app_class(env, activity, class_name)?;
            let mut locals = Vec::with_capacity(args.len());
            for arg in args {
                locals.push(
                    env.new_string(*arg)
                        .map_err(|e| format!("alloc argument: {e}"))?,
                );
            }
            let mut values = vec![JValue::Object(activity)];
            for local in &locals {
                values.push(JValue::Object(local));
            }
            let descriptor = context_string_descriptor(args.len());
            let value = env
                .call_static_method(&class, method, descriptor.as_str(), &values)
                .and_then(|v| v.l())
                .map_err(|e| format!("{method}: {e}"))?;
            if value.is_null() {
                return Ok(String::new());
            }
            // Bound to a local: the JavaStr borrows it until converted.
            let jstr = JString::from(value);
            let text: String = env
                .get_string(&jstr)
                .map_err(|e| format!("read {method} result: {e}"))?
                .into();
            Ok(text)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_match_the_kotlin_signatures() {
        assert_eq!(
            context_string_descriptor(0),
            "(Landroid/content/Context;)Ljava/lang/String;"
        );
        assert_eq!(
            context_string_descriptor(2),
            "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"
        );
    }

    #[test]
    fn in_band_errors_become_err() {
        assert_eq!(in_band("content://x/1".to_string()), Ok("content://x/1".to_string()));
        assert_eq!(in_band("error:disk full".to_string()), Err("disk full".to_string()));
        assert_eq!(in_band("ok".to_string()), Ok("ok".to_string()));
    }
}
