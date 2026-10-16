//! Subscription paywall platform bridge.
//!
//! Android: bridges to `com.qguard.messaging.PlayBilling` (Google Play Billing
//! Library) over JNI — launch a subscription purchase, refresh/restore owned
//! purchases, and read the billing state JSON the Kotlin side maintains. The
//! purchase token this yields is NEVER trusted locally: the frontend submits it
//! to the backend (`/api/v1/play-billing/verify`), which validates it with the
//! Google Play Developer API before activating the account's subscription.
//!
//! Desktop: purchases run through PayPal in the system browser
//! (`billing_open_checkout`); there is no local billing state.
//!
//! All commands are `async` — they must never run on the WebView main thread
//! (the same rule as the call/vault commands; JNI attach + Play service binds
//! would jank or deadlock the UI).

use serde_json::{json, Value};

use crate::error::{QGuardError, Result};

/// Which purchase rail this build uses.
#[tauri::command]
pub async fn billing_platform() -> Result<String> {
    #[cfg(target_os = "android")]
    {
        Ok("android".to_string())
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok("desktop".to_string())
    }
}

/// Open a payment/management URL in the system browser (desktop) or via an
/// intent (Android). HTTPS-only with a strict host allowlist so a compromised
/// renderer cannot use this command as an arbitrary URL launcher.
#[tauri::command]
pub async fn billing_open_checkout(app: tauri::AppHandle, url: String) -> Result<()> {
    let parsed = url::Url::parse(&url)
        .map_err(|_| QGuardError::InvalidInput("invalid checkout URL".to_string()))?;
    if parsed.scheme() != "https" {
        return Err(QGuardError::InvalidInput("checkout URL must be https".to_string()));
    }
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    // PayPal approval pages, Google Play subscription management, and the
    // public site PayPal returns the buyer to. (qguard.dev was listed here but
    // never existed; the site is qguardhelix.com.)
    let allowed = host == "www.paypal.com"
        || host == "paypal.com"
        || host == "www.sandbox.paypal.com"
        || host == "play.google.com"
        || host == "qguardhelix.com"
        || host == "www.qguardhelix.com";
    if !allowed {
        return Err(QGuardError::InvalidInput(format!(
            "checkout host not allowed: {host}"
        )));
    }
    use tauri_plugin_shell::ShellExt;
    // shell().open is deprecated in favor of the separate opener plugin, but it
    // remains fully functional on desktop AND Android (intent), and the shell
    // plugin is already part of this app — no reason to add a second plugin
    // dependency for one call.
    #[allow(deprecated)]
    app.shell()
        .open(url, None)
        .map_err(|e| QGuardError::Storage(format!("open checkout: {e}")))?;
    Ok(())
}

/// Current Play Billing state JSON (see PlayBilling.kt for the shape).
/// Desktop returns `{ "available": false }`.
#[tauri::command]
pub async fn billing_state() -> Result<Value> {
    #[cfg(target_os = "android")]
    {
        let raw = android::call_string("getStateJson")?;
        serde_json::from_str(&raw)
            .map_err(|e| QGuardError::Storage(format!("parse billing state: {e}")))
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(json!({ "available": false, "platform": "desktop" }))
    }
}

/// Launch the Google Play purchase flow for a subscription product.
/// `account_id` (the Supabase user id) becomes the obfuscatedAccountId so the
/// backend can bind the purchase to this account. `old_purchase_token` turns
/// the flow into an in-place plan change (prorated) instead of a second,
/// duplicate subscription.
#[tauri::command]
pub async fn billing_launch_purchase(
    product_id: String,
    base_plan_id: String,
    account_id: String,
    old_purchase_token: Option<String>,
) -> Result<()> {
    if product_id.is_empty() || base_plan_id.is_empty() || account_id.is_empty() {
        return Err(QGuardError::InvalidInput(
            "product, base plan, and account are required".to_string(),
        ));
    }
    #[cfg(target_os = "android")]
    {
        android::launch_purchase(&product_id, &base_plan_id, &account_id, old_purchase_token.as_deref())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (product_id, base_plan_id, account_id, old_purchase_token);
        Err(QGuardError::InvalidInput(
            "Google Play Billing is only available in the Android app".to_string(),
        ))
    }
}

/// Re-query owned subscription purchases from Google Play (Restore purchases).
/// The refreshed list lands in `billing_state`.
#[tauri::command]
pub async fn billing_refresh_purchases() -> Result<()> {
    #[cfg(target_os = "android")]
    {
        android::call_void("refreshPurchases")
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Android JNI bridge to com.qguard.messaging.PlayBilling
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
mod android {
    use jni::objects::{JObject, JString, JValue};
    use jni::JNIEnv;

    use crate::error::{QGuardError, Result};

    const PLAY_BILLING_CLASS: &str = "com.qguard.messaging.PlayBilling";

    fn billing_err(context: &str, detail: impl std::fmt::Display) -> QGuardError {
        QGuardError::Storage(format!("Play Billing {context}: {detail}"))
    }

    /// Runs `f` with a JNIEnv + the ndk-context object attached to this thread.
    /// That object is the APPLICATION context (tao >= 0.37), not the Activity;
    /// PlayBilling.launchPurchase resolves the Activity via CurrentActivity.
    fn with_env<T>(f: impl FnOnce(&mut JNIEnv, &JObject) -> Result<T>) -> Result<T> {
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| billing_err("attach JavaVM", e))?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|e| billing_err("attach JNI thread", e))?;
        let activity = unsafe { JObject::from_raw(ctx.context().cast()) };
        let result = f(&mut env, &activity);
        if result.is_err() && env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        result
    }

    /// Loads the PlayBilling class through the APP class loader — `find_class`
    /// on a native (non-Java) thread only sees system classes, never ours.
    fn load_class<'a>(env: &mut JNIEnv<'a>, activity: &JObject) -> Result<JObject<'a>> {
        let loader = env
            .call_method(activity, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])
            .and_then(|v| v.l())
            .map_err(|e| billing_err("getClassLoader", e))?;
        let name = env
            .new_string(PLAY_BILLING_CLASS)
            .map_err(|e| billing_err("alloc class name", e))?;
        env.call_method(
            &loader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(&name)],
        )
        .and_then(|v| v.l())
        .map_err(|e| billing_err("loadClass(PlayBilling)", e))
    }

    /// Calls a static PlayBilling method that takes the Activity and returns a String.
    pub fn call_string(method: &str) -> Result<String> {
        with_env(|env, activity| {
            let class = load_class(env, activity)?;
            let class = jni::objects::JClass::from(class);
            let value = env
                .call_static_method(
                    &class,
                    method,
                    "(Landroid/content/Context;)Ljava/lang/String;",
                    &[JValue::Object(activity)],
                )
                .and_then(|v| v.l())
                .map_err(|e| billing_err(method, e))?;
            let jstr = JString::from(value);
            let text = env
                .get_string(&jstr)
                .map_err(|e| billing_err("read result", e))?;
            Ok(text.into())
        })
    }

    /// Calls a static PlayBilling method with only the Activity, returning void.
    pub fn call_void(method: &str) -> Result<()> {
        with_env(|env, activity| {
            let class = load_class(env, activity)?;
            let class = jni::objects::JClass::from(class);
            env.call_static_method(
                &class,
                method,
                "(Landroid/content/Context;)V",
                &[JValue::Object(activity)],
            )
            .map_err(|e| billing_err(method, e))?;
            Ok(())
        })
    }

    pub fn launch_purchase(
        product_id: &str,
        base_plan_id: &str,
        account_id: &str,
        old_purchase_token: Option<&str>,
    ) -> Result<()> {
        with_env(|env, activity| {
            let class = load_class(env, activity)?;
            let class = jni::objects::JClass::from(class);
            let jproduct = env
                .new_string(product_id)
                .map_err(|e| billing_err("alloc product id", e))?;
            let jbase = env
                .new_string(base_plan_id)
                .map_err(|e| billing_err("alloc base plan", e))?;
            let jaccount = env
                .new_string(account_id)
                .map_err(|e| billing_err("alloc account id", e))?;
            let jold = match old_purchase_token {
                Some(token) => JObject::from(
                    env.new_string(token)
                        .map_err(|e| billing_err("alloc old token", e))?,
                ),
                None => JObject::null(),
            };
            env.call_static_method(
                &class,
                "launchPurchase",
                "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                &[
                    JValue::Object(activity),
                    JValue::Object(&jproduct),
                    JValue::Object(&jbase),
                    JValue::Object(&jaccount),
                    JValue::Object(&jold),
                ],
            )
            .map_err(|e| billing_err("launchPurchase", e))?;
            Ok(())
        })
    }
}
