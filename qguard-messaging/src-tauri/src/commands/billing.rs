//! Subscription paywall platform bridge.
//!
//! Android: bridges to `com.qguard.messaging.PlayBilling` (Google Play Billing
//! Library) over JNI — launch a subscription purchase, refresh/restore owned
//! purchases, and read the billing state JSON the Kotlin side maintains. The
//! purchase token this yields is NEVER trusted locally: the frontend submits it
//! to the backend (`/api/v1/subscriptions/verify`), which validates it with the
//! Google Play Developer API, acknowledges it server-side, and only then
//! computes the account's entitlements. Only base-plan offers are purchasable
//! (no trial or introductory offer exists in the catalog).
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

/// Product ids sold on Play look like `qh_<tier>_<monthly|yearly>` (remappable
/// server-side); anything outside this alphabet is refused before JNI.
fn valid_product_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 100 && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
}

/// The obfuscated account id is issued by the backend: 64 lowercase hex chars
/// (SHA-256 of the QGuard user id). Never an email or other personal data.
fn valid_account_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Launch the Google Play purchase flow for one product's base plan.
/// `account_id` becomes the obfuscatedAccountId so the backend can bind the
/// purchase to this account. `old_purchase_token` turns the flow into an
/// in-place plan change (`replacement`: "upgrade" | "downgrade") instead of a
/// second, duplicate subscription.
#[tauri::command]
pub async fn billing_launch_purchase(
    product_id: String,
    account_id: String,
    old_purchase_token: Option<String>,
    replacement: Option<String>,
) -> Result<()> {
    if !valid_product_id(&product_id) {
        return Err(QGuardError::InvalidInput("invalid product id".to_string()));
    }
    if !valid_account_id(&account_id) {
        return Err(QGuardError::InvalidInput("invalid billing account id".to_string()));
    }
    let replacement = match replacement.as_deref() {
        None | Some("upgrade") => "upgrade",
        Some("downgrade") => "downgrade",
        Some(_) => return Err(QGuardError::InvalidInput("invalid replacement mode".to_string())),
    };
    #[cfg(target_os = "android")]
    {
        android::launch_purchase(&product_id, &account_id, old_purchase_token.as_deref(), replacement)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (product_id, account_id, old_purchase_token, replacement);
        Err(QGuardError::InvalidInput(
            "Google Play Billing is only available in the Android app".to_string(),
        ))
    }
}

/// Load localized product details (price, currency, period) from Google Play.
/// The result lands in `billing_state().products`.
#[tauri::command]
pub async fn billing_query_products(product_ids: Vec<String>) -> Result<()> {
    if product_ids.is_empty() || product_ids.len() > 16 || !product_ids.iter().all(|id| valid_product_id(id)) {
        return Err(QGuardError::InvalidInput("invalid product id list".to_string()));
    }
    #[cfg(target_os = "android")]
    {
        android::call_with_string("queryProducts", &product_ids.join(","))
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = product_ids;
        Ok(())
    }
}

/// End the Google Play connection (sign-out).
#[tauri::command]
pub async fn billing_disconnect() -> Result<()> {
    #[cfg(target_os = "android")]
    {
        android::call_void("disconnect")
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(())
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

    /// Calls a static PlayBilling method (Context, String) returning void.
    pub fn call_with_string(method: &str, arg: &str) -> Result<()> {
        with_env(|env, activity| {
            let class = load_class(env, activity)?;
            let class = jni::objects::JClass::from(class);
            let jarg = env.new_string(arg).map_err(|e| billing_err("alloc argument", e))?;
            env.call_static_method(
                &class,
                method,
                "(Landroid/content/Context;Ljava/lang/String;)V",
                &[JValue::Object(activity), JValue::Object(&jarg)],
            )
            .map_err(|e| billing_err(method, e))?;
            Ok(())
        })
    }

    pub fn launch_purchase(
        product_id: &str,
        account_id: &str,
        old_purchase_token: Option<&str>,
        replacement: &str,
    ) -> Result<()> {
        with_env(|env, activity| {
            let class = load_class(env, activity)?;
            let class = jni::objects::JClass::from(class);
            let jproduct = env
                .new_string(product_id)
                .map_err(|e| billing_err("alloc product id", e))?;
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
            let jreplacement = env
                .new_string(replacement)
                .map_err(|e| billing_err("alloc replacement", e))?;
            env.call_static_method(
                &class,
                "launchPurchase",
                "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                &[
                    JValue::Object(activity),
                    JValue::Object(&jproduct),
                    JValue::Object(&jaccount),
                    JValue::Object(&jold),
                    JValue::Object(&jreplacement),
                ],
            )
            .map_err(|e| billing_err("launchPurchase", e))?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod billing_input_tests {
    use super::{valid_account_id, valid_product_id};

    #[test]
    fn billing_product_ids_are_restricted_before_jni() {
        assert!(valid_product_id("qh_starter_monthly"));
        assert!(valid_product_id("qh_pro_yearly_v2"));
        assert!(!valid_product_id(""));
        assert!(!valid_product_id("QH_PRO"));
        assert!(!valid_product_id("qh pro"));
        assert!(!valid_product_id("qh_pro;drop"));
        assert!(!valid_product_id(&"a".repeat(101)));
    }

    #[test]
    fn billing_account_id_must_be_the_backend_hash_not_personal_data() {
        assert!(valid_account_id(&"ab".repeat(32)));
        assert!(!valid_account_id("someone@example.com"));
        assert!(!valid_account_id("5b0c6f7e-1c2d-4e5f-8a9b-0c1d2e3f4a5b"));
        assert!(!valid_account_id(&"AB".repeat(32)));
        assert!(!valid_account_id(&"ab".repeat(31)));
    }
}
