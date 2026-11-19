//! Background Mesh on Android: the visible foreground service that keeps the
//! process alive while Qguard is locked, and private alerts while it is.
//! Desktop keeps running while minimized, so both calls are no-ops there.

#[cfg(target_os = "android")]
const CLASS: &str = "com.qguard.messaging.HelixMeshService";

const SERVICE_TITLE: &str = "Qguard Mesh is active";
const SERVICE_TEXT: &str =
    "Receiving and relaying encrypted messages from trusted nearby devices. Turn this off in Offline settings.";

/// Start (or refresh) the background service. Call while Qguard is in front.
pub(super) fn start() -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        use crate::security::android_bridge::{call_static_string, in_band};
        return call_static_string(CLASS, "start", &[SERVICE_TITLE, SERVICE_TEXT]).and_then(in_band).map(|_| ());
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (SERVICE_TITLE, SERVICE_TEXT);
        Ok(())
    }
}

pub(super) fn stop() {
    #[cfg(target_os = "android")]
    {
        use crate::security::android_bridge::call_static_string;
        let _ = call_static_string(CLASS, "stop", &[]);
    }
}

/// A private Android alert while Qguard is locked. Never message text.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(super) fn notify(slot: &str, title: &str, body: &str) {
    #[cfg(target_os = "android")]
    {
        use crate::security::android_bridge::call_static_string;
        if let Err(error) = call_static_string(CLASS, "notify", &[slot, title, body]) {
            tracing::debug!("background Mesh alert was not shown: {error}");
        }
    }
    #[cfg(not(target_os = "android"))]
    let _ = (slot, title, body);
}
