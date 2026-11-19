#[cfg(not(windows))]
use super::HotspotDetails;
use super::HotspotSnapshot;
#[cfg(not(windows))]
use crate::error::QGuardError;
use crate::error::Result;

#[cfg(windows)]
pub(super) use super::windows_wifi::Hotspot as Host;

#[cfg(windows)]
pub(super) fn snapshot() -> Result<HotspotSnapshot> {
    Ok(HotspotSnapshot {
        available: Host::available()?,
        ..HotspotSnapshot::default()
    })
}

#[cfg(target_os = "android")]
fn call(method: &str) -> Result<String> {
    use crate::security::android_bridge::{call_static_string, in_band};
    call_static_string("com.qguard.messaging.HelixLocalHotspot", method, &[])
        .and_then(in_band)
        .map_err(|reason| QGuardError::Storage(format!("Temporary hotspot: {reason}")))
}

#[cfg(target_os = "android")]
pub(super) struct Host;

#[cfg(target_os = "android")]
impl Host {
    pub(super) fn start() -> Result<Self> {
        call("start")?;
        Ok(Self)
    }

    pub(super) fn snapshot(&self) -> Result<HotspotSnapshot> {
        snapshot()
    }

    pub(super) fn details(&self) -> Result<Option<HotspotDetails>> {
        let raw = call("details")?;
        serde_json::from_str(&raw)
            .map_err(|_| QGuardError::Storage("Hotspot details are unreadable.".into()))
    }
}

#[cfg(target_os = "android")]
impl Drop for Host {
    fn drop(&mut self) {
        let _ = call("stop");
    }
}

#[cfg(target_os = "android")]
pub(super) fn snapshot() -> Result<HotspotSnapshot> {
    let raw = call("status")?;
    serde_json::from_str(&raw)
        .map_err(|_| QGuardError::Storage("Hotspot status is unreadable.".into()))
}

#[cfg(not(any(target_os = "android", windows)))]
pub(super) struct Host;

#[cfg(not(any(target_os = "android", windows)))]
impl Host {
    pub(super) fn start() -> Result<Self> {
        Err(QGuardError::InvalidInput(
            "Temporary hotspots are unavailable on this platform.".into(),
        ))
    }
    pub(super) fn snapshot(&self) -> Result<HotspotSnapshot> {
        snapshot()
    }
    pub(super) fn details(&self) -> Result<Option<HotspotDetails>> {
        Ok(None)
    }
}

#[cfg(not(any(target_os = "android", windows)))]
pub(super) fn snapshot() -> Result<HotspotSnapshot> {
    Ok(HotspotSnapshot::default())
}
