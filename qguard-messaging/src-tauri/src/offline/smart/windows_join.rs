//! Joining another device's private Wi-Fi link (Windows).
//!
//! A paired device that shares only Bluetooth with this PC hosts a temporary
//! WPA2/WPA3 network and sends its name and passphrase over the authenticated
//! post-quantum channel. After the user agrees, this module connects the
//! WLAN adapter to it through the native WLAN API (no shell, no console), and
//! later restores the network the PC was using before. The temporary profile
//! is deleted when the link ends, so the passphrase does not stay on the PC.

use std::{ffi::c_void, ptr, thread, time::Duration};

use windows::{
    core::{GUID, HSTRING, PCWSTR},
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::WiFi::{
            dot11_BSS_type_infrastructure, wlan_connection_mode_profile,
            wlan_interface_state_connected, wlan_intf_opcode_current_connection, WlanCloseHandle,
            WlanConnect, WlanDeleteProfile, WlanEnumInterfaces, WlanFreeMemory, WlanOpenHandle,
            WlanQueryInterface, WlanSetProfile, WLAN_CONNECTION_ATTRIBUTES,
            WLAN_CONNECTION_PARAMETERS, WLAN_INTERFACE_INFO_LIST,
        },
    },
};
use zeroize::Zeroizing;

use crate::error::{QGuardError, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

fn wifi_error(message: impl Into<String>) -> QGuardError {
    QGuardError::Storage(format!("Wi-Fi link: {}", message.into()))
}

struct Client(HANDLE);

impl Client {
    fn open() -> Result<Self> {
        let mut handle = HANDLE::default();
        let mut version = 0;
        // SAFETY: out-pointers are valid locals; the handle is closed in Drop.
        let status = unsafe { WlanOpenHandle(2, None, &mut version, &mut handle) };
        if status != 0 {
            return Err(wifi_error("Windows WLAN service is unavailable. Turn on Wi-Fi and retry."));
        }
        Ok(Self(handle))
    }

    /// The first WLAN interface (the adapter that will join the link).
    fn interface(&self) -> Result<GUID> {
        let mut list: *mut WLAN_INTERFACE_INFO_LIST = ptr::null_mut();
        // SAFETY: WLAN allocates the list; it is freed below on every path.
        let status = unsafe { WlanEnumInterfaces(self.0, None, &mut list) };
        if status != 0 || list.is_null() {
            return Err(wifi_error("No Wi-Fi adapter was found."));
        }
        // SAFETY: non-null list returned by WlanEnumInterfaces with count checked.
        let guid = unsafe { ((*list).dwNumberOfItems > 0).then(|| (*list).InterfaceInfo[0].InterfaceGuid) };
        unsafe { WlanFreeMemory(list.cast()) };
        guid.ok_or_else(|| wifi_error("No Wi-Fi adapter was found."))
    }

    /// The profile and SSID of the current connection, when connected.
    fn current(&self, interface: &GUID) -> Option<(String, Vec<u8>)> {
        let mut size = 0u32;
        let mut data: *mut c_void = ptr::null_mut();
        // SAFETY: WLAN allocates `data`; it is freed below.
        let status = unsafe {
            WlanQueryInterface(self.0, interface, wlan_intf_opcode_current_connection, None, &mut size, &mut data, None)
        };
        if status != 0 || data.is_null() || (size as usize) < std::mem::size_of::<WLAN_CONNECTION_ATTRIBUTES>() {
            if !data.is_null() {
                unsafe { WlanFreeMemory(data) };
            }
            return None;
        }
        // SAFETY: the buffer holds a WLAN_CONNECTION_ATTRIBUTES (size checked).
        let attributes = unsafe { &*(data as *const WLAN_CONNECTION_ATTRIBUTES) };
        let connected = attributes.isState == wlan_interface_state_connected;
        let name_len = attributes.strProfileName.iter().position(|&c| c == 0).unwrap_or(256);
        let profile = String::from_utf16_lossy(&attributes.strProfileName[..name_len]);
        let ssid_struct = attributes.wlanAssociationAttributes.dot11Ssid;
        let ssid_len = (ssid_struct.uSSIDLength as usize).min(32);
        let ssid = ssid_struct.ucSSID[..ssid_len].to_vec();
        unsafe { WlanFreeMemory(data) };
        connected.then_some((profile, ssid))
    }

    fn set_profile(&self, interface: &GUID, xml: &str) -> Result<()> {
        let wide = HSTRING::from(xml);
        let mut reason = 0u32;
        // SAFETY: valid handle, interface and NUL-terminated profile XML.
        let status = unsafe { WlanSetProfile(self.0, interface, 0, &wide, PCWSTR::null(), true, None, &mut reason) };
        if status != 0 {
            return Err(wifi_error(format!("Windows refused the temporary Wi-Fi profile (code {status}, reason {reason}).")));
        }
        Ok(())
    }

    fn connect(&self, interface: &GUID, profile: &str) -> Result<()> {
        let name = HSTRING::from(profile);
        let parameters = WLAN_CONNECTION_PARAMETERS {
            wlanConnectionMode: wlan_connection_mode_profile,
            strProfile: PCWSTR(name.as_ptr()),
            pDot11Ssid: ptr::null_mut(),
            pDesiredBssidList: ptr::null_mut(),
            dot11BssType: dot11_BSS_type_infrastructure,
            dwFlags: 0,
        };
        // SAFETY: `name` outlives the call; parameters reference only it.
        let status = unsafe { WlanConnect(self.0, interface, &parameters, None) };
        if status != 0 {
            return Err(wifi_error(format!("Windows could not start the Wi-Fi connection (code {status}).")));
        }
        Ok(())
    }

    fn delete_profile(&self, interface: &GUID, profile: &str) {
        let name = HSTRING::from(profile);
        // SAFETY: valid handle, interface and profile name.
        unsafe { WlanDeleteProfile(self.0, interface, &name, None) };
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // SAFETY: the handle came from WlanOpenHandle.
        unsafe { WlanCloseHandle(self.0, None) };
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The WLAN profile for the link. WPA3-only hosts need SAE; WPA2 and WPA3
/// transition hosts accept WPA2-PSK. The profile never auto-connects.
pub(crate) fn profile_xml(profile: &str, ssid: &str, passphrase: &str, security: Option<&str>) -> String {
    let authentication = if security == Some("wpa3") { "WPA3SAE" } else { "WPA2PSK" };
    format!(
        "<?xml version=\"1.0\"?>\
<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\
<name>{name}</name>\
<SSIDConfig><SSID><hex>{hex}</hex></SSID></SSIDConfig>\
<connectionType>ESS</connectionType><connectionMode>manual</connectionMode>\
<MSM><security><authEncryption><authentication>{authentication}</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption>\
<sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>{key}</keyMaterial></sharedKey></security></MSM>\
</WLANProfile>",
        name = xml_escape(profile),
        hex = hex::encode_upper(ssid.as_bytes()),
        key = xml_escape(passphrase),
    )
}

/// The network to return to after the link, and the temporary profile.
pub(crate) struct Joined {
    interface: GUID,
    previous: Option<String>,
    profile: String,
}

/// Connect this PC to the link network. Blocks up to 30 s; call it from a
/// blocking task.
pub(crate) fn join(ssid: &str, passphrase: &str, security: Option<&str>) -> Result<Joined> {
    if ssid.is_empty() || ssid.len() > 32 || passphrase.len() < 8 || passphrase.len() > 63 {
        return Err(wifi_error("The link network details are invalid."));
    }
    let client = Client::open()?;
    let interface = client.interface()?;
    let previous = client
        .current(&interface)
        .filter(|(_, current)| current.as_slice() != ssid.as_bytes())
        .map(|(profile, _)| profile)
        .filter(|profile| !profile.is_empty());
    let profile = format!("Qguard link {ssid}");
    let xml = Zeroizing::new(profile_xml(&profile, ssid, passphrase, security));
    client.set_profile(&interface, &xml)?;
    let joined = Joined { interface, previous, profile };
    if let Err(error) = client.connect(&interface, &joined.profile) {
        restore(&joined);
        return Err(error);
    }
    let deadline = std::time::Instant::now() + CONNECT_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if client.current(&interface).is_some_and(|(_, current)| current.as_slice() == ssid.as_bytes()) {
            return Ok(joined);
        }
        thread::sleep(Duration::from_millis(500));
    }
    restore(&joined);
    Err(wifi_error("The PC could not join the other device's Wi-Fi link. Keep the devices close and retry."))
}

/// Leave the link: delete its profile and reconnect the previous network.
pub(crate) fn restore(joined: &Joined) {
    let Ok(client) = Client::open() else { return };
    client.delete_profile(&joined.interface, &joined.profile);
    if let Some(previous) = &joined.previous {
        let _ = client.connect(&joined.interface, previous);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_profile_escapes_names_and_keys_and_picks_the_security_mode() {
        let xml = profile_xml("Qguard link A&B", "A&B", "pa<ss>\"word'", None);
        assert!(xml.contains("<name>Qguard link A&amp;B</name>"));
        assert!(xml.contains("<hex>412642</hex>"));
        assert!(xml.contains("<keyMaterial>pa&lt;ss&gt;&quot;word&apos;</keyMaterial>"));
        assert!(xml.contains("<authentication>WPA2PSK</authentication>"));
        assert!(xml.contains("<connectionMode>manual</connectionMode>"));
        assert!(profile_xml("p", "s", "12345678", Some("wpa3")).contains("WPA3SAE"));
        assert!(join("", "12345678", None).is_err());
        assert!(join("ssid", "short", None).is_err());
    }
}
