import { useState } from "react";
import { Check, Copy, LoaderCircle, TriangleAlert, Wifi, WifiOff } from "lucide-react";
import { offlinePeerName, type OfflinePeer } from "@/lib/offline";
import { safeInvoke } from "@/lib/tauri";
import "./wifi-link-card.css";

type Run = (task: () => Promise<unknown>, result?: string, pending?: string) => Promise<boolean>;

function CopyValue({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return <div className="wifi-link-value">
    <span>{label}</span>
    <code>{value}</code>
    <button type="button" className="focus-ring" aria-label={`Copy ${label.toLowerCase()}`} onClick={() => {
      void navigator.clipboard?.writeText(value).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }, () => undefined);
    }}>{copied ? <Check size={15} aria-hidden /> : <Copy size={15} aria-hidden />}</button>
  </div>;
}

/**
 * The direct Wi-Fi link to one paired device, exactly as the native link
 * manager reports it: XFER sets it up over the encrypted Bluetooth channel
 * when the two devices share no local network, so files move at Wi-Fi speed.
 */
export function WifiLinkCard({ peer, accountId, busy, run }: {
  peer: OfflinePeer; accountId: string; busy: boolean; run: Run;
}) {
  const link = peer.wifiLink;
  if (!link) return null;
  const name = offlinePeerName(peer, `Device ${peer.fingerprint.slice(0, 8)}`);
  const join = (accept: boolean) => void run(
    () => safeInvoke("offline_wifi_link_join", { peer: peer.fingerprint, accept, expectedAccount: accountId }),
    undefined,
    accept ? `Joining ${name}'s Wi-Fi link…` : undefined,
  );
  const close = () => void run(() => safeInvoke("offline_wifi_link_close", { peer: peer.fingerprint, expectedAccount: accountId }));
  const working = ["requested", "starting", "hosting", "joining"].includes(link.state);

  const copy = {
    requested: [`Setting up a direct Wi-Fi link with ${name}`, `${name} is opening a private Wi-Fi network for this transfer. Keep both devices close.`],
    starting: ["Opening a private Wi-Fi link", `Your files move over this link at Wi-Fi speed. ${name} joins it next.`],
    hosting: ["Private Wi-Fi link open", `Waiting for ${name} to join. The link closes by itself after the transfer.`],
    joinPrompt: [`Join ${name}'s Wi-Fi link`, `${name} opened a private, password-protected Wi-Fi network so your files move at full speed. This computer leaves its current Wi-Fi during the transfer and returns to it automatically afterwards.`],
    joining: [`Joining ${name}'s Wi-Fi link`, "Connecting to the private network. This takes a few seconds."],
    manual: [`Join ${name}'s Wi-Fi network`, "Open Wi-Fi settings on this device and join the network below. Qguard continues the transfer as soon as it is connected."],
    connected: ["Direct Wi-Fi link active", `Files move to and from ${name} over the private link. It closes by itself when the transfers finish.`],
    failed: ["The Wi-Fi link could not be set up", link.error ?? "Keep both devices close, check that Wi-Fi is on, and try again."],
    declined: ["Wi-Fi link not joined", `The transfer with ${name} waits until both devices share a network.`],
  }[link.state];

  return <section className="wifi-link-card" data-state={link.state} aria-label={`Wi-Fi link with ${name}`} aria-live="polite">
    <span className="wifi-link-icon" aria-hidden>
      {working ? <LoaderCircle size={20} className="wifi-link-spin" />
        : link.state === "failed" ? <TriangleAlert size={20} />
        : link.state === "declined" ? <WifiOff size={20} /> : <Wifi size={20} />}
    </span>
    <div className="wifi-link-copy">
      <h3>{copy[0]}</h3>
      <p>{copy[1]}</p>
      {link.state === "manual" && link.network && link.passphrase && <div className="wifi-link-network">
        <CopyValue label="Network" value={link.network} />
        <CopyValue label="Password" value={link.passphrase} />
      </div>}
      <div className="wifi-link-actions">
        {(link.state === "joinPrompt" || link.state === "declined") && link.automaticJoin && <>
          <button type="button" className="wifi-link-primary focus-ring" disabled={busy} onClick={() => join(true)}>Join Wi-Fi link</button>
          {link.state === "joinPrompt" && <button type="button" className="focus-ring" disabled={busy} onClick={() => join(false)}>Not now</button>}
        </>}
        {link.state === "connected" && <button type="button" className="focus-ring" disabled={busy} onClick={close}>End link</button>}
        {link.state === "failed" && <button type="button" className="wifi-link-primary focus-ring" disabled={busy} onClick={close}>Try again</button>}
        {(link.state === "hosting" || link.state === "manual" || link.state === "requested") && <button type="button" className="focus-ring" disabled={busy} onClick={close}>Cancel link</button>}
      </div>
    </div>
  </section>;
}
