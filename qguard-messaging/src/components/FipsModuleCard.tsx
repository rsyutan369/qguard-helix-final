import { AlertTriangle, BadgeCheck, CheckCircle2, ChevronDown, ExternalLink, ShieldCheck, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { fetchCryptoModuleStatus, setApprovedMode, type CryptoModuleStatus } from "@/lib/crypto-module";

/**
 * Settings → Security: this device's encryption self-check, and — folded away
 * under "Advanced" — the FIPS 140-3 view of the cryptographic module.
 *
 * Most people never need approved mode: it exists for organisations that must
 * use only FIPS-approved algorithms, and with it off a PIN is stretched with
 * Argon2id, which resists guessing better than PBKDF2. So by default the card
 * shows one line (the self-test the core ran) and keeps the module's
 * implementation details, validation status, algorithm table and the switch
 * behind the Advanced section, which opens on its own when approved mode is
 * already on or is decided by the build / operator.
 *
 * Everything shown is what the core reports, never a constant. "Approved
 * algorithm" and "inside a validated module" are kept apart on purpose — the
 * default build runs approved algorithms in a module that is not
 * CMVP-validated.
 */
export function FipsModuleCard() {
  const [status, setStatus] = useState<CryptoModuleStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showAlgorithms, setShowAlgorithms] = useState(false);
  const [message, setMessage] = useState<{ tone: "ok" | "error"; text: string } | null>(null);

  useEffect(() => {
    void fetchCryptoModuleStatus()
      .then((next) => {
        setStatus(next);
        // Someone who uses approved mode (or whose build/operator set it) sees it at once.
        if (next && (next.approvedMode || next.approvedModeSource !== "setting")) setShowAdvanced(true);
      })
      .catch(() => setStatus(null));
  }, []);

  if (!status) return null;

  const switchable = status.approvedModeSource === "setting";
  const failed = status.selfTest.results.filter((result) => !result.passed);
  const vaultPin = status.credentials.some((credential) => credential.id === "vault-pin");
  const pqAlgorithms = status.algorithms.filter((algorithm) => /ML-KEM|ML-DSA|SLH-DSA/i.test(algorithm.name)).map((algorithm) => algorithm.name);

  const toggle = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const next = await setApprovedMode(!status.approvedMode);
      setStatus(next);
      setMessage({
        tone: "ok",
        text: next.approvedMode
          ? `Approved mode on. New passwords and PINs use PBKDF2-${next.pbkdf2.prf} (${next.pbkdf2.iterations.toLocaleString()} iterations); existing ones are re-sealed the next time you unlock with them.`
          : "Approved mode off. New passwords and PINs use Argon2id again; existing ones are re-sealed the next time you unlock with them.",
      });
    } catch (error) {
      setMessage({ tone: "error", text: error instanceof Error ? error.message : String(error) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="shell-card p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-bold text-ink-950"><ShieldCheck size={18} /> Encryption self-check</div>
        {status.approvedMode && (
          <span className="status-pill bg-emerald-50 text-emerald-600">
            FIPS approved mode on
            {status.approvedModeSource === "build" ? " · this build" : status.approvedModeSource === "environment" ? " · QGUARD_FIPS_APPROVED_MODE" : ""}
          </span>
        )}
      </div>

      <div className={`mt-3 rounded-lg border p-3 text-sm ${status.selfTest.passed ? "border-emerald-100 bg-emerald-50 text-emerald-700" : "border-red-100 bg-red-50 text-red-700"}`}>
        {status.selfTest.passed ? (
          <>
            <div className="flex items-center gap-2 font-semibold">
              <CheckCircle2 size={16} /> Self-test passed: {status.selfTest.results.length} known-answer and pairwise tests in {status.selfTest.durationMs} ms
            </div>
            <p className="mt-1 text-[13px] text-emerald-800/80">
              Checked when the app started{pqAlgorithms.length > 0 ? `, including the post-quantum ${pqAlgorithms.join(", ")}` : ""}. Nothing for you to do.
            </p>
          </>
        ) : (
          <>
            <div className="flex items-center gap-2 font-semibold"><XCircle size={16} /> Self-test failed — encryption, key agreement and signing are disabled on this device</div>
            <ul className="mt-1 list-disc pl-5 text-[13px]">
              {failed.map((result) => <li key={result.name}>{result.name}{result.detail ? `: ${result.detail}` : ""}</li>)}
            </ul>
          </>
        )}
      </div>

      <button
        type="button"
        onClick={() => setShowAdvanced((open) => !open)}
        aria-expanded={showAdvanced}
        className="mt-3 inline-flex items-center gap-1 text-sm font-semibold text-ink-600 hover:text-ink-900"
      >
        <ChevronDown size={15} className={`transition-transform ${showAdvanced ? "rotate-180" : ""}`} />
        Advanced: FIPS 140-3 approved mode
      </button>
      {!showAdvanced && (
        <p className="mt-1 text-[12px] text-ink-500">Only for organisations that are required to use FIPS 140-3 approved algorithms. Most people should leave it off.</p>
      )}

      {showAdvanced && (
        <div className="mt-3 space-y-3 border-t border-line pt-3">
          <p className="text-sm text-ink-600">
            Turn this on only if your organisation requires FIPS 140-3 approved algorithms. With it off, your PIN and passwords are protected
            with Argon2id, which is harder to guess than the PBKDF2 that approved mode must use.
          </p>

          <dl className="grid gap-2 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-[12px] font-semibold uppercase tracking-wide text-ink-500">Module</dt>
              <dd className="text-ink-800">{status.module.name}</dd>
              <dd className="text-[12px] text-ink-500">{status.module.version}</dd>
            </div>
            <div>
              <dt className="text-[12px] font-semibold uppercase tracking-wide text-ink-500">Validation</dt>
              {status.fipsValidatedModule && status.certificate ? (
                <dd className="flex items-center gap-1 text-emerald-700">
                  <BadgeCheck size={14} />
                  <a href={status.certificate.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-semibold underline">
                    CMVP certificate #{status.certificate.number} <ExternalLink size={12} />
                  </a>
                </dd>
              ) : (
                <dd className="text-ink-700">Not a CMVP-validated module. Its algorithms are the NIST-approved ones; the implementation itself is not certified.</dd>
              )}
            </div>
          </dl>

          <p className="text-sm text-ink-600">
            Approved mode {status.approvedMode ? "on" : "off"}. It keeps every operation on FIPS-approved algorithms. Argon2id is not one, so
            passwords and PINs are stretched with PBKDF2-{status.pbkdf2.prf} ({status.pbkdf2.iterations.toLocaleString()} iterations,{" "}
            {status.pbkdf2.saltBits}-bit salt) instead, and the Quantum Vault needs a password of at least {status.pbkdf2.vaultPasswordMinChars} characters.
          </p>
          {vaultPin && (
            <p className="flex items-start gap-2 text-[13px] text-amber-700">
              <AlertTriangle size={14} className="mt-0.5 shrink-0" />
              Your Quantum Vault opens with a PIN. In approved mode it keeps Argon2id — PBKDF2 would make a PIN easier to guess — and is
              reported as not approved until you add a vault password of {status.pbkdf2.vaultPasswordMinChars}+ characters.
            </p>
          )}
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={busy || !switchable || (!status.approvedMode && !status.selfTest.passed)}
              onClick={() => void toggle()}
              className="rounded-lg border border-line bg-white px-4 py-2 text-sm font-bold text-ink-700 hover:bg-canvas disabled:opacity-60"
            >
              {status.approvedMode ? "Turn approved mode off" : "Turn approved mode on"}
            </button>
            <button
              type="button"
              onClick={() => setShowAlgorithms((open) => !open)}
              className="inline-flex items-center gap-1 rounded-lg border border-line bg-white px-4 py-2 text-sm font-bold text-ink-700 hover:bg-canvas"
              aria-expanded={showAlgorithms}
            >
              Algorithms and credentials <ChevronDown size={14} className={showAlgorithms ? "rotate-180" : ""} />
            </button>
          </div>
          {message && (
            <div className={`rounded-lg border p-3 text-sm font-semibold ${message.tone === "ok" ? "border-emerald-100 bg-emerald-50 text-emerald-700" : "border-red-100 bg-red-50 text-red-700"}`}>
              {message.text}
            </div>
          )}

          {showAlgorithms && (
            <div className="space-y-4">
              <div className="overflow-x-auto">
                <table className="w-full min-w-[560px] text-left text-[13px]">
                  <thead className="text-[12px] uppercase tracking-wide text-ink-500">
                    <tr>
                      <th className="py-1 pr-3 font-semibold">Algorithm</th>
                      <th className="py-1 pr-3 font-semibold">Used for</th>
                      <th className="py-1 pr-3 font-semibold">FIPS-approved</th>
                      <th className="py-1 font-semibold">In a validated module</th>
                    </tr>
                  </thead>
                  <tbody>
                    {status.algorithms.map((algorithm) => (
                      <tr key={algorithm.id} className="border-t border-line align-top">
                        <td className="py-2 pr-3">
                          <div className="font-semibold text-ink-900">{algorithm.name}</div>
                          <div className="text-ink-500">{algorithm.standard}</div>
                        </td>
                        <td className="py-2 pr-3 text-ink-700">
                          {algorithm.usedFor}
                          {algorithm.note && <div className="text-ink-500">{algorithm.note}</div>}
                        </td>
                        <td className="py-2 pr-3">{algorithm.approved ? <span className="text-emerald-700">Yes</span> : <span className="text-amber-700">No</span>}</td>
                        <td className="py-2">{algorithm.validated ? <span className="text-emerald-700">Yes</span> : <span className="text-ink-600">No</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {status.credentials.length > 0 && (
                <div>
                  <div className="text-[12px] font-semibold uppercase tracking-wide text-ink-500">Unlock credentials on this device</div>
                  <ul className="mt-1 space-y-1 text-[13px]">
                    {status.credentials.map((credential) => (
                      <li key={credential.id} className="flex flex-wrap items-baseline gap-x-2">
                        <span className="font-semibold text-ink-900">{credential.label}</span>
                        <span className="text-ink-600">{credential.kdf}</span>
                        <span className={credential.meetsApprovedMode ? "text-emerald-700" : "text-amber-700"}>
                          {credential.meetsApprovedMode ? "meets approved mode" : "does not meet approved mode yet"}
                        </span>
                        {credential.note && <span className="w-full text-ink-500">{credential.note}</span>}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div>
                <div className="text-[12px] font-semibold uppercase tracking-wide text-ink-500">Outside this module</div>
                <ul className="mt-1 list-disc space-y-1 pl-5 text-[13px] text-ink-600">
                  {status.outsideBoundary.map((item) => <li key={item}>{item}</li>)}
                </ul>
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
