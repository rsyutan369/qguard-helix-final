import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { WorkspaceLockGate } from "@/components/workspace/WorkspaceLockGate";
import type { ScopeStatus, WorkspaceScope } from "@/lib/use-workspace-lock";

const locked: ScopeStatus = {
  configured: true,
  hasPassword: false,
  hasPin: true,
  unlocked: false,
  failedAttempts: 0,
  lockoutUntil: null,
  lockdown: false,
  unreadable: false,
};

const unreadable: ScopeStatus = { ...locked, hasPin: false, unreadable: true };

const noop = async () => undefined;

function render(scope: WorkspaceScope, status: ScopeStatus): string {
  return renderToStaticMarkup(
    createElement(WorkspaceLockGate, {
      scope,
      status,
      recoveryEnabled: false,
      inactivityMinutes: 15,
      onUnlock: noop,
      onSetup: noop,
      onCancel: () => undefined,
      onRecoverChat: noop,
      onRecoverVaultWithKey: noop,
      onRecoverVaultWithAccount: noop,
    }),
  );
}

describe("WorkspaceLockGate with a lock record that no longer opens", () => {
  it("offers the account-password reset for Secure Chat, not an unlock it cannot check", () => {
    const html = render("chat", unreadable);
    expect(html).toContain("Set up Secure Chat again");
    expect(html).toContain("storage key was replaced");
    expect(html).toContain("Confirm your account password");
    expect(html).not.toContain("Unlock Chat");
    expect(html).not.toContain("Protect Secure Chat");
  });

  it("offers the recovery-key and start-fresh resets for the vault", () => {
    const html = render("vault", unreadable);
    expect(html).toContain("Set up Quantum Vault again");
    expect(html).toContain("I have my recovery key");
    expect(html).toContain("Reset vault (start fresh)");
    expect(html).not.toContain("Unlock Vault");
  });

  it("control: a readable lock still shows the normal unlock screen", () => {
    const html = render("chat", locked);
    expect(html).toContain("Unlock Chat");
    expect(html).not.toContain("storage key was replaced");
  });
});
