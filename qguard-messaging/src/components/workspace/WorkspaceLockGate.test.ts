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

  it("offers hidden vault phrase recovery on the vault's recovery screen only when the app wires it, and never for chat", () => {
    const withHidden = (scope: WorkspaceScope) =>
      renderToStaticMarkup(
        createElement(WorkspaceLockGate, {
          scope,
          status: unreadable,
          inactivityMinutes: 15,
          onUnlock: noop,
          onSetup: noop,
          onCancel: () => undefined,
          onRecoverChat: noop,
          onRecoverVaultWithKey: noop,
          onRecoverVaultWithAccount: noop,
          onHiddenRecovered: () => undefined,
        }),
      );
    expect(withHidden("vault")).toContain("Forgot a hidden vault&#x27;s pattern? Use its 12-word recovery phrase");
    expect(withHidden("chat")).not.toContain("12-word recovery phrase");
    expect(render("vault", unreadable)).not.toContain("12-word recovery phrase");
  });

  it("control: a readable lock still shows the normal unlock screen", () => {
    const html = render("chat", locked);
    expect(html).toContain("Unlock Chat");
    expect(html).not.toContain("storage key was replaced");
  });
});

function renderWithPattern(scope: WorkspaceScope, status: ScopeStatus): string {
  return renderToStaticMarkup(
    createElement(WorkspaceLockGate, {
      scope,
      status,
      inactivityMinutes: 15,
      onUnlock: noop,
      onSetup: noop,
      onPatternUnlock: noop,
      onCancel: () => undefined,
    }),
  );
}

describe("WorkspaceLockGate pattern unlock", () => {
  it("offers a pattern on the vault even when none is set, so the screen says nothing about hidden vaults", () => {
    const html = renderWithPattern("vault", locked);
    expect(html).toContain(">Pattern<");
    expect(html).toContain(">PIN<");
    // A PIN is set, so the PIN field is what shows first.
    expect(html).toContain("Enter your PIN");
  });

  it("opens on the pattern pad once the vault has a pattern", () => {
    const html = renderWithPattern("vault", { ...locked, hasPattern: true });
    expect(html).toContain("Draw your pattern");
    expect(html).toContain("Pattern pad");
  });

  it("never offers a pattern for Secure Chat", () => {
    const html = renderWithPattern("chat", locked);
    expect(html).not.toContain(">Pattern<");
    expect(html).not.toContain("Pattern pad");
  });

  it("lets a new vault be protected with a pattern from the start", () => {
    const html = renderWithPattern("vault", { ...locked, configured: false, hasPin: false });
    expect(html).toContain(">Pattern<");
    expect(html).toContain("Protect Quantum Vault");
  });
});
