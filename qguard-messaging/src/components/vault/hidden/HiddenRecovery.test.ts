import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { HiddenSummary } from "@/lib/vault-hidden";

const core = vi.hoisted(() => ({
  checkRecovery: vi.fn(),
  recover: vi.fn(),
  setUpRecovery: vi.fn(),
  removeRecovery: vi.fn(),
}));
vi.mock("@/lib/vault-hidden", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/vault-hidden")>();
  return { ...actual, hiddenVault: { ...actual.hiddenVault, ...core } };
});
const dialog = vi.hoisted(() => ({ ask: vi.fn(async () => true) }));
vi.mock("@/lib/tauri-dialog", () => dialog);

import { RecoverHiddenVault, RecoveryPhraseCard } from "@/components/vault/hidden/HiddenRecovery";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const WORDS = "legal winner thank year wave sausage worth useful legal winner thank yellow".split(" ");

function summary(overrides: Partial<HiddenSummary> = {}): HiddenSummary {
  return { files: 3, folders: 1, bytes: 2048, createdAt: "2026-11-05T00:00:00Z", duressErase: false, recoveryPhrase: false, ...overrides };
}

let root: Root | null = null;
let container: HTMLDivElement;

async function render(element: ReturnType<typeof createElement>) {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => root!.render(element));
}

/** Set an input's value the way typing does, so React sees the change. */
async function type(input: HTMLInputElement, value: string) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

function button(label: string): HTMLButtonElement {
  const found = [...document.querySelectorAll("button")].find((b) => b.textContent?.includes(label));
  if (!found) throw new Error(`no button "${label}"`);
  return found as HTMLButtonElement;
}

async function click(target: HTMLElement) {
  await act(async () => target.click());
}

beforeEach(() => {
  Object.values(core).forEach((fn) => fn.mockReset());
  dialog.ask.mockClear();
});

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  document.body.innerHTML = "";
});

describe("RecoverHiddenVault", () => {
  it("a phrase typed into the first box fills all twelve, is checked in the core, then asks for a new pattern", async () => {
    core.checkRecovery.mockResolvedValue(summary());
    await render(createElement(RecoverHiddenVault, { onRecovered: vi.fn() }));
    const check = button("Check phrase");
    expect(check.disabled).toBe(true);

    const boxes = [...container.querySelectorAll<HTMLInputElement>('input[aria-label^="Word "]')];
    expect(boxes).toHaveLength(12);
    // Typed or pasted as one line (a multi-line paste arrives through onPaste,
    // since an input's value cannot hold line breaks).
    await type(boxes[0], `1. ${WORDS.join(" ")}`);
    expect(boxes.map((box) => box.value)).toEqual(WORDS);
    expect(check.disabled).toBe(false);

    await click(check);
    expect(core.checkRecovery).toHaveBeenCalledWith(WORDS.join(" "));
    expect(container.textContent).toContain("Phrase accepted");
    expect(container.textContent).toContain("3 files");
    expect(container.textContent).toContain("Draw a new pattern");
  });

  it("shows the core's reason when a phrase opens nothing, and stays on the words", async () => {
    core.checkRecovery.mockRejectedValue(new Error("These words don't open a hidden vault on this device."));
    await render(createElement(RecoverHiddenVault, { onRecovered: vi.fn() }));
    const boxes = [...container.querySelectorAll<HTMLInputElement>('input[aria-label^="Word "]')];
    await type(boxes[0], WORDS.join(" "));
    await click(button("Check phrase"));
    expect(container.querySelector('[role="alert"]')?.textContent).toContain("don't open a hidden vault");
    expect(core.recover).not.toHaveBeenCalled();
    expect(boxes[11].value).toBe("yellow");
  });
});

describe("RecoveryPhraseCard", () => {
  it("sets up a phrase, shows the words once and only finishes when three are typed back", async () => {
    const onChanged = vi.fn();
    const onNotice = vi.fn();
    core.setUpRecovery.mockResolvedValue({ words: WORDS, summary: summary({ recoveryPhrase: true }) });
    await render(createElement(RecoveryPhraseCard, { summary: summary(), busy: false, onChanged, onNotice }));
    expect(container.textContent).toContain("Not set up");

    await click(button("Set up recovery phrase"));
    expect(dialog.ask).not.toHaveBeenCalled();
    await click(button("Show my 12 words"));
    expect(core.setUpRecovery).toHaveBeenCalledTimes(1);
    expect(onChanged).toHaveBeenCalledWith(expect.objectContaining({ recoveryPhrase: true }));
    const shown = [...document.querySelectorAll("ol li")].map((li) => li.textContent);
    expect(shown).toHaveLength(12);
    expect(shown[0]).toBe("1legal");

    await click(button("I wrote them down"));
    const done = button("Done");
    expect(done.disabled).toBe(true);
    const asks = [...document.querySelectorAll("label")].filter((label) => /^Word \d+/.test(label.textContent ?? ""));
    expect(asks).toHaveLength(3);
    for (const ask of asks) {
      const position = Number(/^Word (\d+)/.exec(ask.textContent ?? "")![1]) - 1;
      await type(ask.querySelector("input")!, ` ${WORDS[position].toUpperCase()} `);
    }
    expect(done.disabled).toBe(false);
    await click(done);
    expect(onNotice).toHaveBeenCalledWith(expect.objectContaining({ tone: "success" }));
    expect(document.querySelector("ol")).toBeNull();
  });

  it("asks before replacing or removing an existing phrase", async () => {
    const onChanged = vi.fn();
    core.removeRecovery.mockResolvedValue(summary());
    await render(createElement(RecoveryPhraseCard, { summary: summary({ recoveryPhrase: true }), busy: false, onChanged, onNotice: vi.fn() }));
    expect(container.textContent).toContain("Set up —");

    dialog.ask.mockResolvedValueOnce(false);
    await click(button("Create a new phrase"));
    expect(document.querySelector('[role="dialog"]')).toBeNull();

    await click(button("Remove phrase"));
    expect(dialog.ask).toHaveBeenCalledTimes(2);
    expect(core.removeRecovery).toHaveBeenCalledTimes(1);
    expect(onChanged).toHaveBeenCalledWith(expect.objectContaining({ recoveryPhrase: false }));
  });
});
