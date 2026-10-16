import { describe, expect, it } from "vitest";
import { settlePinRestore } from "@/lib/pin-restore";

describe("settlePinRestore", () => {
  it("holds the PIN gate while unlock/setSession is still in flight", () => {
    // auth.loading is still false here: setSession has not notified yet. This
    // is exactly the window in which the LoginPage used to flash.
    expect(settlePinRestore("restoring", { signedIn: false, loading: false })).toBe("restoring");
    expect(settlePinRestore("restoring", { signedIn: false, loading: true })).toBe("restoring");
  });

  it("holds the PIN gate while the auth context processes the restored session", () => {
    expect(settlePinRestore("applied", { signedIn: false, loading: true })).toBe("applied");
  });

  it("releases the gate once the session reaches the auth context", () => {
    expect(settlePinRestore("applied", { signedIn: true, loading: false })).toBe("idle");
    expect(settlePinRestore("restoring", { signedIn: true, loading: false })).toBe("idle");
  });

  it("releases the gate when processing ends without a session, so the error is visible", () => {
    expect(settlePinRestore("applied", { signedIn: false, loading: false })).toBe("idle");
  });

  it("stays idle when no restore is running", () => {
    expect(settlePinRestore("idle", { signedIn: false, loading: false })).toBe("idle");
    expect(settlePinRestore("idle", { signedIn: true, loading: true })).toBe("idle");
  });
});
