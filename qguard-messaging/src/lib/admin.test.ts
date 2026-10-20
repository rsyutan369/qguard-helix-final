import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/supabase", () => ({ supabase: {} }));
vi.mock("@/lib/auth-context", () => ({ useAuth: () => ({ user: null }) }));

const { fetchAppRole, parseAppRole } = await import("./admin");

function fakeClient(result: { data: unknown; error: unknown } | Error) {
  const calls: string[] = [];
  const client = {
    from(table: string) {
      calls.push(table);
      const chain = {
        select: () => chain,
        eq: (column: string, value: string) => { calls.push(`${column}=${value}`); return chain; },
        maybeSingle: async () => { if (result instanceof Error) throw result; return result; },
      };
      return chain;
    },
  };
  return { client: client as never, calls };
}

describe("app roles", () => {
  it("accepts only known roles", () => {
    expect(parseAppRole("operator")).toBe("operator");
    expect(parseAppRole("admin")).toBeNull();
    expect(parseAppRole(null)).toBeNull();
  });

  it("reads the caller's own row from the server-side role table", async () => {
    const { client, calls } = fakeClient({ data: { role: "operator" }, error: null });
    expect(await fetchAppRole("user-1", client)).toBe("operator");
    expect(calls).toEqual(["messaging_app_roles", "user_id=user-1"]);
  });

  it("grants nothing when there is no row, an error, or no table yet", async () => {
    expect(await fetchAppRole("u", fakeClient({ data: null, error: null }).client)).toBeNull();
    expect(await fetchAppRole("u", fakeClient({ data: null, error: { code: "42P01" } }).client)).toBeNull();
    expect(await fetchAppRole("u", fakeClient(new Error("network")).client)).toBeNull();
  });
});
