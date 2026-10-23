import { describe, expect, it } from "vitest";
import { defaultCountryIso, flagOf, maskPhone, parsePhoneNumber, PHONE_COUNTRIES } from "@/lib/phone-number";

describe("parsePhoneNumber", () => {
  it("normalises a national number with a trunk 0 to E.164", () => {
    expect(parsePhoneNumber("0917 123 4567", "PH")).toEqual(expect.objectContaining({ ok: true, e164: "+639171234567" }));
    expect(parsePhoneNumber("07700 900123", "GB")).toEqual(expect.objectContaining({ ok: true, e164: "+447700900123" }));
  });

  it("gives the same E.164 for every way one number can be typed, so it never opens a second account", () => {
    const forms = ["0917-123-4567", "917 123 4567", "+63 917 123 4567", "0063 917 123 4567", "639171234567", "(0917) 123.4567"];
    const results = forms.map((form) => parsePhoneNumber(form, "PH"));
    for (const result of results) expect(result).toEqual(expect.objectContaining({ ok: true, e164: "+639171234567" }));
  });

  it("lets a full international number override the selected country", () => {
    expect(parsePhoneNumber("+44 7700 900123", "PH")).toEqual(expect.objectContaining({ ok: true, e164: "+447700900123" }));
  });

  it("keeps Italy's significant leading zero", () => {
    expect(parsePhoneNumber("06 1234 5678", "IT")).toEqual(expect.objectContaining({ ok: true, e164: "+390612345678" }));
  });

  it("rejects wrong lengths, letters and empty input with a readable reason", () => {
    expect(parsePhoneNumber("0917 123", "PH")).toEqual({ ok: false, error: "Enter a valid Philippines mobile number." });
    expect(parsePhoneNumber("0917 ABC 4567", "PH").ok).toBe(false);
    expect(parsePhoneNumber("   ", "PH")).toEqual({ ok: false, error: "Enter your mobile number." });
  });

  it("separates US and Canada by the selected country while both use +1", () => {
    expect(parsePhoneNumber("(415) 555-0132", "US")).toEqual(expect.objectContaining({ ok: true, e164: "+14155550132" }));
    expect(parsePhoneNumber("+1 415 555 0132", "CA")).toEqual(expect.objectContaining({ ok: true, e164: "+14155550132", country: expect.objectContaining({ iso2: "CA" }) }));
  });
});

describe("maskPhone", () => {
  it("shows the country code and last four digits only", () => {
    expect(maskPhone("+639171234567")).toBe("+63 ••• ••• 4567");
    expect(maskPhone("+447700900123")).toBe("+44 ••• ••• 0123");
  });

  it("never echoes something that is not a number", () => {
    expect(maskPhone("")).toBe("your mobile number");
    expect(maskPhone(null)).toBe("your mobile number");
  });
});

describe("country data", () => {
  it("has unique ISO codes and plausible length ranges", () => {
    const codes = PHONE_COUNTRIES.map((country) => country.iso2);
    expect(new Set(codes).size).toBe(codes.length);
    for (const country of PHONE_COUNTRIES) {
      expect(country.lengths[0]).toBeLessThanOrEqual(country.lengths[1]);
      expect(country.dial.length + country.lengths[1]).toBeLessThanOrEqual(15);
    }
  });

  it("derives the default country from the locale", () => {
    expect(defaultCountryIso(["en-PH"])).toBe("PH");
    expect(defaultCountryIso(["fr", "de-DE"])).toBe("DE");
    expect(defaultCountryIso(["xx"])).toBe("US");
  });

  it("builds regional-indicator flags", () => {
    expect(flagOf("ph")).toBe("🇵🇭");
  });
});
