/**
 * Mobile numbers for sign-in: country selection, E.164 normalisation, masking.
 *
 * Supabase Auth keys phone accounts by E.164 (`+<country><national>`), so the
 * one thing that must be exact is the string handed to it. This is deliberately
 * not a full libphonenumber: the SMS provider is the final judge of whether a
 * number is reachable. What this guarantees is that a number is never sent in a
 * form that silently creates a SECOND account for the same person (a national
 * trunk "0" kept, spaces, a doubled country code) and that numbers are never
 * shown in full where a masked form will do.
 */

export interface PhoneCountry {
  iso2: string;
  name: string;
  dial: string;
  /** Allowed national significant number lengths (without the trunk prefix). */
  lengths: [number, number];
  /** True where the leading 0 is part of the number (Italy) and must be kept. */
  keepsLeadingZero?: boolean;
}

// Sorted by name. Lengths are national significant numbers (ITU-T E.164 plans).
export const PHONE_COUNTRIES: PhoneCountry[] = [
  { iso2: "AR", name: "Argentina", dial: "54", lengths: [10, 11] },
  { iso2: "AU", name: "Australia", dial: "61", lengths: [9, 9] },
  { iso2: "AT", name: "Austria", dial: "43", lengths: [10, 13] },
  { iso2: "BD", name: "Bangladesh", dial: "880", lengths: [10, 10] },
  { iso2: "BE", name: "Belgium", dial: "32", lengths: [9, 9] },
  { iso2: "BR", name: "Brazil", dial: "55", lengths: [10, 11] },
  { iso2: "BN", name: "Brunei", dial: "673", lengths: [7, 7] },
  { iso2: "KH", name: "Cambodia", dial: "855", lengths: [8, 9] },
  { iso2: "CA", name: "Canada", dial: "1", lengths: [10, 10] },
  { iso2: "CL", name: "Chile", dial: "56", lengths: [9, 9] },
  { iso2: "CN", name: "China", dial: "86", lengths: [11, 11] },
  { iso2: "CO", name: "Colombia", dial: "57", lengths: [10, 10] },
  { iso2: "CZ", name: "Czechia", dial: "420", lengths: [9, 9] },
  { iso2: "DK", name: "Denmark", dial: "45", lengths: [8, 8] },
  { iso2: "EG", name: "Egypt", dial: "20", lengths: [10, 10] },
  { iso2: "FI", name: "Finland", dial: "358", lengths: [9, 10] },
  { iso2: "FR", name: "France", dial: "33", lengths: [9, 9] },
  { iso2: "DE", name: "Germany", dial: "49", lengths: [10, 11] },
  { iso2: "GR", name: "Greece", dial: "30", lengths: [10, 10] },
  { iso2: "HK", name: "Hong Kong", dial: "852", lengths: [8, 8] },
  { iso2: "IN", name: "India", dial: "91", lengths: [10, 10] },
  { iso2: "ID", name: "Indonesia", dial: "62", lengths: [9, 12] },
  { iso2: "IE", name: "Ireland", dial: "353", lengths: [9, 9] },
  { iso2: "IL", name: "Israel", dial: "972", lengths: [9, 9] },
  { iso2: "IT", name: "Italy", dial: "39", lengths: [9, 11], keepsLeadingZero: true },
  { iso2: "JP", name: "Japan", dial: "81", lengths: [10, 10] },
  { iso2: "KE", name: "Kenya", dial: "254", lengths: [9, 9] },
  { iso2: "KW", name: "Kuwait", dial: "965", lengths: [8, 8] },
  { iso2: "MY", name: "Malaysia", dial: "60", lengths: [9, 10] },
  { iso2: "MX", name: "Mexico", dial: "52", lengths: [10, 10] },
  { iso2: "NL", name: "Netherlands", dial: "31", lengths: [9, 9] },
  { iso2: "NZ", name: "New Zealand", dial: "64", lengths: [8, 10] },
  { iso2: "NG", name: "Nigeria", dial: "234", lengths: [10, 10] },
  { iso2: "NO", name: "Norway", dial: "47", lengths: [8, 8] },
  { iso2: "PK", name: "Pakistan", dial: "92", lengths: [10, 10] },
  { iso2: "PE", name: "Peru", dial: "51", lengths: [9, 9] },
  { iso2: "PH", name: "Philippines", dial: "63", lengths: [10, 10] },
  { iso2: "PL", name: "Poland", dial: "48", lengths: [9, 9] },
  { iso2: "PT", name: "Portugal", dial: "351", lengths: [9, 9] },
  { iso2: "QA", name: "Qatar", dial: "974", lengths: [8, 8] },
  { iso2: "RO", name: "Romania", dial: "40", lengths: [9, 9] },
  { iso2: "SA", name: "Saudi Arabia", dial: "966", lengths: [9, 9] },
  { iso2: "SG", name: "Singapore", dial: "65", lengths: [8, 8] },
  { iso2: "ZA", name: "South Africa", dial: "27", lengths: [9, 9] },
  { iso2: "KR", name: "South Korea", dial: "82", lengths: [9, 10] },
  { iso2: "ES", name: "Spain", dial: "34", lengths: [9, 9] },
  { iso2: "SE", name: "Sweden", dial: "46", lengths: [7, 9] },
  { iso2: "CH", name: "Switzerland", dial: "41", lengths: [9, 9] },
  { iso2: "TW", name: "Taiwan", dial: "886", lengths: [9, 9] },
  { iso2: "TH", name: "Thailand", dial: "66", lengths: [9, 9] },
  { iso2: "TR", name: "Türkiye", dial: "90", lengths: [10, 10] },
  { iso2: "AE", name: "United Arab Emirates", dial: "971", lengths: [9, 9] },
  { iso2: "GB", name: "United Kingdom", dial: "44", lengths: [10, 10] },
  { iso2: "US", name: "United States", dial: "1", lengths: [10, 10] },
  { iso2: "VN", name: "Vietnam", dial: "84", lengths: [9, 10] },
];

const BY_ISO = new Map(PHONE_COUNTRIES.map((country) => [country.iso2, country]));

export function countryByIso(iso2: string): PhoneCountry | undefined {
  return BY_ISO.get(iso2.toUpperCase());
}

/** Regional-indicator flag for an ISO-3166 alpha-2 code. */
export function flagOf(iso2: string): string {
  return iso2
    .toUpperCase()
    .replace(/[A-Z]/g, (letter) => String.fromCodePoint(0x1f1e6 + letter.charCodeAt(0) - 65));
}

/** The country from the UI locale (`en-PH` → PH), else the United States. */
export function defaultCountryIso(locales: readonly string[] = typeof navigator !== "undefined" ? navigator.languages ?? [navigator.language] : []): string {
  for (const locale of locales) {
    const region = /[-_]([A-Za-z]{2})\b/.exec(locale ?? "")?.[1]?.toUpperCase();
    if (region && BY_ISO.has(region)) return region;
  }
  return "US";
}

export const E164_RE = /^\+[1-9]\d{6,14}$/;

export type PhoneParseResult =
  | { ok: true; e164: string; country: PhoneCountry | null }
  | { ok: false; error: string };

/** Longest dial-code match for a full international number. */
function countryForInternational(digits: string, preferredIso?: string): PhoneCountry | null {
  const preferred = preferredIso ? countryByIso(preferredIso) : undefined;
  if (preferred && digits.startsWith(preferred.dial)) return preferred;
  let best: PhoneCountry | null = null;
  for (const country of PHONE_COUNTRIES) {
    if (digits.startsWith(country.dial) && (!best || country.dial.length > best.dial.length)) best = country;
  }
  return best;
}

/**
 * Normalise what the user typed into E.164.
 *
 * Accepts a national number for the selected country ("0917 123 4567") or a
 * full international one ("+63 917 123 4567", "0063…"), which wins over the
 * selection.
 */
export function parsePhoneNumber(input: string, countryIso: string): PhoneParseResult {
  const raw = input.trim();
  if (!raw) return { ok: false, error: "Enter your mobile number." };
  if (/[^\d\s()+.\-]/.test(raw)) return { ok: false, error: "A mobile number can only contain digits." };

  let digits = raw.replace(/\D/g, "");
  const international = raw.startsWith("+") || digits.startsWith("00");
  if (raw.startsWith("+") === false && digits.startsWith("00")) digits = digits.slice(2);

  let country: PhoneCountry | null;
  let national: string;
  if (international) {
    country = countryForInternational(digits, countryIso);
    if (!country) {
      const e164 = `+${digits}`;
      return E164_RE.test(e164) ? { ok: true, e164, country: null } : { ok: false, error: "That doesn't look like a valid international number." };
    }
    national = digits.slice(country.dial.length);
  } else {
    country = countryByIso(countryIso) ?? null;
    if (!country) return { ok: false, error: "Choose your country first." };
    national = digits;
    // A pasted number that already starts with the dial code ("63917…" for PH).
    if (national.length > country.lengths[1] && national.startsWith(country.dial)) {
      national = national.slice(country.dial.length);
    }
  }

  if (!country.keepsLeadingZero) national = national.replace(/^0+/, "");
  if (national.length < country.lengths[0] || national.length > country.lengths[1]) {
    return { ok: false, error: `Enter a valid ${country.name} mobile number.` };
  }
  const e164 = `+${country.dial}${national}`;
  if (!E164_RE.test(e164)) return { ok: false, error: "That doesn't look like a valid mobile number." };
  return { ok: true, e164, country };
}

/** "+63 ••• ••• 4567" — enough to recognise, not enough to reuse. */
export function maskPhone(phone: string | null | undefined): string {
  const digits = (phone ?? "").replace(/\D/g, "");
  if (digits.length < 6) return "your mobile number";
  const country = countryForInternational(digits);
  const dial = country?.dial ?? digits.slice(0, Math.min(3, digits.length - 4));
  const hiddenLength = Math.max(0, digits.length - dial.length - 4);
  const hidden = "•".repeat(hiddenLength).replace(/(.{3})(?=.)/g, "$1 ");
  return `+${dial} ${hidden} ${digits.slice(-4)}`.replace(/\s+/g, " ");
}
