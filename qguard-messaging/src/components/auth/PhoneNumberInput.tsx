import { PHONE_COUNTRIES, countryByIso, flagOf } from "@/lib/phone-number";

interface PhoneNumberInputProps {
  countryIso: string;
  number: string;
  onCountryChange: (iso2: string) => void;
  onNumberChange: (value: string) => void;
  inputClass: string;
  disabled?: boolean;
  autoFocus?: boolean;
}

/** Country selector + national number, as one labelled control group. */
export function PhoneNumberInput({ countryIso, number, onCountryChange, onNumberChange, inputClass, disabled, autoFocus }: PhoneNumberInputProps) {
  const country = countryByIso(countryIso);
  return (
    <div className="mt-2 flex gap-2">
      <label className="relative w-[104px] shrink-0">
        <span className="sr-only">Country</span>
        <select
          value={countryIso}
          onChange={(event) => onCountryChange(event.target.value)}
          disabled={disabled}
          className={`${inputClass} !mt-0 !w-full appearance-none pr-2 !text-transparent`}
          aria-label="Country calling code"
        >
          {PHONE_COUNTRIES.map((item) => (
            <option key={item.iso2} value={item.iso2} className="bg-[#120d26] text-white">
              {flagOf(item.iso2)} {item.name} (+{item.dial})
            </option>
          ))}
        </select>
        {/* The closed select shows only flag + code; the list shows full names. */}
        <span className="pointer-events-none absolute inset-y-0 left-3.5 flex items-center gap-1.5 text-[15px] text-white" aria-hidden>
          <span>{flagOf(countryIso)}</span>
          <span className="font-semibold">+{country?.dial ?? ""}</span>
        </span>
      </label>
      <label className="min-w-0 flex-1">
        <span className="sr-only">Mobile number</span>
        <input
          type="tel"
          inputMode="tel"
          autoComplete="tel-national"
          value={number}
          onChange={(event) => onNumberChange(event.target.value.replace(/[^\d\s()+.\-]/g, "").slice(0, 24))}
          className={`${inputClass} !mt-0`}
          placeholder="Mobile number"
          disabled={disabled}
          autoFocus={autoFocus}
          required
        />
      </label>
    </div>
  );
}
