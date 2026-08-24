# Changelog

## 1.3.0 — Quantum Vault security hardening

**Nothing you already have stops working.** Every `.qvault` container, every
`.qgkey` identity, every recovery key and every conversation carries on exactly
as before. There is no migration to run and no re-encryption. If you read one
line of this note, read that one.

What changed is that three things the app used to *suggest*, it now *enforces* —
so a few screens will look different, and one of them will look like a step
backwards until you know why. This note explains each one and what to do about
it.

---

### Three things you will notice

#### 1. Your saved recipients all show as "Not verified"

**What you'll see.** Open Quantum Vault → Portable Hybrid Identity and every
recipient in your address book is flagged amber, and the Seal buttons are
disabled.

**Why.** A recipient bundle (`.qgpub.json`) proves it is internally consistent.
It does not prove *whose* identity it is — there is no signature on it that could.
So anyone able to swap the file while it was on its way to you gets your sealed
file instead, and nothing afterwards looks wrong: the container verifies, it
opens, it just opens for the wrong person.

The only thing that catches this is comparing the recipient's fingerprint with
them over a channel the attacker doesn't control. The app used to say so in a
notice and then seal anyway. Now it doesn't seal until you've confirmed.

Nobody has ever recorded a confirmation, so everyone starts unverified. That is
the correct starting state, not a bug.

**What to do.** Once per recipient, roughly a minute each:

1. Click **Verify** next to them.
2. Get them on a call, or ask in person. Not over the same channel that carried
   their bundle — if that one is compromised, so is anything it delivers.
3. Have them read out the fingerprint their own app shows.
4. Type it in. Dashes, spaces and capitalisation don't matter; the sixteen
   characters do.

If what they read doesn't match, **stop**. The bundle you were given is not the
one they sent. Ask them to send it again through a different route.

**Also new:** if a second identity turns up under a name you already have saved,
with different keys, the app now says so immediately. That is what a substituted
bundle looks like from your side.

Changed your mind, or someone re-issued their identity? **Unverify** puts them
back behind the check.

#### 2. Some of your encrypted files are flagged "needs re-protection"

**What you'll see.** A badge on affected containers in the Explorer, and a count
in the recovery panel.

**Why.** Every container carries a spare key wrap so your own device can open its
own files. Until now that wrap was tied to a key held in your operating system's
keychain — which meant someone with both your app data folder and keychain access
could open the vault *without your vault password*. The password was a lock on a
door with a second, weaker door beside it.

New containers are wrapped to a key that lives inside the password-protected
vault itself, so there's only the one door now. Files encrypted before this
update still have the old wrap.

**What to do.** Select them and hit **Re-protect**. It rewrites the container's
header — your files are not re-encrypted, so it's quick even on large ones. The
app only re-protects what actually needs it, so running it twice costs nothing.

Not urgent unless your device or its keychain could plausibly be accessed by
someone else. Worth clearing anyway.

#### 3. Creating an identity may reject the passphrase you'd have used

**What you'll see.** A strength meter, a **Generate** button, and a refusal if
what you typed is too weak — even if it clears the old twelve-character minimum.

**Why.** A `.qgkey` bundle is a file. If someone gets a copy, the only thing
between them and everything sealed to that identity is the passphrase, and they
can guess at it offline for as long as they like. Twelve characters of something
memorable does not survive that. It was the most likely way this vault actually
got opened — well ahead of anything to do with the cryptography.

The bar is now roughly 70 bits of estimated strength, measured properly:
character count, dictionary words, keyboard runs, repeats and common passwords
all feed into it, and the app takes the most pessimistic reading rather than the
flattering one.

**What to do.** Press **Generate**. Seven random words is about 77 bits, comfortably
over the bar, and far easier to retype than the mangled-word passwords the old
minimum encouraged. Store it in your password manager.

**Existing bundles are not affected.** Importing a `.qgkey` you already have works
with the passphrase it already has, whatever its strength. The check applies only
when creating or exporting a new one. If you want to re-protect an old identity
under a stronger passphrase, export it again.

---

### Under the hood

**ML-KEM is now conformant to final FIPS 203.** The vault has always used ML-KEM
rather than the older Kyber, but it reached it through a library packaged at the
standard's *draft* revision. The two differ in exactly one place — how a keypair
is expanded from its seed. Encapsulation, decapsulation and every stored format
are byte-for-byte identical, which is why nothing you have needs migrating and
why devices on older versions still interoperate in both directions.

What this buys is the ability to stand behind the claim: key generation now
matches the published standard, so FIPS 203 test vectors pass. A known-answer
vector captured from the previous build is committed as a test, so if a future
change ever breaks an existing container, that test fails before the release does.

Note the distinction, because it matters if you are answering a procurement
questionnaire: implementing FIPS 203 and FIPS 204 correctly is not the same as
holding a CMVP validation certificate. We do the former. We do not claim the
latter.

**Sender attestations are checked earlier.** When you open a file someone sent
you, the proof of who sent it is now verified before any content is written to
disk, rather than just after. It already worked this way for files sealed to your
portable identity; now it works that way on every path.

---

### What happens to your existing data

| You have | What happens |
|---|---|
| `.qvault` files | Open exactly as before. Flagged for optional re-protection. |
| `.qgkey` identities | Import and unlock unchanged, whatever the passphrase. |
| Recipient bundles | Kept. Need one-time verification before sealing. |
| Recovery keys | Unchanged. Still work on a fresh device. |
| Enterprise recovery keys | Unchanged. Existing escrow keys keep working. |
| Messages and calls | Unchanged. Old and new versions interoperate both ways. |
| Web vault identities | Unchanged. Still interoperate in both directions. |

---

### If something looks wrong

**"Verify … before sealing" and you already verified them.** Verification is tied
to the exact fingerprint, not the name. If their fingerprint changed, they
re-issued their identity — or you were handed a different bundle. Check with them
before verifying the new one.

**A container reports it can't be re-protected.** Re-protection needs a key that
can open the container. If it was sealed by a different device and you're not on
that device, use that one, or open it with your recovery key instead.

**The strength meter rejects something you consider strong.** The estimate is
deliberately pessimistic — it would rather refuse a good passphrase than accept a
weak one. Press **Generate** rather than arguing with it.

---

Full technical detail, including what the fingerprint check can and cannot prove,
is in [`SECURITY-HARDENING.md`](./SECURITY-HARDENING.md).
