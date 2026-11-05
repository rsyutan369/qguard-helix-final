//! Hidden vaults: vaults the app never lists, each opened only by drawing its
//! own pattern, kept so that a copy of the disk shows nothing but alike-looking
//! random files.
//!
//! What it protects, and what it cannot:
//! * Nothing in the app names a hidden vault or says one exists. The pattern
//!   pad that opens one is the same pad that opens the Quantum Vault, for
//!   everyone; a pattern that opens nothing is just a wrong pattern.
//! * On disk, every file of every hidden vault — index or content — is pure
//!   AES-256-GCM output or random padding, with a random name, no header, magic
//!   number or extension, in ONE flat folder that every account has, filled
//!   with random cover files when it is created. Without a key nothing tells an
//!   index from a file, a file from a cover, or one vault from another.
//! * Keys come from the pattern AND from this device's secure store (Android
//!   Keystore, Windows Credential Manager): a disk image alone cannot even be
//!   used to test a guess. With the device key an attacker still pays a full
//!   Argon2id (64 MiB, 3 passes) per guess.
//! * There is no cloud copy and no escrow. The only way back in without the
//!   pattern is the vault's own 12-word recovery phrase (BIP-39), if its owner
//!   set one up: the phrase opens a *recovery record* — one more pool file,
//!   alike in every way to the rest — holding the vault's index key, and the
//!   owner then draws a new pattern. The phrase is 128 random bits that only
//!   the owner holds (shown once, never stored); it does not need this
//!   device's secure store, so it still works if that store's key is lost, but
//!   it only opens files that are still in this device's pool. Without the
//!   pattern or the phrase, a hidden vault is gone. Deleting a file removes its
//!   key from the index (the only place it ever existed), then overwrites and
//!   deletes the content; the previous index generation is overwritten too.
//! * The folder's file count is kept on a multiple of [`COVER_BAND`] with cover
//!   files (sized like ordinary files), and every file's modified/accessed
//!   times — and on Windows its created time — are set to one fixed date, so a
//!   file browser shows neither how many vaults there are nor when they were
//!   used.
//! * Decoy vaults and duress erase: any hidden vault can be filled with
//!   harmless files and shown under coercion. One can also be *armed*: the
//!   next time its pattern is drawn on the lock screen, it opens as usual and,
//!   in the background, every other file in the pool is destroyed — the start
//!   of each first (its nonce, so neither an index nor its file keys can ever
//!   be decrypted again), then the whole file — and covers refill the folder.
//!   The flag lives only inside that vault's encrypted index and is cleared the
//!   moment it fires, so the opened vault looks like any other. Opening a vault
//!   from inside the unlocked Quantum Vault never sets it off (that is how the
//!   decoy is looked after). The Quantum Vault itself is never touched.
//! * Limits, stated plainly: an examiner can see the folder's total size, and
//!   if they image the device twice, that it changed; a vault with many files
//!   can push the count past what a decoy alone explains. Filesystem metadata
//!   the app cannot set (Linux/Android change and birth times, NTFS
//!   `$FILE_NAME` times, the folder's own times) still records when files were
//!   written. Flash storage may keep stale copies of overwritten blocks — they
//!   are ciphertext under keys that no longer exist anywhere but in the
//!   pattern. A short or common pattern can be guessed by someone holding the
//!   unlocked device's key material; the lock screen's attempt limit only stops
//!   guessing in the app. A duress erase takes seconds and stops if the app is
//!   killed (it resumes the next time the decoy is drawn); someone watching the
//!   disk while it runs can see it. Anyone who finds a written-down recovery
//!   phrase can open that vault with this device's files, no pattern needed; a
//!   duress erase destroys every other vault's recovery record along with it.
//!
//! Keys (HKDF-SHA3-256 throughout):
//! ```text
//! pool key   = HKDF(device storage key, "pool")
//! pool salt  = HKDF(device storage key, "salt")[..16]
//! vault key  = HKDF(salt = pool salt, Argon2id(pool salt, pattern) ‖ pool key)
//! index key  = HKDF(vault key, "index")
//! index name = HKDF(vault key, "index name" ‖ a|b)[..16], hex
//! file key   = 256 random bits per file, stored only inside the index
//!
//! phrase        = 128 random bits, shown as 12 BIP-39 words
//! recovery key  = HKDF(phrase, "recovery key")
//! recovery name = HKDF(phrase, "recovery name")[..16], hex
//! ```
//! The recovery record holds the index key and both index names, and is
//! rewritten whenever the pattern changes; the index holds the record's name
//! and key (not the phrase), so a vault can rewrite or remove its record.
//!
//! Formats (`‖` = concatenation; every file is padded to a size bucket so its
//! length says little):
//! ```text
//! index  nonce(12) ‖ AES-256-GCM(index key, len(u32 LE) ‖ JSON ‖ zeros) ‖ tag(16)
//! record nonce(12) ‖ AES-256-GCM(recovery key, len(u32 LE) ‖ JSON ‖ zeros) ‖ tag(16)
//! file   for each 1 MiB chunk: nonce(12) ‖ AES-256-GCM(file key, chunk) ‖ tag(16),
//!        then random padding; the chunk AAD binds file id, position and "last"
//! ```

use std::collections::{BTreeMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::provider::{self, Sha3_256Hasher as Sha3_256};
use crate::crypto::symmetric::{self, KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use crate::crypto::{kdf, mnemonic, passcode};
use crate::error::{QGuardError, Result};
use crate::vault::sniff;
use crate::vault::store::{self, HashingReader, StoreEntry, StoreIndex};

const POOL_KEY_INFO: &[u8] = b"QGuard-HiddenVault-Pool-v1";
const POOL_SALT_INFO: &[u8] = b"QGuard-HiddenVault-Salt-v1";
const VAULT_KEY_INFO: &[u8] = b"QGuard-HiddenVault-Key-v1";
const INDEX_KEY_INFO: &[u8] = b"QGuard-HiddenVault-Index-v1";
const INDEX_NAME_INFO: &[u8] = b"QGuard-HiddenVault-IndexName-v1|";
const RECOVERY_KEY_INFO: &[u8] = b"QGuard-HiddenVault-RecoveryKey-v1";
const RECOVERY_NAME_INFO: &[u8] = b"QGuard-HiddenVault-RecoveryName-v1";

const INDEX_VERSION: u8 = 1;
const RECORD_VERSION: u8 = 1;
/// Plaintext bytes per chunk.
pub const CHUNK: u64 = 1024 * 1024;
/// Every pool file is named by this many hex characters.
const NAME_HEX: usize = 32;
const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;
/// Smallest size any pool file has.
const MIN_FILE_BYTES: u64 = 16 * 1024;
/// The pool's file count is always topped up to a multiple of this.
pub const COVER_BAND: usize = 16;
/// A new pool (and the pool after a duress erase) starts with 1 to this many
/// bands of covers, at random.
const COVER_START_BANDS: u64 = 3;
/// Covers are 16 KiB × 2^(0..7): up to 2 MiB, mostly small, like real files.
const COVER_SIZE_DOUBLINGS: u64 = 7;
/// Content beyond this is not overwritten before deletion; it is already
/// unreadable once its key has left the index.
const SHRED_LIMIT: u64 = 64 * 1024 * 1024;
/// A duress erase first overwrites this much of the start of every file: the
/// first nonce of an index or of a file's first chunk is in it.
const HEAD_WIPE: u64 = 64 * 1024;
/// Every pool file carries this modified/accessed time (2020-01-01 UTC).
const POOL_TIME_SECS: u64 = 1_577_836_800;

/// Held while the pool's file count changes, so topping up never miscounts a
/// file that is half written.
static POOL_COUNT: Mutex<()> = Mutex::new(());

fn pool_count_guard() -> std::sync::MutexGuard<'static, ()> {
    POOL_COUNT.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The message for a pattern that cannot be used for a new hidden vault. The
/// same whatever the reason, so trying patterns here teaches nothing.
pub const PATTERN_TAKEN: &str = "Choose a different pattern.";

fn io_err(context: &str, error: io::Error) -> QGuardError {
    QGuardError::Storage(format!("{context}: {error}"))
}

/// The stored size of a file holding `len` bytes: at least 16 KiB, then rounded
/// up to 1/32 of the next power of two — under 6.25 % padding, since `len` is
/// more than half that power.
pub fn padded_len(len: u64) -> u64 {
    if len <= MIN_FILE_BYTES {
        return MIN_FILE_BYTES;
    }
    let step = (len.next_power_of_two() / 32).max(4096);
    len.div_ceil(step) * step
}

fn random_u64() -> u64 {
    u64::from_le_bytes(provider::random_array::<8>())
}

fn write_random<W: Write>(writer: &mut W, mut remaining: u64) -> io::Result<()> {
    let mut noise = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let step = remaining.min(noise.len() as u64) as usize;
        provider::fill_random(&mut noise[..step]);
        writer.write_all(&noise[..step])?;
        remaining -= step as u64;
    }
    Ok(())
}

fn pool_time() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(POOL_TIME_SECS)
}

/// Give a pool file the one fixed date every pool file has. Best effort: a
/// filesystem that refuses still stores the file.
fn settle_times(file: &File) {
    let when = pool_time();
    let times = std::fs::FileTimes::new().set_accessed(when).set_modified(when);
    #[cfg(windows)]
    let times = {
        use std::os::windows::fs::FileTimesExt;
        times.set_created(when)
    };
    let _ = file.set_times(times);
}

/// A cover's size: 16 KiB doubled a random, fractional number of times (up to
/// 2 MiB), on a size bucket like every pool file.
fn cover_len() -> u64 {
    let doublings = (random_u64() % (COVER_SIZE_DOUBLINGS * 1000)) as f64 / 1000.0;
    padded_len((MIN_FILE_BYTES as f64 * doublings.exp2()) as u64)
}

/// How many files a new pool starts with: a random whole number of bands.
fn start_files() -> usize {
    (1 + random_u64() % COVER_START_BANDS) as usize * COVER_BAND
}

/// Overwrite the first [`HEAD_WIPE`] bytes of a file with random bytes.
fn wipe_head(path: &Path) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    let len = file.metadata()?.len().min(HEAD_WIPE);
    write_random(&mut file, len)?;
    file.sync_all()
}

/// Overwrite (up to [`SHRED_LIMIT`]) and delete. Best effort on the overwrite;
/// the delete must happen.
fn shred(path: &Path) -> Result<()> {
    let overwrite = (|| -> io::Result<()> {
        let mut file = OpenOptions::new().write(true).open(path)?;
        let len = file.metadata()?.len().min(SHRED_LIMIT);
        write_random(&mut file, len)?;
        file.sync_all()
    })();
    if let Err(error) = overwrite {
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_err("delete hidden vault file", error)),
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// The device half of every hidden vault key (from the device storage key in
/// the OS secure store).
pub struct PoolSecrets {
    key: Zeroizing<[u8; KEY_SIZE]>,
    salt: [u8; 16],
}

impl PoolSecrets {
    pub fn derive(device_storage_key: &[u8; KEY_SIZE]) -> Result<Self> {
        let key = Zeroizing::new(kdf::derive_32(device_storage_key, POOL_KEY_INFO)?);
        let full = kdf::derive_32(device_storage_key, POOL_SALT_INFO)?;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&full[..16]);
        Ok(Self { key, salt })
    }
}

/// Keys of one hidden vault. Deriving them is the slow step (Argon2id).
#[cfg_attr(test, derive(Clone))]
pub struct HiddenKeys {
    index_key: Zeroizing<[u8; KEY_SIZE]>,
    names: [String; 2],
}

impl HiddenKeys {
    pub fn derive(pool: &PoolSecrets, pattern_secret: &[u8]) -> Result<Self> {
        let stretched = Zeroizing::new(passcode::secret_ikm(passcode::KDF_ARGON2ID_V1, &pool.salt, pattern_secret)?);
        let mut ikm = Zeroizing::new(Vec::with_capacity(stretched.len() + KEY_SIZE));
        ikm.extend_from_slice(&stretched);
        ikm.extend_from_slice(&*pool.key);
        let vault_key = Zeroizing::new(kdf::derive_32_with_salt(&pool.salt, &ikm, VAULT_KEY_INFO)?);
        let index_key = Zeroizing::new(kdf::derive_32(&*vault_key, INDEX_KEY_INFO)?);
        let name = |slot: &[u8]| -> Result<String> {
            let derived = Zeroizing::new(kdf::derive_32(&*vault_key, &[INDEX_NAME_INFO, slot].concat())?);
            Ok(hex::encode(&derived[..NAME_HEX / 2]))
        };
        Ok(Self { index_key, names: [name(b"a")?, name(b"b")?] })
    }

    /// The keys a recovery record holds.
    fn from_record(record: &RecoveryRecord) -> Result<Self> {
        let mut index_key = Zeroizing::new([0u8; KEY_SIZE]);
        hex::decode_to_slice(&record.index_key, &mut *index_key)
            .map_err(|_| QGuardError::Crypto("hidden vault recovery record is damaged".to_string()))?;
        Ok(Self { index_key, names: record.names.clone() })
    }
}

/// The keys a recovery phrase gives: where its record is and what opens it.
pub struct RecoveryKeys {
    key: Zeroizing<[u8; KEY_SIZE]>,
    name: String,
}

impl RecoveryKeys {
    pub fn derive(phrase_entropy: &[u8; mnemonic::ENTROPY_BYTES]) -> Result<Self> {
        let key = Zeroizing::new(kdf::derive_32(phrase_entropy, RECOVERY_KEY_INFO)?);
        let name = Zeroizing::new(kdf::derive_32(phrase_entropy, RECOVERY_NAME_INFO)?);
        Ok(Self { key, name: hex::encode(&name[..NAME_HEX / 2]) })
    }

    fn reference(&self) -> RecoveryRef {
        RecoveryRef { name: self.name.clone(), key: hex::encode(*self.key) }
    }
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

/// One account's pool folder.
#[derive(Clone, Debug)]
pub struct Pool {
    dir: PathBuf,
}

impl Pool {
    /// `safe_user` must already be filesystem-safe (`AppState::safe_user_key`).
    pub fn new(data_dir: &Path, safe_user: &str) -> Self {
        Self { dir: data_dir.join("vault").join("pool").join(safe_user) }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn new_name() -> String {
        hex::encode(provider::random_array::<{ NAME_HEX / 2 }>())
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        if name.len() != NAME_HEX || !name.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(QGuardError::Storage("invalid hidden vault file name".to_string()));
        }
        Ok(self.dir.join(name))
    }

    fn names(&self) -> Vec<PathBuf> {
        std::fs::read_dir(&self.dir)
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default()
    }

    /// Create the folder with its covers if needed, and keep its file count on
    /// a band. Every account gets one, hidden vault or not, and a new one holds
    /// a random 1 to [`COVER_START_BANDS`] bands of covers, so neither having a
    /// pool nor its first few bands says that a vault exists.
    pub fn ensure(&self) -> Result<()> {
        let fresh = self.names().is_empty();
        self.fill_to(if fresh { start_files() } else { 0 })
    }

    /// Add covers until the file count is a non-zero multiple of
    /// [`COVER_BAND`]. Covers are never removed (nothing records which files
    /// are covers), so the count only ever moves up a band.
    pub fn top_up(&self) -> Result<()> {
        self.fill_to(0)
    }

    /// Add covers until there are at least `min_files` files and the count is
    /// on a band.
    fn fill_to(&self, min_files: usize) -> Result<()> {
        let _counting = pool_count_guard();
        std::fs::create_dir_all(&self.dir).map_err(|e| io_err("create hidden vault pool", e))?;
        let count = self.names().len();
        let target = count.max(min_files).div_ceil(COVER_BAND).max(1) * COVER_BAND;
        for _ in count..target {
            let len = cover_len();
            self.write_new(&Self::new_name(), |writer| write_random(writer, len))?;
        }
        Ok(())
    }

    /// Wipe every file of every hidden vault on this device and start a new
    /// pool. Needs no pattern: it can only destroy.
    pub fn erase_all(&self) -> Result<()> {
        for path in self.names() {
            if path.is_file() {
                shred(&path)?;
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
        self.ensure()
    }

    /// Write a complete file under `name`: through a temporary file of the same
    /// kind of name, flushed to disk, then renamed into place.
    fn write_new(&self, name: &str, fill: impl FnOnce(&mut BufWriter<File>) -> io::Result<()>) -> Result<()> {
        let target = self.path(name)?;
        let temp = self.path(&Self::new_name())?;
        let written = (|| -> io::Result<()> {
            let mut writer = BufWriter::new(File::create(&temp)?);
            fill(&mut writer)?;
            writer.flush()?;
            settle_times(writer.get_ref());
            writer.get_ref().sync_all()
        })();
        if let Err(error) = written {
            let _ = std::fs::remove_file(&temp);
            return Err(io_err("write hidden vault file", error));
        }
        std::fs::rename(&temp, &target).map_err(|e| {
            let _ = std::fs::remove_file(&temp);
            io_err("store hidden vault file", e)
        })
    }
}

// ---------------------------------------------------------------------------
// Index
// ---------------------------------------------------------------------------

/// Where one file's content is and the key that opens it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HiddenFile {
    blob: String,
    key: String,
    /// Bytes of chunk data in the blob (the rest is padding).
    stored_len: u64,
}

impl Drop for HiddenFile {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HiddenIndex {
    version: u8,
    generation: u64,
    created_at: DateTime<Utc>,
    /// Folders and files, with the vault's ordinary tree rules (names unique
    /// per folder, no folder moved into itself). Its activity log stays empty.
    tree: StoreIndex,
    files: BTreeMap<String, HiddenFile>,
    /// Armed for duress erase (see the module notes). Absent in indexes from
    /// before decoys existed, which reads as not armed.
    #[serde(default)]
    duress_erase: bool,
    /// This vault's recovery record, if a phrase is set up. Absent in indexes
    /// from before recovery phrases existed.
    #[serde(default)]
    recovery: Option<RecoveryRef>,
}

/// Where a vault's recovery record is and the key that seals it (derived from
/// the phrase; the phrase itself is never stored).
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryRef {
    name: String,
    key: String,
}

impl Drop for RecoveryRef {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl RecoveryRef {
    fn keys(&self) -> Result<RecoveryKeys> {
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        hex::decode_to_slice(&self.key, &mut *key).map_err(|_| QGuardError::Crypto("hidden vault recovery key is damaged".to_string()))?;
        Ok(RecoveryKeys { key, name: self.name.clone() })
    }
}

/// What a recovery record holds: enough to open the vault's index.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryRecord {
    version: u8,
    index_key: String,
    names: [String; 2],
}

impl Drop for RecoveryRecord {
    fn drop(&mut self) {
        self.index_key.zeroize();
    }
}

fn index_aad(user_id: &str, name: &str) -> Vec<u8> {
    format!("QGHV-Index-v1|{user_id}|{name}").into_bytes()
}

fn record_aad(user_id: &str, name: &str) -> Vec<u8> {
    format!("QGHV-Recovery-v1|{user_id}|{name}").into_bytes()
}

fn chunk_aad(file_id: &str, position: u64, last: bool) -> Vec<u8> {
    format!("QGHV-Chunk-v1|{file_id}|{position}|{}", u8::from(last)).into_bytes()
}

/// `value` as JSON, length-prefixed, zero-padded to a size bucket and sealed:
/// the one shape of every index and recovery record.
fn seal_padded<T: Serialize>(key: &[u8; KEY_SIZE], aad: &[u8], value: &T) -> Result<Vec<u8>> {
    let json = Zeroizing::new(serde_json::to_vec(value).map_err(|e| QGuardError::Storage(format!("encode hidden vault index: {e}")))?);
    let total = padded_len((NONCE_SIZE + 4 + json.len() + TAG_SIZE) as u64) as usize;
    let mut plain = Zeroizing::new(vec![0u8; total - NONCE_SIZE - TAG_SIZE]);
    plain[..4].copy_from_slice(&(json.len() as u32).to_le_bytes());
    plain[4..4 + json.len()].copy_from_slice(&json);
    let sealed = provider::aes256gcm_seal(key, aad, &plain)?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.ciphertext);
    out.extend_from_slice(&sealed.tag);
    Ok(out)
}

fn open_padded<T: serde::de::DeserializeOwned>(key: &[u8; KEY_SIZE], aad: &[u8], bytes: &[u8]) -> Result<T> {
    if bytes.len() < NONCE_SIZE + 4 + TAG_SIZE {
        return Err(QGuardError::Crypto("hidden vault index is too short".to_string()));
    }
    let (nonce, rest) = bytes.split_at(NONCE_SIZE);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_SIZE);
    let plain = Zeroizing::new(provider::aes256gcm_open(key, nonce, aad, ciphertext, tag)?);
    let len = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
    let json = plain.get(4..4 + len).ok_or_else(|| QGuardError::Crypto("hidden vault index is damaged".to_string()))?;
    serde_json::from_slice(json).map_err(|e| QGuardError::Storage(format!("decode hidden vault index: {e}")))
}

fn seal_index(keys: &HiddenKeys, user_id: &str, name: &str, index: &HiddenIndex) -> Result<Vec<u8>> {
    seal_padded(&keys.index_key, &index_aad(user_id, name), index)
}

fn open_index(keys: &HiddenKeys, user_id: &str, name: &str, bytes: &[u8]) -> Result<HiddenIndex> {
    let index: HiddenIndex = open_padded(&keys.index_key, &index_aad(user_id, name), bytes)?;
    if index.version != INDEX_VERSION {
        return Err(QGuardError::Storage("hidden vault index from a newer app version".to_string()));
    }
    Ok(index)
}

fn seal_record(recovery: &RecoveryKeys, user_id: &str, keys: &HiddenKeys) -> Result<Vec<u8>> {
    let record = RecoveryRecord { version: RECORD_VERSION, index_key: hex::encode(*keys.index_key), names: keys.names.clone() };
    seal_padded(&recovery.key, &record_aad(user_id, &recovery.name), &record)
}

fn open_record(recovery: &RecoveryKeys, user_id: &str, bytes: &[u8]) -> Result<RecoveryRecord> {
    let record: RecoveryRecord = open_padded(&recovery.key, &record_aad(user_id, &recovery.name), bytes)?;
    if record.version != RECORD_VERSION {
        return Err(QGuardError::Storage("hidden vault recovery record from a newer app version".to_string()));
    }
    Ok(record)
}

// ---------------------------------------------------------------------------
// An open hidden vault
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HiddenSummary {
    pub files: u64,
    pub folders: u64,
    pub bytes: u64,
    pub created_at: DateTime<Utc>,
    /// Armed: drawing this vault's pattern on the lock screen erases every
    /// other hidden vault. Always false once it has fired.
    pub duress_erase: bool,
    /// A 12-word recovery phrase is set up for this vault.
    pub recovery_phrase: bool,
}

pub struct HiddenVault {
    pool: Pool,
    user_id: String,
    keys: HiddenKeys,
    index: HiddenIndex,
    /// Which of the two index names holds the current generation.
    slot: usize,
    /// Set by [`HiddenVault::destroy`]: nothing may be written for it again.
    destroyed: bool,
}

/// What a duress erase destroys, fixed at the moment the decoy opened.
pub struct DuressPlan {
    pool: Pool,
    targets: Vec<PathBuf>,
}

impl DuressPlan {
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }
}

/// Carry out a duress erase for the decoy in `vault`, which is already open
/// and in use. In order: the start of every other pool file (so no index and
/// no file key can be decrypted again even if the app is killed next), the
/// decoy's disarmed index to disk (until then a restart would fire it again),
/// every other file overwritten and deleted, then covers as in a new pool.
/// Files the decoy writes meanwhile were not in the plan and are never
/// touched. Nothing stops it part way: a decoy deleted meanwhile, or an index
/// that cannot be written, still leaves every other file destroyed.
pub fn run_duress(plan: DuressPlan, vault: &Mutex<HiddenVault>) -> Result<()> {
    for path in &plan.targets {
        let _ = wipe_head(path);
    }
    if let Ok(mut guard) = vault.lock() {
        let _ = guard.persist();
    }
    for path in &plan.targets {
        let _ = shred(path);
    }
    plan.pool.fill_to(start_files())
}

fn chunk_count(size: u64) -> u64 {
    size.div_ceil(CHUNK).max(1)
}

fn chunk_len(size: u64, position: u64) -> usize {
    size.saturating_sub(position * CHUNK).min(CHUNK) as usize
}

/// Read until `buf` is full or the source ends.
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

impl HiddenVault {
    /// The vault these keys open, if there is one. A file at one of its names
    /// that does not open (a write cut short) is passed over.
    pub fn open(pool: Pool, user_id: &str, keys: HiddenKeys) -> Result<Option<Self>> {
        let mut best: Option<(usize, HiddenIndex)> = None;
        for slot in 0..2 {
            let path = pool.path(&keys.names[slot])?;
            let bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(io_err("read hidden vault", error)),
            };
            if bytes.len() as u64 > MAX_INDEX_BYTES {
                continue;
            }
            if let Ok(index) = open_index(&keys, user_id, &keys.names[slot], &bytes) {
                if best.as_ref().map_or(true, |(_, current)| index.generation > current.generation) {
                    best = Some((slot, index));
                }
            }
        }
        Ok(best.map(|(slot, index)| Self { pool, user_id: user_id.to_string(), keys, index, slot, destroyed: false }))
    }

    /// A new, empty vault for these keys. Refused if anything is at either of
    /// its names already.
    pub fn create(pool: Pool, user_id: &str, keys: HiddenKeys) -> Result<Self> {
        pool.ensure()?;
        for name in &keys.names {
            if pool.path(name)?.exists() {
                return Err(QGuardError::InvalidInput(PATTERN_TAKEN.to_string()));
            }
        }
        let index = HiddenIndex {
            version: INDEX_VERSION,
            generation: 1,
            created_at: Utc::now(),
            tree: StoreIndex::new(),
            files: BTreeMap::new(),
            duress_erase: false,
            recovery: None,
        };
        let bytes = seal_index(&keys, user_id, &keys.names[0], &index)?;
        {
            let _counting = pool_count_guard();
            pool.write_new(&keys.names[0], |writer| writer.write_all(&bytes))?;
        }
        let _ = pool.top_up();
        Ok(Self { pool, user_id: user_id.to_string(), keys, index, slot: 0, destroyed: false })
    }

    pub fn summary(&self) -> HiddenSummary {
        let tree = &self.index.tree;
        HiddenSummary {
            files: tree.entries.iter().filter(|e| e.is_file()).count() as u64,
            folders: tree.entries.iter().filter(|e| e.is_folder()).count() as u64,
            bytes: tree.entries.iter().filter(|e| e.is_file()).map(|e| e.size_bytes).sum(),
            created_at: self.index.created_at,
            duress_erase: self.index.duress_erase,
            recovery_phrase: self.index.recovery.is_some(),
        }
    }

    /// The vault a recovery phrase opens, if it opens one: its record, then the
    /// index the record names. A record the index no longer names (replaced by
    /// a newer phrase) opens nothing.
    pub fn recover(pool: Pool, user_id: &str, phrase_entropy: &[u8; mnemonic::ENTROPY_BYTES]) -> Result<Option<Self>> {
        let recovery = RecoveryKeys::derive(phrase_entropy)?;
        let bytes = match std::fs::read(pool.path(&recovery.name)?) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_err("read hidden vault", error)),
        };
        if bytes.len() as u64 > MAX_INDEX_BYTES {
            return Ok(None);
        }
        let Ok(record) = open_record(&recovery, user_id, &bytes) else {
            return Ok(None);
        };
        let vault = Self::open(pool, user_id, HiddenKeys::from_record(&record)?)?;
        Ok(vault.filter(|vault| vault.index.recovery.as_ref().is_some_and(|current| current.name == recovery.name)))
    }

    /// Write (or replace) the recovery record at `recovery` so it opens `keys`.
    fn write_record(&self, recovery: &RecoveryKeys, keys: &HiddenKeys) -> Result<()> {
        let bytes = seal_record(recovery, &self.user_id, keys)?;
        let _counting = pool_count_guard();
        self.pool.write_new(&recovery.name, |writer| writer.write_all(&bytes))
    }

    /// Set up a new recovery phrase for this vault, replacing any earlier one
    /// (which stops working). Returns the phrase's entropy: shown once, never
    /// stored.
    pub fn set_up_recovery(&mut self) -> Result<Zeroizing<[u8; mnemonic::ENTROPY_BYTES]>> {
        if self.destroyed {
            return Err(QGuardError::NotFound("this hidden vault was deleted".to_string()));
        }
        // A name already in the pool is astronomically unlikely; never reuse one.
        let (entropy, recovery) = loop {
            let entropy = mnemonic::generate();
            let recovery = RecoveryKeys::derive(&entropy)?;
            if !self.pool.path(&recovery.name)?.exists() {
                break (entropy, recovery);
            }
        };
        self.write_record(&recovery, &self.keys)?;
        let previous = self.index.recovery.clone();
        if let Err(error) = self.commit(|index| {
            index.recovery = Some(recovery.reference());
            Ok(())
        }) {
            let _ = shred(&self.pool.path(&recovery.name)?);
            return Err(error);
        }
        if let Some(previous) = previous {
            let _ = shred(&self.pool.path(&previous.name)?);
        }
        let _ = self.pool.top_up();
        Ok(entropy)
    }

    /// Remove this vault's recovery phrase: the record is destroyed, and from
    /// then on only the pattern opens the vault.
    pub fn remove_recovery(&mut self) -> Result<()> {
        let Some(previous) = self.index.recovery.clone() else {
            return Ok(());
        };
        self.commit(|index| {
            index.recovery = None;
            Ok(())
        })?;
        shred(&self.pool.path(&previous.name)?)?;
        let _ = self.pool.top_up();
        Ok(())
    }

    /// Move this vault to the keys of a new pattern (after a recovery). In
    /// order: the index under the new names; the recovery record, so the phrase
    /// opens the new keys; only then the old index destroyed. Refused, with
    /// nothing changed, if the new pattern's names are already in the pool.
    pub fn rekey(&mut self, keys: HiddenKeys) -> Result<()> {
        if self.destroyed {
            return Err(QGuardError::NotFound("this hidden vault was deleted".to_string()));
        }
        if keys.names == self.keys.names {
            return Ok(());
        }
        for name in &keys.names {
            if self.pool.path(name)?.exists() {
                return Err(QGuardError::InvalidInput(PATTERN_TAKEN.to_string()));
            }
        }
        let mut next = self.index.clone();
        next.generation += 1;
        let bytes = seal_index(&keys, &self.user_id, &keys.names[0], &next)?;
        {
            let _counting = pool_count_guard();
            self.pool.write_new(&keys.names[0], |writer| writer.write_all(&bytes))?;
        }
        if let Some(reference) = next.recovery.as_ref() {
            if let Err(error) = reference.keys().and_then(|recovery| self.write_record(&recovery, &keys)) {
                let _ = shred(&self.pool.path(&keys.names[0])?);
                return Err(error);
            }
        }
        let old = std::mem::replace(&mut self.keys, keys);
        {
            let _counting = pool_count_guard();
            for name in &old.names {
                let _ = shred(&self.pool.path(name)?);
            }
        }
        self.index = next;
        self.slot = 0;
        let _ = self.pool.top_up();
        Ok(())
    }

    /// Arm or disarm duress erase for this vault.
    pub fn set_duress_erase(&mut self, armed: bool) -> Result<()> {
        if self.index.duress_erase == armed {
            return Ok(());
        }
        self.commit(|index| {
            index.duress_erase = armed;
            Ok(())
        })
    }

    /// For a vault just opened from the lock screen, before anything else can
    /// use it: if it is armed, disarm it in memory (so it shows as an ordinary
    /// vault from the first moment) and list every pool file that is not its
    /// own. [`run_duress`] destroys them and writes the disarmed index.
    pub fn take_duress(&mut self) -> Option<DuressPlan> {
        if !self.index.duress_erase {
            return None;
        }
        self.index.duress_erase = false;
        // The decoy's own index, files and recovery record survive; every other
        // vault's — recovery records included — does not.
        let own: HashSet<&str> = self
            .keys
            .names
            .iter()
            .map(String::as_str)
            .chain(self.index.files.values().map(|file| file.blob.as_str()))
            .chain(self.index.recovery.iter().map(|recovery| recovery.name.as_str()))
            .collect();
        let targets = self
            .pool
            .names()
            .into_iter()
            .filter(|path| path.file_name().and_then(|name| name.to_str()).map_or(true, |name| !own.contains(name)))
            .collect();
        Some(DuressPlan { pool: self.pool.clone(), targets })
    }

    /// Write the index as it is in memory, as a new generation.
    fn persist(&mut self) -> Result<()> {
        self.commit(|_| Ok(()))
    }

    pub fn entries(&self) -> Vec<StoreEntry> {
        self.index.tree.entries.clone()
    }

    pub fn require_file(&self, id: &str) -> Result<StoreEntry> {
        let entry = self.index.tree.require(&store::checked_id(id)?)?;
        if !entry.is_file() {
            return Err(QGuardError::InvalidInput("this action needs a file, not a folder".to_string()));
        }
        Ok(entry.clone())
    }

    /// Change the index and write the next generation, or change nothing. The
    /// generation it replaces is overwritten: no older copy of the file keys
    /// stays behind on disk.
    fn commit<T>(&mut self, change: impl FnOnce(&mut HiddenIndex) -> Result<T>) -> Result<T> {
        if self.destroyed {
            return Err(QGuardError::NotFound("this hidden vault was deleted".to_string()));
        }
        let mut next = self.index.clone();
        let out = change(&mut next)?;
        next.generation += 1;
        let target = 1 - self.slot;
        let bytes = seal_index(&self.keys, &self.user_id, &self.keys.names[target], &next)?;
        {
            let _counting = pool_count_guard();
            shred(&self.pool.path(&self.keys.names[target])?)?;
            self.pool.write_new(&self.keys.names[target], |writer| writer.write_all(&bytes))?;
            let _ = shred(&self.pool.path(&self.keys.names[self.slot])?);
        }
        self.index = next;
        self.slot = target;
        Ok(out)
    }

    pub fn create_folder(&mut self, parent_id: Option<&str>, name: &str) -> Result<StoreEntry> {
        self.commit(|index| index.tree.create_folder(parent_id, name))
    }

    pub fn rename(&mut self, id: &str, name: &str) -> Result<StoreEntry> {
        let id = store::checked_id(id)?;
        self.commit(|index| index.tree.rename(&id, name))
    }

    pub fn move_entries(&mut self, ids: &[String], parent_id: Option<&str>) -> Result<Vec<StoreEntry>> {
        self.commit(|index| ids.iter().map(|id| index.tree.move_entry(&store::checked_id(id)?, parent_id)).collect())
    }

    /// Delete permanently (folders with everything in them). The keys leave
    /// the index first; only then is the content overwritten and deleted.
    pub fn delete(&mut self, ids: &[String]) -> Result<u64> {
        let mut doomed: HashSet<String> = HashSet::new();
        for id in ids {
            let id = store::checked_id(id)?;
            self.index.tree.require(&id)?;
            doomed.extend(self.index.tree.subtree(&id));
        }
        let blobs: Vec<String> = doomed.iter().filter_map(|id| self.index.files.get(id).map(|f| f.blob.clone())).collect();
        self.commit(|index| {
            index.tree.remove(&doomed);
            index.files.retain(|id, _| !doomed.contains(id));
            Ok(())
        })?;
        for blob in blobs {
            let _ = shred(&self.pool.path(&blob)?);
        }
        let _ = self.pool.top_up();
        Ok(doomed.len() as u64)
    }

    /// Encrypt one file into the vault. The content is written and flushed
    /// before the index names it; a failure on the way leaves nothing behind.
    pub fn import<R: Read>(
        &mut self,
        source: R,
        raw_name: &str,
        parent_id: Option<&str>,
        expected_size: u64,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<StoreEntry> {
        let name = store::clean_name(raw_name)?;
        if expected_size > store::MAX_IMPORT_BYTES {
            return Err(QGuardError::InvalidInput(format!(
                "{name} is larger than the {} GB per-file limit",
                store::MAX_IMPORT_BYTES / (1024 * 1024 * 1024)
            )));
        }
        let mut reader = BufReader::new(source);
        let mut head = vec![0u8; sniff::SNIFF_LEN];
        let head_len = read_full(&mut reader, &mut head).map_err(|e| io_err("read source file", e))?;
        head.truncate(head_len);
        let detected = sniff::sniff(&head, &name);
        let mut hashing = HashingReader::new(Cursor::new(head).chain(reader));

        let id = uuid::Uuid::new_v4().to_string();
        let key = Zeroizing::new(symmetric::random_key());
        let blob = Pool::new_name();
        let path = self.pool.path(&blob)?;
        let written = (|| -> Result<(u64, u64, u64)> {
            let mut writer = BufWriter::new(File::create(&path).map_err(|e| io_err("create hidden vault file", e))?);
            let (mut position, mut size, mut stored) = (0u64, 0u64, 0u64);
            let mut current = Zeroizing::new(vec![0u8; CHUNK as usize]);
            let mut filled = read_full(&mut hashing, &mut current).map_err(|e| io_err("read source file", e))?;
            loop {
                let mut next = Zeroizing::new(vec![0u8; CHUNK as usize]);
                let next_filled = if filled == CHUNK as usize {
                    read_full(&mut hashing, &mut next).map_err(|e| io_err("read source file", e))?
                } else {
                    0
                };
                let last = next_filled == 0;
                let sealed = provider::aes256gcm_seal(&key, &chunk_aad(&id, position, last), &current[..filled])?;
                writer
                    .write_all(&sealed.nonce)
                    .and_then(|_| writer.write_all(&sealed.ciphertext))
                    .and_then(|_| writer.write_all(&sealed.tag))
                    .map_err(|e| io_err("write hidden vault file", e))?;
                size += filled as u64;
                stored += (NONCE_SIZE + filled + TAG_SIZE) as u64;
                progress(size, expected_size.max(size));
                if size > store::MAX_IMPORT_BYTES {
                    return Err(QGuardError::InvalidInput("the file is larger than the per-file limit".to_string()));
                }
                if last {
                    break;
                }
                current = next;
                filled = next_filled;
                position += 1;
            }
            let padded = padded_len(stored);
            write_random(&mut writer, padded - stored).map_err(|e| io_err("write hidden vault file", e))?;
            writer
                .flush()
                .map(|_| settle_times(writer.get_ref()))
                .and_then(|_| writer.get_ref().sync_all())
                .map_err(|e| io_err("flush hidden vault file", e))?;
            Ok((size, stored, position + 1))
        })();
        let (size, stored, chunks) = match written {
            Ok(done) => done,
            Err(error) => {
                let _ = shred(&path);
                return Err(error);
            }
        };
        let (plaintext_sha3, _) = hashing.finish();

        let now = Utc::now();
        let entry = StoreEntry {
            id: id.clone(),
            kind: store::KIND_FILE.to_string(),
            name,
            parent_id: parent_id.map(str::to_string),
            created_at: now,
            updated_at: now,
            trashed_at: None,
            favorite: false,
            size_bytes: size,
            stored_bytes: padded_len(stored),
            content_type: detected.content_type.clone(),
            category: detected.category.as_str().to_string(),
            type_check: detected.type_check.as_str().to_string(),
            plaintext_sha3,
            container_version: 0,
            pin_bound: false,
            total_chunks: chunks,
            recovery_protected: false,
            integrity: store::INTEGRITY_VERIFIED.to_string(),
            last_verified_at: None,
            has_thumbnail: false,
            cloud_object_id: None,
            cloud_backed_up_at: None,
            library_fek: None,
            available_offline: true,
            cloud_shared_only: false,
        };
        let record = HiddenFile { blob, key: hex::encode(*key), stored_len: stored };
        let committed = self.commit(|index| {
            let entry = index.tree.insert_file(entry)?;
            index.files.insert(entry.id.clone(), record);
            Ok(entry)
        });
        if committed.is_err() {
            let _ = shred(&path);
        }
        let _ = self.pool.top_up();
        committed
    }

    /// Decrypt a file into `writer`: every chunk's tag (bound to the file, its
    /// position and whether it is the last), then the SHA3-256 recorded when
    /// it was added. A writer that receives an error must be discarded.
    pub fn read_into<W: Write>(&self, id: &str, mut writer: W, progress: &mut dyn FnMut(u64, u64)) -> Result<W> {
        let entry = self.require_file(id)?;
        let record = self
            .index
            .files
            .get(&entry.id)
            .ok_or_else(|| QGuardError::NotFound("the hidden vault has no content for this file".to_string()))?;
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        hex::decode_to_slice(&record.key, &mut *key).map_err(|_| QGuardError::Crypto("hidden vault file key is damaged".to_string()))?;
        let mut reader = BufReader::new(
            File::open(self.pool.path(&record.blob)?).map_err(|e| io_err("open hidden vault file", e))?,
        );
        let chunks = chunk_count(entry.size_bytes);
        let mut hasher = Sha3_256::new();
        let mut done = 0u64;
        for position in 0..chunks {
            let len = chunk_len(entry.size_bytes, position);
            let mut nonce = [0u8; NONCE_SIZE];
            let mut ciphertext = vec![0u8; len];
            let mut tag = [0u8; TAG_SIZE];
            reader
                .read_exact(&mut nonce)
                .and_then(|_| reader.read_exact(&mut ciphertext))
                .and_then(|_| reader.read_exact(&mut tag))
                .map_err(|_| QGuardError::Crypto("the hidden vault file is shorter than recorded".to_string()))?;
            let plain = Zeroizing::new(provider::aes256gcm_open(
                &key,
                &nonce,
                &chunk_aad(&entry.id, position, position + 1 == chunks),
                &ciphertext,
                &tag,
            )?);
            hasher.update(&plain);
            writer.write_all(&plain).map_err(|e| io_err("write output", e))?;
            done += len as u64;
            progress(done, entry.size_bytes);
        }
        if hex::encode(hasher.finalize()) != entry.plaintext_sha3 {
            return Err(QGuardError::Crypto("content does not match the SHA3-256 recorded when it was sealed".to_string()));
        }
        Ok(writer)
    }

    /// Destroy this vault: its recovery record and both index generations
    /// (after which nothing can open it), then every file's content. What
    /// stays in memory is emptied too; the session should be closed next.
    pub fn destroy(&mut self) -> Result<()> {
        self.destroyed = true;
        if let Some(recovery) = self.index.recovery.take() {
            shred(&self.pool.path(&recovery.name)?)?;
        }
        for name in &self.keys.names {
            shred(&self.pool.path(name)?)?;
        }
        for record in self.index.files.values() {
            shred(&self.pool.path(&record.blob)?)?;
        }
        self.index.files.clear();
        self.index.tree = StoreIndex::new();
        let _ = self.pool.top_up();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_pool() -> (Pool, PathBuf) {
        let root = std::env::temp_dir().join(format!("qguard-hidden-test-{}", uuid::Uuid::new_v4()));
        (Pool::new(&root, "user"), root)
    }

    fn secrets(seed: u8) -> PoolSecrets {
        PoolSecrets::derive(&[seed; KEY_SIZE]).unwrap()
    }

    fn keys(pool: &PoolSecrets, pattern: &str) -> HiddenKeys {
        HiddenKeys::derive(pool, &crate::vault::pattern::secret_bytes(pattern).unwrap()).unwrap()
    }

    const PATTERN: &str = "4x4:0-1-2-3-7-11";
    const OTHER: &str = "4x4:12-13-14-15-11-7";

    fn pool_files(pool: &Pool) -> Vec<(String, Vec<u8>)> {
        let mut files: Vec<(String, Vec<u8>)> = pool
            .names()
            .into_iter()
            .map(|path| (path.file_name().unwrap().to_string_lossy().to_string(), std::fs::read(&path).unwrap()))
            .collect();
        files.sort();
        files
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|window| window == needle)
    }

    fn read_back(vault: &HiddenVault, id: &str) -> Vec<u8> {
        vault.read_into(id, Vec::new(), &mut |_, _| {}).unwrap()
    }

    #[test]
    fn a_pool_starts_with_covers_that_look_like_everything_else() {
        let (pool, root) = temp_pool();
        pool.ensure().unwrap();
        let files = pool_files(&pool);
        assert!(files.len() % COVER_BAND == 0 && (COVER_BAND..=COVER_BAND * COVER_START_BANDS as usize).contains(&files.len()));
        for (name, bytes) in &files {
            assert_eq!(name.len(), NAME_HEX);
            assert_eq!(bytes.len() as u64, padded_len(bytes.len() as u64), "covers sit on a size bucket");
            assert!((MIN_FILE_BYTES..=2 * 1024 * 1024).contains(&(bytes.len() as u64)));
        }
        for path in pool.names() {
            assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), pool_time(), "{}", path.display());
        }
        // Ensuring again changes nothing.
        pool.ensure().unwrap();
        assert_eq!(pool_files(&pool), files);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_file_goes_in_comes_back_and_nothing_on_disk_says_what_it_is() {
        let (pool, root) = temp_pool();
        let device = secrets(7);
        let mut vault = HiddenVault::create(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap();
        let photo = [b"\xFF\xD8\xFF\xE0".as_slice(), b"secret holiday ", &vec![42u8; (CHUNK as usize) * 2 + 17]].concat();
        let folder = vault.create_folder(None, "Passports").unwrap();
        let entry = vault.import(Cursor::new(photo.clone()), "passport-scan.jpg", Some(&folder.id), photo.len() as u64, &mut |_, _| {}).unwrap();
        assert_eq!((entry.content_type.as_str(), entry.category.as_str(), entry.total_chunks), ("image/jpeg", "image", 3));
        assert_eq!(read_back(&vault, &entry.id), photo);

        // Reopened from disk with the same pattern on the same device.
        let reopened = HiddenVault::open(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap().expect("vault");
        assert_eq!(reopened.entries().len(), 2);
        assert_eq!(read_back(&reopened, &entry.id), photo);

        // Every pool file: a 32-hex name, a bucket size, and not one readable
        // byte. (Needles are long enough that random bytes never match them.)
        for (name, bytes) in pool_files(&pool) {
            assert!(name.len() == NAME_HEX && name.bytes().all(|b| b.is_ascii_hexdigit()));
            assert_eq!(bytes.len() as u64, padded_len(bytes.len() as u64));
            for needle in [&b"passport"[..], b"Passports", b"image/jpeg", b"secret holiday", b"QGHV-", b"\"name\"", b"plaintextSha3"] {
                assert!(!contains(&bytes, needle), "{:?} is readable in {name}", String::from_utf8_lossy(needle));
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_vault_opens_only_with_its_pattern_its_device_and_its_account() {
        let (pool, root) = temp_pool();
        let device = secrets(7);
        HiddenVault::create(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap();
        assert!(HiddenVault::open(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap().is_some());
        // Another pattern opens nothing (and says nothing about this vault).
        assert!(HiddenVault::open(pool.clone(), "user-1", keys(&device, OTHER)).unwrap().is_none());
        // The same pattern without this device's secure-store key opens nothing.
        assert!(HiddenVault::open(pool.clone(), "user-1", keys(&secrets(8), PATTERN)).unwrap().is_none());
        // Nor under another account.
        assert!(HiddenVault::open(pool.clone(), "user-2", keys(&device, PATTERN)).unwrap().is_none());
        // A pattern already in use cannot make a second vault.
        let taken = HiddenVault::create(pool.clone(), "user-1", keys(&device, PATTERN)).err().expect("refused");
        assert!(taken.to_string().contains(PATTERN_TAKEN));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn two_vaults_share_the_pool_without_seeing_each_other() {
        let (pool, root) = temp_pool();
        let device = secrets(7);
        let mut a = HiddenVault::create(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap();
        let mut b = HiddenVault::create(pool.clone(), "user-1", keys(&device, OTHER)).unwrap();
        a.import(Cursor::new(b"for a".to_vec()), "a.txt", None, 5, &mut |_, _| {}).unwrap();
        b.import(Cursor::new(b"for b".to_vec()), "b.txt", None, 5, &mut |_, _| {}).unwrap();
        let a = HiddenVault::open(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap().unwrap();
        let b = HiddenVault::open(pool.clone(), "user-1", keys(&device, OTHER)).unwrap().unwrap();
        assert_eq!(a.entries().iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), vec!["a.txt"]);
        assert_eq!(b.entries().iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), vec!["b.txt"]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn deleting_takes_the_key_out_first_and_leaves_no_older_index_behind() {
        let (pool, root) = temp_pool();
        let device = secrets(7);
        let mut vault = HiddenVault::create(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap();
        let folder = vault.create_folder(None, "Tax").unwrap();
        let inner = vault.import(Cursor::new(b"2025 return".to_vec()), "return.pdf", Some(&folder.id), 11, &mut |_, _| {}).unwrap();
        let kept = vault.import(Cursor::new(b"keep me".to_vec()), "keep.txt", None, 7, &mut |_, _| {}).unwrap();
        let blob = vault.index.files[&inner.id].blob.clone();

        assert_eq!(vault.delete(&[folder.id.clone()]).unwrap(), 2);
        assert!(!pool.path(&blob).unwrap().exists(), "the content is gone");
        let generations = vault.keys.names.iter().filter(|name| pool.path(name).unwrap().exists()).count();
        assert_eq!(generations, 1, "one index generation remains, never two");
        assert_eq!(pool_files(&pool).len() % COVER_BAND, 0, "a cover takes the deleted file's place in the count");
        let reopened = HiddenVault::open(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap().unwrap();
        assert_eq!(reopened.entries().iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), vec![kept.id.as_str()]);
        assert!(!reopened.index.files.contains_key(&inner.id));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tampering_or_truncating_a_file_is_caught() {
        let (pool, root) = temp_pool();
        let device = secrets(7);
        let mut vault = HiddenVault::create(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap();
        let content = vec![9u8; CHUNK as usize + 5];
        let entry = vault.import(Cursor::new(content.clone()), "big.bin", None, content.len() as u64, &mut |_, _| {}).unwrap();
        let path = pool.path(&vault.index.files[&entry.id].blob).unwrap();
        let pristine = std::fs::read(&path).unwrap();

        let mut flipped = pristine.clone();
        flipped[NONCE_SIZE + 3] ^= 1;
        std::fs::write(&path, &flipped).unwrap();
        assert!(vault.read_into(&entry.id, Vec::new(), &mut |_, _| {}).is_err());

        // Dropping the last chunk: the one before it was sealed as "not last".
        std::fs::write(&path, &pristine[..NONCE_SIZE + CHUNK as usize + TAG_SIZE]).unwrap();
        assert!(vault.read_into(&entry.id, Vec::new(), &mut |_, _| {}).is_err());

        std::fs::write(&path, &pristine).unwrap();
        assert_eq!(read_back(&vault, &entry.id), content);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_empty_file_and_one_of_exactly_one_chunk_round_trip() {
        let (pool, root) = temp_pool();
        let mut vault = HiddenVault::create(pool, "user-1", keys(&secrets(7), PATTERN)).unwrap();
        let empty = vault.import(Cursor::new(Vec::new()), "empty.txt", None, 0, &mut |_, _| {}).unwrap();
        assert_eq!(read_back(&vault, &empty.id), Vec::<u8>::new());
        let exact = vec![1u8; CHUNK as usize];
        let one = vault.import(Cursor::new(exact.clone()), "exact.bin", None, CHUNK, &mut |_, _| {}).unwrap();
        assert_eq!(one.total_chunks, 1);
        assert_eq!(read_back(&vault, &one.id), exact);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn destroying_a_vault_or_the_whole_pool_leaves_nothing_that_opens() {
        let (pool, root) = temp_pool();
        let device = secrets(7);
        let mut vault = HiddenVault::create(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap();
        vault.import(Cursor::new(b"gone".to_vec()), "gone.txt", None, 4, &mut |_, _| {}).unwrap();
        let mut other = HiddenVault::create(pool.clone(), "user-1", keys(&device, OTHER)).unwrap();
        other.import(Cursor::new(b"also gone".to_vec()), "other.txt", None, 9, &mut |_, _| {}).unwrap();

        vault.destroy().unwrap();
        assert!(HiddenVault::open(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap().is_none());
        assert!(HiddenVault::open(pool.clone(), "user-1", keys(&device, OTHER)).unwrap().is_some());

        pool.erase_all().unwrap();
        assert!(HiddenVault::open(pool.clone(), "user-1", keys(&device, OTHER)).unwrap().is_none());
        assert!(!pool_files(&pool).is_empty(), "a fresh pool of covers replaces it");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_count_stays_on_a_band_and_every_file_carries_one_fixed_date() {
        let (pool, root) = temp_pool();
        pool.ensure().unwrap();
        let mut vault = HiddenVault::create(pool.clone(), "user-1", keys(&secrets(7), PATTERN)).unwrap();
        assert_eq!(pool_files(&pool).len() % COVER_BAND, 0);
        for n in 0..3u8 {
            vault.import(Cursor::new(vec![n; 100]), &format!("{n}.txt"), None, 100, &mut |_, _| {}).unwrap();
            assert_eq!(pool_files(&pool).len() % COVER_BAND, 0, "after import {n}");
        }
        let first = vault.entries()[0].id.clone();
        vault.rename(&first, "renamed.txt").unwrap();
        assert_eq!(pool_files(&pool).len() % COVER_BAND, 0);
        for path in pool.names() {
            assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), pool_time(), "{}", path.display());
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_duress_erase_destroys_every_other_vault_and_leaves_the_decoy_looking_ordinary() {
        let (pool, root) = temp_pool();
        let device = secrets(7);
        let (decoy_keys, real_keys) = (keys(&device, PATTERN), keys(&device, OTHER));
        let mut real = HiddenVault::create(pool.clone(), "user-1", real_keys.clone()).unwrap();
        real.import(Cursor::new(b"the real documents".to_vec()), "real.txt", None, 18, &mut |_, _| {}).unwrap();
        drop(real);
        let mut decoy = HiddenVault::create(pool.clone(), "user-1", decoy_keys.clone()).unwrap();
        let shown = decoy.import(Cursor::new(b"holiday photos".to_vec()), "holiday.txt", None, 14, &mut |_, _| {}).unwrap();
        assert!(!decoy.summary().duress_erase);
        decoy.set_duress_erase(true).unwrap();
        drop(decoy);

        // Opened from inside the Quantum Vault (no take_duress): still armed, nothing erased.
        let looked_after = HiddenVault::open(pool.clone(), "user-1", decoy_keys.clone()).unwrap().unwrap();
        assert!(looked_after.summary().duress_erase);
        drop(looked_after);
        assert!(HiddenVault::open(pool.clone(), "user-1", real_keys.clone()).unwrap().is_some());

        // Drawn on the lock screen.
        let mut opened = HiddenVault::open(pool.clone(), "user-1", decoy_keys.clone()).unwrap().unwrap();
        let plan = opened.take_duress().expect("armed");
        assert!(!opened.summary().duress_erase, "an ordinary vault from the first moment");
        assert!(opened.take_duress().is_none(), "fires once");
        assert_eq!(plan.target_count(), pool_files(&pool).len() - 2, "everything but the decoy's index and its one file");
        let open = Mutex::new(opened);
        run_duress(plan, &open).unwrap();

        assert!(HiddenVault::open(pool.clone(), "user-1", real_keys).unwrap().is_none(), "the real vault is gone");
        assert_eq!(read_back(&open.lock().unwrap(), &shown.id), b"holiday photos");
        let count = pool_files(&pool).len();
        assert!(count % COVER_BAND == 0 && count >= COVER_BAND, "covers refill the folder ({count})");
        let reopened = HiddenVault::open(pool.clone(), "user-1", decoy_keys).unwrap().unwrap();
        assert!(!reopened.summary().duress_erase, "the flag is gone from disk too");
        assert_eq!(reopened.entries().len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_decoy_deleted_during_a_duress_erase_is_not_brought_back() {
        let (pool, root) = temp_pool();
        let decoy_keys = keys(&secrets(7), PATTERN);
        let mut decoy = HiddenVault::create(pool.clone(), "user-1", decoy_keys.clone()).unwrap();
        decoy.set_duress_erase(true).unwrap();
        let plan = decoy.take_duress().unwrap();
        decoy.destroy().unwrap();
        run_duress(plan, &Mutex::new(decoy)).unwrap();
        assert!(HiddenVault::open(pool.clone(), "user-1", decoy_keys).unwrap().is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_index_from_before_decoys_reads_as_not_armed() {
        let index = HiddenIndex {
            version: INDEX_VERSION,
            generation: 3,
            created_at: Utc::now(),
            tree: StoreIndex::new(),
            files: BTreeMap::new(),
            duress_erase: true,
            recovery: Some(RecoveryRef { name: "ab".repeat(16), key: "cd".repeat(32) }),
        };
        let mut json = serde_json::to_value(&index).unwrap();
        assert_eq!(json["duressErase"], serde_json::Value::Bool(true));
        assert!(json["recovery"].is_object());
        json.as_object_mut().unwrap().remove("duressErase");
        json.as_object_mut().unwrap().remove("recovery");
        let old: HiddenIndex = serde_json::from_value(json).unwrap();
        assert!(!old.duress_erase);
        assert!(old.recovery.is_none(), "an index from before recovery phrases has none");
    }

    fn phrase(vault: &mut HiddenVault) -> String {
        mnemonic::encode(&vault.set_up_recovery().unwrap()).join(" ")
    }

    fn recover(pool: &Pool, user: &str, words: &str) -> Option<HiddenVault> {
        HiddenVault::recover(pool.clone(), user, &mnemonic::decode(words).unwrap()).unwrap()
    }

    #[test]
    fn a_forgotten_pattern_is_replaced_through_the_recovery_phrase() {
        let (pool, root) = temp_pool();
        let device = secrets(7);
        let mut vault = HiddenVault::create(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap();
        let kept = vault.import(Cursor::new(b"deed to the house".to_vec()), "deed.pdf", None, 17, &mut |_, _| {}).unwrap();
        assert!(!vault.summary().recovery_phrase);
        let words = phrase(&mut vault);
        assert_eq!(words.split(' ').count(), 12);
        assert!(vault.summary().recovery_phrase);
        let before = pool_files(&pool);
        assert_eq!(before.len() % COVER_BAND, 0, "the record is counted like any file");
        drop(vault);

        // The record is one more pool file like the rest: a 32-hex name, a
        // bucket size, nothing readable.
        let record_name = RecoveryKeys::derive(&mnemonic::decode(&words).unwrap()).unwrap().name;
        let (_, record) = before.iter().find(|(name, _)| *name == record_name).expect("record on disk");
        assert_eq!(record.len() as u64, padded_len(record.len() as u64));
        for needle in [&b"indexKey"[..], b"\"names\"", b"QGHV-"] {
            assert!(!contains(record, needle));
        }

        // Pattern forgotten: the phrase opens the vault, a new pattern replaces the old.
        let mut recovered = recover(&pool, "user-1", &words).expect("the phrase opens the vault");
        assert_eq!(read_back(&recovered, &kept.id), b"deed to the house");
        recovered.rekey(keys(&device, OTHER)).unwrap();
        drop(recovered);
        assert!(HiddenVault::open(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap().is_none(), "the old pattern opens nothing");
        let reopened = HiddenVault::open(pool.clone(), "user-1", keys(&device, OTHER)).unwrap().expect("the new pattern opens it");
        assert_eq!(read_back(&reopened, &kept.id), b"deed to the house");
        assert!(reopened.summary().recovery_phrase);
        // The same phrase keeps working after the pattern changed.
        assert_eq!(recover(&pool, "user-1", &words).expect("still opens").entries().len(), 1);
        // Never under another account, and a phrase nobody set up opens nothing.
        assert!(recover(&pool, "user-2", &words).is_none());
        assert!(HiddenVault::recover(pool.clone(), "user-1", &mnemonic::generate()).unwrap().is_none());
        assert_eq!(pool_files(&pool).len() % COVER_BAND, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_tampered_or_moved_recovery_record_fails_authentication_and_releases_nothing() {
        let (pool, root) = temp_pool();
        let device = secrets(7);
        let mut vault = HiddenVault::create(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap();
        let words = phrase(&mut vault);
        drop(vault);
        let entropy = mnemonic::decode(&words).unwrap();
        let recovery = RecoveryKeys::derive(&entropy).unwrap();
        let path = pool.path(&recovery.name).unwrap();
        let pristine = std::fs::read(&path).unwrap();
        let fails_auth = |result: Result<RecoveryRecord>| match result {
            Err(error) => assert!(error.to_string().contains("AEAD authentication failed"), "{error}"),
            Ok(_) => panic!("an altered record must not open"),
        };

        // Control: the untouched record opens under its own key, name and account.
        let record = open_record(&recovery, "user-1", &pristine).unwrap();
        let released = HiddenKeys::from_record(&record).unwrap();
        assert!(HiddenVault::open(pool.clone(), "user-1", released).unwrap().is_some(), "what it releases opens the vault");

        // One flipped bit anywhere — nonce, ciphertext (the sealed index key) or
        // tag — fails the GCM tag check; recovery returns nothing at all.
        for position in [0, NONCE_SIZE + 5, pristine.len() / 2, pristine.len() - 1] {
            let mut altered = pristine.clone();
            altered[position] ^= 0x01;
            fails_auth(open_record(&recovery, "user-1", &altered));
            std::fs::write(&path, &altered).unwrap();
            assert!(recover(&pool, "user-1", &words).is_none(), "byte {position} flipped");
        }
        // Cut short: the tag is no longer where it was sealed.
        fails_auth(open_record(&recovery, "user-1", &pristine[..pristine.len() - 16]));
        std::fs::write(&path, &pristine[..pristine.len() - 16]).unwrap();
        assert!(recover(&pool, "user-1", &words).is_none());

        // The AAD binds the record to its account and its own file name: the same
        // bytes, key and all, refuse to open as another account's or under another name.
        fails_auth(open_record(&recovery, "user-2", &pristine));
        let moved = RecoveryKeys { key: recovery.key.clone(), name: Pool::new_name() };
        fails_auth(open_record(&moved, "user-1", &pristine));
        // A wrong key (any other phrase) fails the same way.
        fails_auth(open_record(&RecoveryKeys::derive(&mnemonic::generate()).unwrap(), "user-1", &pristine));

        // Nothing was changed by the failures: restored, the phrase opens the vault
        // again, and the pattern still opens it too.
        std::fs::write(&path, &pristine).unwrap();
        assert!(recover(&pool, "user-1", &words).is_some());
        assert!(HiddenVault::open(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap().is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_phrase_works_after_the_device_key_is_lost() {
        let (pool, root) = temp_pool();
        let mut vault = HiddenVault::create(pool.clone(), "user-1", keys(&secrets(7), PATTERN)).unwrap();
        let kept = vault.import(Cursor::new(b"still mine".to_vec()), "mine.txt", None, 10, &mut |_, _| {}).unwrap();
        let words = phrase(&mut vault);
        drop(vault);
        // The secure store's key was replaced: the pattern no longer opens it.
        let replaced = secrets(9);
        assert!(HiddenVault::open(pool.clone(), "user-1", keys(&replaced, PATTERN)).unwrap().is_none());
        let mut recovered = recover(&pool, "user-1", &words).expect("the phrase does not need the device key");
        recovered.rekey(keys(&replaced, PATTERN)).unwrap();
        drop(recovered);
        let reopened = HiddenVault::open(pool.clone(), "user-1", keys(&replaced, PATTERN)).unwrap().expect("opens under the new device key");
        assert_eq!(read_back(&reopened, &kept.id), b"still mine");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_new_phrase_replaces_the_old_and_removing_it_leaves_only_the_pattern() {
        let (pool, root) = temp_pool();
        let device = secrets(7);
        let mut vault = HiddenVault::create(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap();
        let first = phrase(&mut vault);
        let second = phrase(&mut vault);
        assert_ne!(first, second);
        assert!(recover(&pool, "user-1", &first).is_none(), "the replaced phrase opens nothing");
        assert!(recover(&pool, "user-1", &second).is_some());
        let count = pool_files(&pool).len();
        vault.remove_recovery().unwrap();
        assert!(!vault.summary().recovery_phrase);
        assert!(recover(&pool, "user-1", &second).is_none(), "a removed phrase opens nothing");
        assert_eq!(pool_files(&pool).len(), count, "a cover takes the record's place in the count");
        assert!(HiddenVault::open(pool.clone(), "user-1", keys(&device, PATTERN)).unwrap().is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_taken_pattern_is_refused_on_rekey_and_nothing_changes() {
        let (pool, root) = temp_pool();
        let device = secrets(7);
        let (mine, theirs) = (keys(&device, PATTERN), keys(&device, OTHER));
        HiddenVault::create(pool.clone(), "user-1", theirs.clone()).unwrap();
        let mut vault = HiddenVault::create(pool.clone(), "user-1", mine.clone()).unwrap();
        let words = phrase(&mut vault);
        let before = pool_files(&pool);
        let refused = vault.rekey(theirs.clone()).err().expect("refused");
        assert!(refused.to_string().contains(PATTERN_TAKEN));
        assert_eq!(pool_files(&pool), before, "nothing on disk changed");
        assert!(HiddenVault::open(pool.clone(), "user-1", mine).unwrap().is_some());
        assert!(recover(&pool, "user-1", &words).is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn deleting_or_a_duress_erase_takes_the_phrase_with_the_vault() {
        let (pool, root) = temp_pool();
        let device = secrets(7);
        let (decoy_keys, real_keys) = (keys(&device, PATTERN), keys(&device, OTHER));
        let mut real = HiddenVault::create(pool.clone(), "user-1", real_keys).unwrap();
        let real_words = phrase(&mut real);
        drop(real);
        let mut decoy = HiddenVault::create(pool.clone(), "user-1", decoy_keys).unwrap();
        let decoy_words = phrase(&mut decoy);
        decoy.set_duress_erase(true).unwrap();
        let plan = decoy.take_duress().unwrap();
        let open = Mutex::new(decoy);
        run_duress(plan, &open).unwrap();
        assert!(recover(&pool, "user-1", &real_words).is_none(), "the erased vault's phrase opens nothing");
        assert!(recover(&pool, "user-1", &decoy_words).is_some(), "the decoy keeps its own phrase");

        open.lock().unwrap().destroy().unwrap();
        assert!(recover(&pool, "user-1", &decoy_words).is_none(), "a deleted vault's phrase opens nothing");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn padding_buckets_are_coarse_and_never_shrink() {
        assert_eq!(padded_len(0), MIN_FILE_BYTES);
        assert_eq!(padded_len(MIN_FILE_BYTES + 1), 20 * 1024);
        for len in [17_000u64, 100_000, 1_048_604, 5_000_000, 3 * 1024 * 1024 * 1024] {
            let padded = padded_len(len);
            assert!(padded >= len && padded - len <= len / 16 + 4096, "{len} -> {padded}");
        }
    }
}
