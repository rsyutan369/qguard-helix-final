//! Encrypted checkpoint storage and streaming file I/O for Qguard XFER.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{anyhow, bail, ensure, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::provider::{self, Sha3_256Hasher};
use crate::state::write_atomic;

pub const CHUNK_SIZE: u32 = 4 * 1024 * 1024;
const MAX_FILES: usize = 128;
const MAX_SELECTION_ENTRIES: usize = 2048;
const MAX_RECORDS: usize = 128;
const MAX_PENDING_OFFERS: usize = 16;
const MAX_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_STAGED_BYTES: u64 = 2 * MAX_BYTES;
const MAX_PATH_BYTES: usize = 512;
const MAX_PATH_DEPTH: usize = 16;
const TTL: i64 = 24 * 60 * 60;
const CLOCK_SKEW: i64 = 5 * 60;
const MAX_DOC_BYTES: usize = 2 * 1024 * 1024;
const SALT_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const OVERHEAD: usize = SALT_BYTES + NONCE_BYTES + TAG_BYTES;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileManifest {
    pub path: String,
    pub size: u64,
    pub chunks: u32,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub id: Uuid,
    pub sender: String,
    pub recipient: String,
    pub files: Vec<FileManifest>,
    pub chunk_size: u32,
    pub created_at: i64,
    pub expires_at: i64,
}

impl Manifest {
    pub fn total_bytes(&self) -> u64 {
        self.files
            .iter()
            .fold(0u64, |total, file| total.saturating_add(file.size))
    }

    fn validate(&self, now: i64) -> Result<()> {
        ensure!(!self.id.is_nil(), "Invalid transfer identifier");
        ensure!(
            valid_identity(&self.sender)
                && valid_identity(&self.recipient)
                && self.sender != self.recipient,
            "Invalid transfer identities"
        );
        ensure!(
            self.chunk_size == CHUNK_SIZE,
            "Unsupported transfer chunk size"
        );
        ensure!(
            self.created_at <= now + CLOCK_SKEW
                && self.expires_at > now
                && self
                    .expires_at
                    .checked_sub(self.created_at)
                    .is_some_and(|ttl| (1..=TTL).contains(&ttl)),
            "Transfer offer expired or its timestamp is invalid"
        );
        ensure!(
            (1..=MAX_FILES).contains(&self.files.len()),
            "Invalid transfer file count"
        );
        ensure!(
            self.total_bytes() <= MAX_BYTES,
            "Transfer exceeds the 32 GiB size limit"
        );

        let mut paths = HashSet::new();
        let mut directories = HashSet::new();
        for file in &self.files {
            validate_relative_path(&file.path)?;
            let normalized = file.path.to_lowercase();
            ensure!(
                !directories.contains(&normalized) && paths.insert(normalized.clone()),
                "Conflicting transfer file paths"
            );
            for (offset, _) in normalized.match_indices('/') {
                let parent = &normalized[..offset];
                ensure!(!paths.contains(parent), "Conflicting transfer file paths");
                directories.insert(parent.to_owned());
            }
            ensure!(
                file.chunks == chunk_count(file.size),
                "Invalid transfer chunk count"
            );
            ensure!(valid_digest(&file.digest), "Invalid transfer file digest");
        }
        Ok(())
    }

    fn file(&self, file: u32) -> Result<&FileManifest> {
        self.files
            .get(file as usize)
            .context("Invalid transfer file index")
    }

    fn chunk_len(&self, file: u32, chunk: u32) -> Result<usize> {
        let file = self.file(file)?;
        ensure!(chunk < file.chunks, "Invalid transfer chunk index");
        let remaining = file.size - u64::from(chunk) * u64::from(self.chunk_size);
        Ok(remaining.min(u64::from(self.chunk_size)) as usize)
    }
}

fn valid_identity(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_:".contains(&c))
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn chunk_count(size: u64) -> u32 {
    size.div_ceil(u64::from(CHUNK_SIZE)) as u32
}

pub(super) fn validate_relative_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= MAX_PATH_BYTES,
        "Invalid transfer file path length"
    );
    ensure!(
        path.split('/').count() <= MAX_PATH_DEPTH,
        "Transfer folder depth exceeds the limit"
    );
    for segment in path.split('/') {
        let device = segment
            .split('.')
            .next()
            .unwrap_or_default()
            .trim_end()
            .to_ascii_uppercase();
        let reserved = matches!(
            device.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || ["COM", "LPT"].iter().any(|prefix| {
            device.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        });
        ensure!(
            !segment.is_empty()
                && segment.len() <= 255
                && segment != "."
                && segment != ".."
                && !segment.starts_with(' ')
                && !segment.ends_with(['.', ' '])
                && !reserved
                && !segment.chars().any(|c| c.is_control()
                    || "\\:<>\"|?*".contains(c)
                    || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')),
            "Unsafe transfer file name"
        );
    }
    Ok(())
}

pub(super) fn checked_metadata(path: &Path) -> Result<Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    require_regular_path(&metadata)?;
    Ok(metadata)
}

fn require_regular_path(metadata: &Metadata) -> Result<()> {
    ensure!(
        !metadata.file_type().is_symlink(),
        "Symbolic links are excluded from transfers"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Includes directory junctions and other reparse-point redirections.
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "Reparse points are excluded from transfers"
        );
    }
    Ok(())
}

pub(super) fn read_file(path: &Path, metadata: &Metadata) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT makes the handle describe the link
        // itself if the path changed since symlink_metadata().
        options.custom_flags(0x0020_0000);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    require_regular_path(&opened)?;
    ensure!(
        opened.is_file() && opened.len() == metadata.len(),
        "Transfer file changed before it could be opened"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            opened.dev() == metadata.dev() && opened.ino() == metadata.ino(),
            "Transfer file changed before it could be opened"
        );
    }
    Ok(file)
}

/// Resolve the native selection immediately. Upload preparation later rejects
/// any redirection of this exact path, including a replaced parent directory.
pub fn selected_source(path: PathBuf) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "Transfer source must be an absolute path"
    );
    let metadata = checked_metadata(&path)?;
    ensure!(
        metadata.is_file() || metadata.is_dir(),
        "Only regular files and folders can be transferred"
    );
    let selected = path.canonicalize()?;
    checked_metadata(&selected)?;
    Ok(selected)
}

/// A source authorized by the native picker. Document URIs must never be
/// accepted directly from renderer arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectedSource {
    Path(PathBuf),
    Document {
        uri: String,
        name: String,
        size: Option<u64>,
    },
    /// Minted by the native SAF picker from a selected document tree.
    DocumentTreeFile {
        uri: String,
        path: String,
        size: Option<u64>,
    },
}

#[derive(Deserialize, Serialize)]
struct Source {
    path: PathBuf,
    digests: Vec<[u8; 32]>,
}

pub struct Upload {
    manifest: Manifest,
    sources: Vec<Source>,
    staged: Option<StagedUpload>,
}

struct StagedUpload {
    root: PathBuf,
    key: Zeroizing<[u8; 32]>,
}

impl Upload {
    pub fn prepare(sender: String, recipient: String, paths: Vec<PathBuf>) -> Result<Self> {
        ensure!(
            (1..=MAX_FILES).contains(&paths.len()),
            "Select up to 128 files or folders"
        );
        let mut selected = Vec::new();
        let mut remaining = MAX_SELECTION_ENTRIES;
        for path in paths {
            ensure!(
                path.is_absolute(),
                "Transfer source must be an absolute path"
            );
            let label = path
                .file_name()
                .and_then(|name| name.to_str())
                .context("Invalid transfer source name")?;
            collect_sources(&path, label, &mut selected, &mut remaining)?;
        }
        ensure!(!selected.is_empty(), "The selection contains no files");

        let mut files = Vec::with_capacity(selected.len());
        let mut sources = Vec::with_capacity(selected.len());
        let mut total = 0u64;
        for (path, relative, size) in selected {
            total = total
                .checked_add(size)
                .filter(|value| *value <= MAX_BYTES)
                .context("Transfer exceeds the 32 GiB size limit")?;
            let (digest, digests) = hash_source(&path, size)?;
            files.push(FileManifest {
                path: relative,
                size,
                chunks: chunk_count(size),
                digest,
            });
            sources.push(Source { path, digests });
        }
        let created_at = Utc::now().timestamp();
        let manifest = Manifest {
            id: Uuid::new_v4(),
            sender,
            recipient,
            files,
            chunk_size: CHUNK_SIZE,
            created_at,
            expires_at: created_at + TTL,
        };
        manifest.validate(created_at)?;
        Ok(Self {
            manifest,
            sources,
            staged: None,
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn read_chunk(&self, file: u32, index: u32) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            Utc::now().timestamp() < self.manifest.expires_at,
            "Transfer expired"
        );
        let length = self.manifest.chunk_len(file, index)?;
        if let Some(staged) = &self.staged {
            return read_chunk(&staged.key, &staged.root, &self.manifest, file, index);
        }
        let source = &self.sources[file as usize];
        let mut handle = open_source(&source.path, self.manifest.file(file)?.size)?;
        handle.seek(SeekFrom::Start(
            u64::from(index) * u64::from(self.manifest.chunk_size),
        ))?;
        let mut chunk = Zeroizing::new(vec![0u8; length]);
        handle.read_exact(&mut chunk)?;
        ensure!(
            provider::constant_time_eq(
                &provider::sha3_256(&chunk),
                &source.digests[index as usize]
            ),
            "Selected source changed since the transfer was prepared"
        );
        Ok(chunk)
    }
}

fn collect_sources(
    path: &Path,
    relative: &str,
    selected: &mut Vec<(PathBuf, String, u64)>,
    remaining: &mut usize,
) -> Result<()> {
    ensure!(
        *remaining > 0,
        "Transfer selection contains too many entries"
    );
    *remaining -= 1;
    validate_relative_path(relative)?;
    let metadata = checked_metadata(path)?;
    ensure!(
        path.canonicalize()? == path,
        "Selected source folder or path changed"
    );
    if metadata.is_file() {
        ensure!(
            selected.len() < MAX_FILES,
            "Transfer contains more than 128 files"
        );
        selected.push((path.to_path_buf(), relative.to_owned(), metadata.len()));
        return Ok(());
    }
    ensure!(
        metadata.is_dir(),
        "Only regular files and folders can be transferred"
    );
    for child in fs::read_dir(path)? {
        let child = child?;
        let name = child.file_name();
        let name = name.to_str().context("Invalid transfer source name")?;
        collect_sources(
            &child.path(),
            &format!("{relative}/{name}"),
            selected,
            remaining,
        )?;
    }
    Ok(())
}

fn open_source(path: &Path, size: u64) -> Result<File> {
    let metadata = checked_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() == size,
        "Selected source changed since the transfer was prepared"
    );
    ensure!(path.canonicalize()? == path, "Selected source path changed");
    read_file(path, &metadata)
}

fn hash_source(path: &Path, size: u64) -> Result<(String, Vec<[u8; 32]>)> {
    let mut file = open_source(path, size)?;
    let mut buffer = Zeroizing::new(vec![0u8; (u64::from(CHUNK_SIZE).min(size)) as usize]);
    let mut hasher = Sha3_256Hasher::new();
    let mut digests = Vec::with_capacity(chunk_count(size) as usize);
    let mut remaining = size;
    while remaining > 0 {
        let length = remaining.min(u64::from(CHUNK_SIZE)) as usize;
        let chunk = &mut buffer[..length];
        file.read_exact(chunk)?;
        digests.push(provider::sha3_256(chunk));
        hasher.update(chunk);
        remaining -= length as u64;
    }
    ensure!(
        file.metadata()?.len() == size,
        "Selected source changed while it was being prepared"
    );
    Ok((hex::encode(hasher.finalize()), digests))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    Incoming,
    Outgoing,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    AwaitingConsent,
    Ready,
    Transferring,
    Paused,
    Stopped,
    Interrupted,
    Verified,
    Rejected,
    Cancelled,
    Expired,
    Failed,
}

impl Status {
    fn receiving(self) -> bool {
        matches!(self, Self::Ready | Self::Transferring | Self::Interrupted)
    }

    fn discarded(self) -> bool {
        matches!(
            self,
            Self::Rejected | Self::Cancelled | Self::Expired | Self::Failed
        )
    }

    fn held(self) -> bool {
        matches!(self, Self::Paused | Self::Stopped)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TransferAction {
    Pause,
    Resume,
    Stop,
    Cancel,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlIntent {
    pub revision: u64,
    pub action: TransferAction,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TransferFailure {
    ConnectionLost,
    PeerUnavailable,
    StorageFull,
    FileWrite,
    Encryption,
    Integrity,
    Timeout,
    Interrupted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileProgress {
    pub completed_bytes: u64,
    pub payload_complete: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub manifest: Manifest,
    pub direction: Direction,
    pub status: Status,
    pub completed_bytes: u64,
    pub verified_files: u32,
    pub updated_at: i64,
    pub destination: Option<String>,
    pub destinations: Vec<Option<String>>,
    #[serde(default)]
    pub receive_into_vault: bool,
    #[serde(default)]
    pub queued_locally: bool,
    #[serde(default)]
    pub started_at_ms: Option<i64>,
    #[serde(default)]
    pub completed_at_ms: Option<i64>,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub failure: Option<TransferFailure>,
    #[serde(default)]
    pub pending_control: Option<ControlIntent>,
    #[serde(default)]
    pub local_hold: Option<TransferAction>,
    #[serde(default)]
    pub remote_hold: Option<TransferAction>,
    #[serde(default)]
    remote_control_revision: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub android_destinations: BTreeMap<u32, String>,
    /// First 64 bits of the most recent authenticated session binding (a
    /// SHA3-256 digest of the signed hybrid handshake). Both devices derive
    /// the same value from the same session, so users can compare them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip)]
    pub file_progress: Vec<FileProgress>,
}

impl Record {
    pub fn folder_name(&self) -> Option<&str> {
        let (folder, _) = self.manifest.files.first()?.path.split_once('/')?;
        self.manifest
            .files
            .iter()
            .all(|file| {
                file.path
                    .split_once('/')
                    .is_some_and(|(root, _)| root == folder)
            })
            .then_some(folder)
    }
}

#[derive(Deserialize, Serialize)]
struct Stored {
    record: Record,
    next: Vec<u32>,
}

impl Stored {
    fn new(manifest: Manifest, direction: Direction, status: Status) -> Self {
        let count = manifest.files.len();
        Self {
            record: Record {
                manifest,
                direction,
                status,
                completed_bytes: 0,
                verified_files: 0,
                updated_at: Utc::now().timestamp(),
                destination: None,
                destinations: vec![None; count],
                receive_into_vault: false,
                queued_locally: false,
                started_at_ms: None,
                completed_at_ms: None,
                revision: 0,
                failure: None,
                pending_control: None,
                local_hold: None,
                remote_hold: None,
                remote_control_revision: 0,
                android_destinations: BTreeMap::new(),
                session_id: None,
                file_progress: Vec::new(),
            },
            next: vec![0; count],
        }
    }

    fn update_progress(&mut self) {
        self.record.file_progress = self
            .record
            .manifest
            .files
            .iter()
            .zip(&self.next)
            .map(|(file, next)| FileProgress {
                completed_bytes: file.size.min(u64::from(*next) * u64::from(CHUNK_SIZE)),
                payload_complete: *next == file.chunks,
            })
            .collect();
        self.record.completed_bytes = self
            .record
            .file_progress
            .iter()
            .map(|file| file.completed_bytes)
            .sum();
    }

    fn begin(&mut self) {
        // A checkpoint from an earlier version may already contain data without
        // a start time. Its first start cannot be reconstructed from a retry.
        if self.record.started_at_ms.is_none() && self.next.iter().all(|next| *next == 0) {
            self.record.started_at_ms = Some(Utc::now().timestamp_millis());
        }
        self.record.status = Status::Transferring;
        self.record.failure = None;
    }

    fn set_pending_control(&mut self, action: TransferAction) -> Result<()> {
        self.record.pending_control = Some(ControlIntent {
            revision: self.next_revision()?,
            action,
        });
        Ok(())
    }

    fn next_revision(&self) -> Result<u64> {
        self.record
            .revision
            .checked_add(1)
            .context("Transfer revision exhausted")
    }

    fn apply_hold_status(&mut self) {
        if !(self.record.status.receiving() || self.record.status.held()) {
            return;
        }
        let holds = [self.record.local_hold, self.record.remote_hold];
        if holds.contains(&Some(TransferAction::Stop)) {
            self.record.status = Status::Stopped;
        } else if holds.contains(&Some(TransferAction::Pause)) {
            self.record.status = Status::Paused;
        } else if self.record.status.held() {
            self.record.status = Status::Ready;
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissingFile {
    pub file: u32,
    pub next: u32,
}

/// Keep one store per account and serialize mutations to its on-disk records.
pub struct Store {
    root: PathBuf,
    key: Zeroizing<[u8; 32]>,
    gate: Mutex<()>,
}

enum QueueSource {
    File {
        path: PathBuf,
        name: String,
        size: u64,
    },
    Document {
        uri: String,
        name: String,
        size: Option<u64>,
    },
}

fn queued_document(uri: String, name: String, size: Option<u64>) -> Result<QueueSource> {
    ensure!(
        crate::security::content_uri::is_content_uri(&uri)
            && uri.len() <= 4096
            && !uri.chars().any(char::is_control),
        "Invalid Android document URI"
    );
    validate_relative_path(&name)?;
    ensure!(
        size.is_none_or(|size| size <= MAX_BYTES),
        "Transfer exceeds the 32 GiB size limit"
    );
    Ok(QueueSource::Document { uri, name, size })
}

fn staged_bytes(records: &[Record]) -> u64 {
    let now = Utc::now().timestamp();
    records
        .iter()
        .filter(|record| {
            record.manifest.expires_at > now
                && !record.status.discarded()
                && (record.direction == Direction::Incoming
                    && (record.status.receiving()
                        || record.status.held()
                        || record.status == Status::Verified)
                    || record.direction == Direction::Outgoing
                        && record.queued_locally
                        && record.status != Status::Verified)
        })
        .fold(0u64, |total, record| {
            total.saturating_add(record.manifest.total_bytes())
        })
}

impl Store {
    pub fn open(root: PathBuf, key: [u8; 32]) -> Result<Self> {
        let key = Zeroizing::new(key);
        ensure!(root.is_absolute(), "Invalid transfer storage directory");
        private_dir(&root)?;
        Ok(Self {
            root,
            key,
            gate: Mutex::new(()),
        })
    }

    pub fn offer(&self, manifest: Manifest, sender: &str, local: &str) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        manifest.validate(Utc::now().timestamp())?;
        ensure!(
            manifest.sender == sender && manifest.recipient == local,
            "Transfer identity does not match the authenticated connection"
        );
        let id = manifest.id;
        if self.record_path(id).exists() {
            let existing = self.load(id)?;
            ensure!(
                existing.record.direction == Direction::Incoming
                    && existing.record.manifest == manifest,
                "Transfer offer changed after receipt"
            );
            return Ok(existing.record);
        }
        let records = self.prune()?;
        ensure!(
            records
                .iter()
                .filter(|record| record.status == Status::AwaitingConsent)
                .count()
                < MAX_PENDING_OFFERS,
            "Incoming offer queue is full"
        );
        self.ensure_capacity(&records)?;
        private_dir(&self.transfer_dir(id))?;
        self.save(Stored::new(
            manifest,
            Direction::Incoming,
            Status::AwaitingConsent,
        ))
    }

    pub fn register_upload(&self, upload: &Upload) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        upload.manifest.validate(Utc::now().timestamp())?;
        let id = upload.manifest.id;
        ensure!(!self.record_path(id).exists(), "Transfer already exists");
        self.ensure_capacity(&self.prune()?)?;
        private_dir(&self.transfer_dir(id))?;
        let source = Zeroizing::new(serde_json::to_vec(&upload.sources)?);
        ensure!(
            source.len() <= MAX_DOC_BYTES,
            "Transfer source checkpoint is too large"
        );
        write_atomic(
            &self.source_path(id),
            &seal(&self.key, &aad(id, b"source"), &source)?,
        )?;
        self.save(Stored::new(
            upload.manifest.clone(),
            Direction::Outgoing,
            Status::Ready,
        ))
    }

    /// Materialize an offline send into authenticated encrypted chunks before
    /// publishing its record. A restart no longer needs the original file or
    /// an Android content-provider permission that may have expired.
    #[cfg(test)]
    pub fn queue_sources(
        &self,
        sender: String,
        recipient: String,
        sources: Vec<SelectedSource>,
    ) -> Result<Record> {
        self.queue_sources_authorized(sender, recipient, sources, || Ok(()))
    }

    pub fn queue_sources_authorized(
        &self,
        sender: String,
        recipient: String,
        sources: Vec<SelectedSource>,
        authorize: impl Fn() -> Result<()>,
    ) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        authorize()?;
        ensure!(
            valid_identity(&sender) && valid_identity(&recipient) && sender != recipient,
            "Invalid transfer identities"
        );
        ensure!(
            (1..=MAX_FILES).contains(&sources.len()),
            "Select up to 128 files or folders"
        );
        let records = self.prune()?;
        self.ensure_capacity(&records)?;
        let available = MAX_STAGED_BYTES
            .checked_sub(staged_bytes(&records))
            .context("Transfer storage limit reached")?
            .min(MAX_BYTES);
        let mut expanded = Vec::new();
        let mut remaining = MAX_SELECTION_ENTRIES;
        for source in sources {
            match source {
                SelectedSource::Path(path) => {
                    let label = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .context("Invalid transfer source name")?;
                    let mut selected = Vec::new();
                    collect_sources(&path, label, &mut selected, &mut remaining)?;
                    expanded.extend(
                        selected
                            .into_iter()
                            .map(|(path, name, size)| QueueSource::File { path, name, size }),
                    );
                }
                SelectedSource::Document { uri, name, size } => {
                    ensure!(!name.contains('/'), "Invalid Android document name");
                    expanded.push(queued_document(uri, name, size)?);
                }
                SelectedSource::DocumentTreeFile { uri, path, size } => {
                    ensure!(
                        path.contains('/'),
                        "Android tree entry is missing its folder name"
                    );
                    expanded.push(queued_document(uri, path, size)?);
                }
            }
            ensure!(
                expanded.len() <= MAX_FILES,
                "Transfer contains more than 128 files"
            );
        }
        ensure!(!expanded.is_empty(), "The selection contains no files");

        let id = Uuid::new_v4();
        ensure!(!self.transfer_dir(id).exists(), "Transfer already exists");
        private_dir(&self.chunk_dir(id))?;
        let result = (|| -> Result<Record> {
            let mut files = Vec::with_capacity(expanded.len());
            let mut total = 0u64;
            for source in expanded {
                authorize()?;
                let (mut reader, name, expected): (Box<dyn Read>, String, Option<u64>) =
                    match source {
                        QueueSource::File { path, name, size } => {
                            (Box::new(open_source(&path, size)?), name, Some(size))
                        }
                        QueueSource::Document { uri, name, size } => (
                            Box::new(
                                crate::security::content_uri::open_read(&uri)
                                    .context("Could not read the selected Android document")?,
                            ),
                            name,
                            size,
                        ),
                    };
                let remaining = available
                    .checked_sub(total)
                    .context("Transfer storage limit reached")?;
                let manifest = self.stage_reader(
                    id,
                    files.len() as u32,
                    name,
                    expected,
                    &mut *reader,
                    remaining,
                    &authorize,
                )?;
                total = total
                    .checked_add(manifest.size)
                    .context("Transfer exceeds its storage limit")?;
                files.push(manifest);
            }
            let created_at = Utc::now().timestamp();
            let manifest = Manifest {
                id,
                sender,
                recipient,
                files,
                chunk_size: CHUNK_SIZE,
                created_at,
                expires_at: created_at + TTL,
            };
            manifest.validate(created_at)?;
            let mut stored = Stored::new(manifest, Direction::Outgoing, Status::Ready);
            stored.record.queued_locally = true;
            authorize()?;
            self.save(stored)
        })();
        if result.is_err() {
            // No visible record was committed. Remove only this generated
            // transfer directory, which contains ciphertext and no source file.
            remove_dir_if_present(&self.transfer_dir(id))?;
        }
        result
    }

    fn stage_reader(
        &self,
        id: Uuid,
        file: u32,
        path: String,
        expected_size: Option<u64>,
        reader: &mut dyn Read,
        remaining: u64,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<FileManifest> {
        validate_relative_path(&path)?;
        ensure!(
            expected_size.map_or(true, |size| size <= remaining),
            "Transfer storage limit reached"
        );
        let mut hasher = Sha3_256Hasher::new();
        let mut bytes = Zeroizing::new(vec![0u8; CHUNK_SIZE as usize]);
        let mut size = 0u64;
        let mut chunks = 0u32;
        loop {
            authorize()?;
            let mut filled = 0;
            while filled < bytes.len() {
                match reader.read(&mut bytes[filled..]) {
                    Ok(0) => break,
                    Ok(read) => filled += read,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        return Err(error).context("Could not read a selected transfer source")
                    }
                }
            }
            if filled == 0 {
                break;
            }
            size = size
                .checked_add(filled as u64)
                .filter(|size| *size <= remaining && *size <= MAX_BYTES)
                .context("Transfer source exceeds the available encrypted storage limit")?;
            ensure!(
                expected_size.map_or(true, |expected| size <= expected),
                "Selected document grew while it was being queued"
            );
            authorize()?;
            hasher.update(&bytes[..filled]);
            write_atomic(
                &self.chunk_path(id, file, chunks),
                &seal(&self.key, &chunk_aad(id, file, chunks), &bytes[..filled])?,
            )?;
            chunks = chunks
                .checked_add(1)
                .context("Transfer contains too many chunks")?;
        }
        ensure!(
            expected_size.map_or(true, |expected| expected == size),
            "Selected document size changed while it was being queued"
        );
        Ok(FileManifest {
            path,
            size,
            chunks,
            digest: hex::encode(hasher.finalize()),
        })
    }

    pub fn open_upload(&self, id: Uuid) -> Result<Upload> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let stored = self.load(id)?;
        ensure!(
            stored.record.direction == Direction::Outgoing && stored.record.status.receiving(),
            "Transfer is unavailable for sending"
        );
        let manifest = stored.record.manifest;
        manifest.validate(Utc::now().timestamp())?;
        if stored.record.queued_locally {
            ensure!(
                checked_metadata(&self.chunk_dir(id))?.is_dir(),
                "Encrypted queued source is unavailable"
            );
            return Ok(Upload {
                manifest,
                sources: Vec::new(),
                staged: Some(StagedUpload {
                    root: self.chunk_dir(id),
                    key: self.key.clone(),
                }),
            });
        }
        let source = open(
            &self.key,
            &aad(id, b"source"),
            &self.source_path(id),
            MAX_DOC_BYTES,
        )?;
        let sources: Vec<Source> = serde_json::from_slice(&source)?;
        ensure!(
            sources.len() == manifest.files.len(),
            "Invalid transfer source checkpoint"
        );
        for (source, file) in sources.iter().zip(&manifest.files) {
            ensure!(
                source.path.is_absolute() && source.digests.len() == file.chunks as usize,
                "Invalid transfer source checkpoint"
            );
        }
        Ok(Upload {
            manifest,
            sources,
            staged: None,
        })
    }

    pub fn get(&self, id: Uuid) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        self.load(id).map(|stored| stored.record)
    }

    pub fn list(&self) -> Result<Vec<Record>> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut records = self.prune()?;
        records.sort_unstable_by_key(|record| std::cmp::Reverse(record.updated_at));
        Ok(records)
    }

    /// Call once when opening an account's transfer runtime, before networking.
    pub fn recover_interrupted(&self) -> Result<()> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        for record in self.prune()? {
            if record.status == Status::Transferring {
                let mut stored = self.load(record.manifest.id)?;
                stored.record.status = Status::Interrupted;
                stored.record.failure = Some(TransferFailure::Interrupted);
                self.save(stored)?;
            }
        }
        Ok(())
    }

    pub fn accept(&self, id: Uuid) -> Result<Record> {
        self.accept_with_destination(id, false)
    }

    pub fn accept_with_destination(&self, id: Uuid, receive_into_vault: bool) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.load(id)?;
        ensure!(
            stored.record.direction == Direction::Incoming
                && stored.record.status == Status::AwaitingConsent,
            "Transfer is not awaiting consent"
        );
        stored.record.manifest.validate(Utc::now().timestamp())?;
        let reserved_bytes = staged_bytes(&self.prune()?);
        ensure!(
            reserved_bytes + stored.record.manifest.total_bytes() <= MAX_STAGED_BYTES,
            "Transfer storage limit reached"
        );
        private_dir(&self.chunk_dir(id))?;
        stored.record.status = Status::Ready;
        stored.record.receive_into_vault = receive_into_vault;
        stored.apply_hold_status();
        self.save(stored)
    }

    pub fn reject(&self, id: Uuid) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.load(id)?;
        ensure!(
            stored.record.direction == Direction::Incoming
                && stored.record.status == Status::AwaitingConsent,
            "Transfer is not awaiting consent"
        );
        stored.record.status = Status::Rejected;
        self.save(stored)
    }

    /// Record an explicit decline from the authenticated receiving peer.
    pub fn reject_outgoing(&self, id: Uuid) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.load(id)?;
        ensure!(
            stored.record.direction == Direction::Outgoing,
            "Transfer is not outgoing"
        );
        if stored.record.status == Status::Rejected {
            self.discard_payload(id)?;
            return Ok(stored.record);
        }
        ensure!(
            stored.record.status.receiving() || stored.record.status.held(),
            "Transfer is no longer active"
        );
        ensure!(
            stored.record.manifest.expires_at > Utc::now().timestamp(),
            "Transfer expired"
        );
        stored.record.status = Status::Rejected;
        stored.record.local_hold = None;
        stored.record.remote_hold = None;
        stored.record.pending_control = None;
        stored.record.failure = None;
        let record = self.save(stored)?;
        self.discard_payload(id)?;
        Ok(record)
    }

    pub fn cancel(&self, id: Uuid) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.load(id)?;
        if stored.record.status == Status::Cancelled {
            return self.cancel_stored(stored);
        }
        ensure!(
            stored.record.status.receiving()
                || stored.record.status.held()
                || stored.record.status == Status::AwaitingConsent,
            "Transfer is no longer active"
        );
        stored.set_pending_control(TransferAction::Cancel)?;
        self.cancel_stored(stored)
    }

    /// Compatibility with a legacy authenticated cancellation. It must not
    /// create a new local intent that would echo the cancellation to the peer.
    pub fn cancel_remote_legacy(&self, id: Uuid) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.load(id)?;
        if stored.record.status == Status::Cancelled {
            return self.cancel_stored(stored);
        }
        if stored.record.status == Status::Verified || stored.record.status.discarded() {
            return Ok(stored.record);
        }
        stored.record.pending_control = None;
        self.cancel_stored(stored)
    }

    fn cancel_stored(&self, mut stored: Stored) -> Result<Record> {
        let id = stored.record.manifest.id;
        let record = if stored.record.status == Status::Cancelled {
            stored.record
        } else {
            stored.record.status = Status::Cancelled;
            stored.record.local_hold = None;
            stored.record.remote_hold = None;
            stored.record.failure = None;
            self.save(stored)?
        };
        // Cancellation is durable and blocks all further I/O at this point.
        // A locked encrypted chunk must not prevent propagating that state.
        // History pruning and a repeated cancellation retry the cleanup.
        let _ = self.discard_payload(id);
        Ok(record)
    }

    pub fn apply_remote_control(
        &self,
        id: Uuid,
        revision: u64,
        action: TransferAction,
    ) -> Result<Record> {
        ensure!(revision != 0, "Invalid transfer control revision");
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.load(id)?;
        if stored.record.status == Status::Cancelled && action == TransferAction::Cancel {
            return self.cancel_stored(stored);
        }
        if revision <= stored.record.remote_control_revision
            || stored.record.status == Status::Verified
            || stored.record.status.discarded()
        {
            return Ok(stored.record);
        }
        stored.record.manifest.validate(Utc::now().timestamp())?;
        stored.record.remote_control_revision = revision;
        match action {
            TransferAction::Cancel => {
                stored.record.pending_control = None;
                return self.cancel_stored(stored);
            }
            TransferAction::Pause | TransferAction::Stop => {
                stored.record.remote_hold = Some(action)
            }
            TransferAction::Resume => stored.record.remote_hold = None,
        }
        // An incoming offer can be held by its sender. Resume releases the
        // hold without advancing consent or starting the receiver's transfer.
        stored.apply_hold_status();
        self.save(stored)
    }

    pub fn ack_control(&self, id: Uuid, revision: u64) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.load(id)?;
        if stored
            .record
            .pending_control
            .is_some_and(|intent| intent.revision == revision)
        {
            stored.record.pending_control = None;
            return self.save(stored);
        }
        Ok(stored.record)
    }

    pub fn interrupt(&self, id: Uuid) -> Result<Record> {
        self.record_failure(id, TransferFailure::Interrupted)
    }

    pub fn record_failure(&self, id: Uuid, failure: TransferFailure) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.load(id)?;
        if stored.record.status.receiving() {
            if stored.record.status == Status::Interrupted && stored.record.failure == Some(failure)
            {
                return Ok(stored.record);
            }
            stored.record.status = Status::Interrupted;
            stored.record.failure = Some(failure);
            return self.save(stored);
        }
        if stored.record.status == Status::Failed && stored.record.failure.is_none() {
            stored.record.failure = Some(failure);
            return self.save(stored);
        }
        Ok(stored.record)
    }

    pub fn pause(&self, id: Uuid) -> Result<Record> {
        self.hold(id, TransferAction::Pause)
    }

    pub fn stop(&self, id: Uuid) -> Result<Record> {
        self.hold(id, TransferAction::Stop)
    }

    fn hold(&self, id: Uuid, action: TransferAction) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.load(id)?;
        ensure!(
            stored.record.status.receiving() || stored.record.status.held(),
            "Transfer is no longer active"
        );
        stored.record.manifest.validate(Utc::now().timestamp())?;
        if stored.record.local_hold == Some(action) {
            return Ok(stored.record);
        }
        stored.record.local_hold = Some(action);
        stored.set_pending_control(action)?;
        stored.apply_hold_status();
        self.save(stored)
    }

    pub fn resume(&self, id: Uuid) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.load(id)?;
        stored.record.manifest.validate(Utc::now().timestamp())?;
        if stored.record.status == Status::Transferring {
            // A crash may have left an active checkpoint on disk. The live
            // runtime decides whether it has an active connection for this ID.
            return Ok(stored.record);
        }
        ensure!(
            matches!(
                stored.record.status,
                Status::Paused | Status::Stopped | Status::Interrupted | Status::Ready
            ),
            "Transfer is unavailable for resuming"
        );
        ensure!(
            stored.record.local_hold.is_some() || stored.record.remote_hold.is_none(),
            "The other device must resume this transfer"
        );
        if stored.record.local_hold.take().is_some() {
            stored.set_pending_control(TransferAction::Resume)?;
        }
        stored.apply_hold_status();
        if !stored.record.status.held() {
            stored.record.status = Status::Ready;
            stored.record.failure = None;
        }
        self.save(stored)
    }

    /// Start a consented data stream after the transport has authenticated.
    pub fn start(&self, id: Uuid, direction: Direction) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.receiving(id, direction)?;
        if stored.record.status == Status::Transferring && stored.record.failure.is_none() {
            return Ok(stored.record);
        }
        stored.begin();
        self.save(stored)
    }

    /// Determine authoritative resume offsets by authenticating persisted chunks.
    pub fn missing(&self, id: Uuid) -> Result<Vec<MissingFile>> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.receiving(id, Direction::Incoming)?;
        let mut missing = Vec::new();
        let mut repaired = false;
        for (file_index, file) in stored.record.manifest.files.iter().enumerate() {
            let file_index = file_index as u32;
            let next = &mut stored.next[file_index as usize];
            for index in 0..*next {
                if self
                    .read_chunk(&stored.record.manifest, file_index, index)
                    .is_err()
                {
                    for stale in index..*next {
                        remove_file_if_present(&self.chunk_path(id, file_index, stale))?;
                    }
                    *next = index;
                    repaired = true;
                    break;
                }
            }
            if *next < file.chunks {
                missing.push(MissingFile {
                    file: file_index,
                    next: *next,
                });
            }
        }
        if repaired {
            self.save(stored)?;
        }
        Ok(missing)
    }

    pub fn put(&self, id: Uuid, file: u32, index: u32, bytes: &[u8]) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.receiving(id, Direction::Incoming)?;
        let length = stored.record.manifest.chunk_len(file, index)?;
        ensure!(bytes.len() == length, "Incorrect transfer chunk size");
        let next = stored.next[file as usize];
        ensure!(index <= next, "Out-of-order transfer chunk");
        if index < next {
            let old = self.read_chunk(&stored.record.manifest, file, index)?;
            ensure!(
                provider::constant_time_eq(&old, bytes),
                "Duplicate transfer chunk differs from the stored chunk"
            );
            return Ok(stored.record);
        }
        let sealed = seal(&self.key, &chunk_aad(id, file, index), bytes)?;
        write_atomic(&self.chunk_path(id, file, index), &sealed).context(
            "Could not save encrypted transfer chunk. Check available storage and retry",
        )?;
        stored.begin();
        stored.next[file as usize] += 1;
        self.save(stored)
    }

    pub fn record_remote_missing(&self, id: Uuid, missing: &[MissingFile]) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.receiving(id, Direction::Outgoing)?;
        ensure!(
            missing.len() <= stored.next.len(),
            "Invalid receiver resume response"
        );
        stored.begin();
        stored.next = stored
            .record
            .manifest
            .files
            .iter()
            .map(|file| file.chunks)
            .collect();
        for offset in missing {
            let file = stored.record.manifest.file(offset.file)?;
            let next = &mut stored.next[offset.file as usize];
            ensure!(
                offset.next < file.chunks && *next == file.chunks,
                "Invalid receiver resume response"
            );
            *next = offset.next;
        }
        self.save(stored)
    }

    pub fn record_ack(&self, id: Uuid, file: u32, index: u32) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.receiving(id, Direction::Outgoing)?;
        stored.record.manifest.chunk_len(file, index)?;
        let next = stored.next[file as usize];
        ensure!(index <= next, "Out-of-order transfer acknowledgment");
        if index < next {
            return Ok(stored.record);
        }
        stored.begin();
        stored.next[file as usize] += 1;
        self.save(stored)
    }

    pub fn mark_verified(&self, id: Uuid) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.load(id)?;
        ensure!(
            stored.record.direction == Direction::Outgoing,
            "Transfer is not outgoing"
        );
        if stored.record.status == Status::Verified {
            self.discard_payload(id)?;
            return Ok(stored.record);
        }
        ensure!(
            stored.record.status.receiving()
                || stored.record.status.held()
                || stored.record.status == Status::Cancelled,
            "Transfer cannot be reconciled as verified"
        );
        ensure!(
            stored.record.manifest.expires_at > Utc::now().timestamp(),
            "Transfer expired"
        );
        for (next, file) in stored.next.iter_mut().zip(&stored.record.manifest.files) {
            // The authenticated receiver can replay its verified receipt after
            // a lost ACK or after a concurrent local stop, pause or cancellation.
            *next = file.chunks;
        }
        let record = self.complete(stored)?;
        self.discard_payload(id)?;
        Ok(record)
    }

    /// An authenticated receiving peer reports a terminal integrity failure.
    pub fn fail_integrity(&self, id: Uuid) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let stored = self.load(id)?;
        ensure!(
            stored.record.direction == Direction::Outgoing,
            "Transfer is not outgoing"
        );
        if !(stored.record.status.receiving() || stored.record.status.held()) {
            return Ok(stored.record);
        }
        self.fail_integrity_stored(stored)
    }

    fn fail_integrity_stored(&self, mut stored: Stored) -> Result<Record> {
        let id = stored.record.manifest.id;
        stored.record.status = Status::Failed;
        stored.record.failure = Some(TransferFailure::Integrity);
        stored.record.local_hold = None;
        stored.record.remote_hold = None;
        stored.record.pending_control = None;
        let record = self.save(stored)?;
        self.discard_payload(id)?;
        Ok(record)
    }

    pub fn verify(&self, id: Uuid) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let stored = self.receiving(id, Direction::Incoming)?;
        for (file_index, file) in stored.record.manifest.files.iter().enumerate() {
            ensure!(
                stored.next[file_index] == file.chunks,
                "Transfer still has missing chunks"
            );
            let mut hasher = Sha3_256Hasher::new();
            for chunk in 0..file.chunks {
                let bytes = self.read_chunk(&stored.record.manifest, file_index as u32, chunk)?;
                hasher.update(&bytes);
            }
            if !provider::constant_time_eq(
                hex::encode(hasher.finalize()).as_bytes(),
                file.digest.as_bytes(),
            ) {
                self.fail_integrity_stored(stored)?;
                bail!("Final file integrity check failed");
            }
        }
        self.complete(stored)
    }

    pub fn read_verified(&self, id: Uuid, file: u32) -> Result<VerifiedReader> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        self.verified_reader(id, file)
    }

    fn verified_reader(&self, id: Uuid, file: u32) -> Result<VerifiedReader> {
        let stored = self.load(id)?;
        ensure!(
            stored.record.direction == Direction::Incoming
                && stored.record.status == Status::Verified,
            "Transfer has not been verified"
        );
        stored.record.manifest.validate(Utc::now().timestamp())?;
        stored.record.manifest.file(file)?;
        Ok(VerifiedReader {
            root: self.chunk_dir(id),
            key: self.key.clone(),
            manifest: stored.record.manifest,
            file,
            next: 0,
            buffer: Zeroizing::new(Vec::new()),
            position: 0,
            hasher: Some(Sha3_256Hasher::new()),
        })
    }

    /// Record which authenticated session carries this transfer. The value is
    /// a public transcript digest prefix, so it reveals no key material.
    pub fn note_session(&self, id: Uuid, binding: &[u8; 32]) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        let mut stored = self.load(id)?;
        let session = hex::encode_upper(&binding[..8]);
        if stored.record.session_id.as_deref() == Some(session.as_str()) {
            return Ok(stored.record);
        }
        stored.record.session_id = Some(session);
        self.save(stored)
    }

    pub fn set_destination(&self, id: Uuid, file: u32, destination: String) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        self.save_destination(id, file, destination, None)
    }

    pub fn set_android_destination(
        &self,
        id: Uuid,
        file: u32,
        destination: String,
        uri: String,
    ) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        ensure!(
            crate::security::content_uri::is_content_uri(&uri)
                && uri.len() <= 4096
                && !uri.chars().any(char::is_control),
            "Invalid Android transfer destination"
        );
        self.save_destination(id, file, destination, Some(uri))
    }

    fn save_destination(
        &self,
        id: Uuid,
        file: u32,
        destination: String,
        android_uri: Option<String>,
    ) -> Result<Record> {
        ensure!(
            !destination.is_empty()
                && destination.len() <= 4096
                && !destination.chars().any(char::is_control),
            "Invalid transfer destination"
        );
        let mut stored = self.load(id)?;
        ensure!(
            stored.record.direction == Direction::Incoming
                && stored.record.status == Status::Verified,
            "Transfer has not been verified"
        );
        stored.record.manifest.file(file)?;
        stored.record.destination = Some(destination.clone());
        stored.record.destinations[file as usize] = Some(destination);
        if let Some(uri) = android_uri {
            stored.record.android_destinations.insert(file, uri);
        } else {
            stored.record.android_destinations.remove(&file);
        }
        self.save(stored)
    }

    /// Publish a verified file without replacing any existing destination.
    /// Callers must get the destination from a user-authorized native picker.
    pub fn export_file(&self, id: Uuid, file: u32, destination: &Path) -> Result<Record> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow!("Transfer storage is unavailable"))?;
        ensure!(
            destination.is_absolute(),
            "Transfer destination must be an absolute path"
        );
        let name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .context("Invalid destination name")?;
        validate_relative_path(name)?;
        let parent = destination
            .parent()
            .context("Invalid transfer destination")?;
        ensure!(
            checked_metadata(parent)?.is_dir(),
            "Invalid transfer destination directory"
        );
        let parent = parent.canonicalize()?;
        let destination = parent.join(name);
        ensure!(
            fs::symlink_metadata(&destination)
                .is_err_and(|error| error.kind() == io::ErrorKind::NotFound),
            "Transfer destination already exists or is inaccessible"
        );
        let mut reader = self.verified_reader(id, file)?;
        let staging = self.export_staging(id);
        remove_dir_if_present(&staging)?;
        private_dir(&staging)?;
        let result = (|| -> Result<()> {
            let mut output = tempfile::NamedTempFile::new_in(&staging)?;
            io::copy(&mut reader, output.as_file_mut())?;
            output.as_file().sync_all()?;
            output.persist_noclobber(&destination).context(
                "Could not publish the export safely. Choose an unused destination on the same drive as Qguard storage",
            )?;
            Ok(())
        })();
        let cleanup = remove_dir_if_present(&staging);
        result?;
        cleanup?;
        self.save_destination(id, file, destination.display().to_string(), None)
    }

    fn complete(&self, mut stored: Stored) -> Result<Record> {
        stored.record.status = Status::Verified;
        stored.record.verified_files = stored.record.manifest.files.len() as u32;
        stored.record.completed_at_ms = Some(Utc::now().timestamp_millis());
        stored.record.failure = None;
        stored.record.pending_control = None;
        stored.record.local_hold = None;
        stored.record.remote_hold = None;
        self.save(stored)
    }

    fn receiving(&self, id: Uuid, direction: Direction) -> Result<Stored> {
        let stored = self.load(id)?;
        ensure!(
            stored.record.direction == direction && stored.record.status.receiving(),
            "Transfer is not authorized or active"
        );
        ensure!(
            stored.record.manifest.expires_at > Utc::now().timestamp(),
            "Transfer expired"
        );
        Ok(stored)
    }

    fn transfer_dir(&self, id: Uuid) -> PathBuf {
        self.root.join(id.to_string())
    }

    fn record_path(&self, id: Uuid) -> PathBuf {
        self.transfer_dir(id).join("record.qgx")
    }

    fn source_path(&self, id: Uuid) -> PathBuf {
        self.transfer_dir(id).join("source.qgx")
    }

    fn chunk_dir(&self, id: Uuid) -> PathBuf {
        self.transfer_dir(id).join("chunks")
    }

    fn export_staging(&self, id: Uuid) -> PathBuf {
        self.transfer_dir(id).join("private-export")
    }

    fn chunk_path(&self, id: Uuid, file: u32, index: u32) -> PathBuf {
        chunk_path(&self.chunk_dir(id), file, index)
    }

    fn read_chunk(&self, manifest: &Manifest, file: u32, index: u32) -> Result<Zeroizing<Vec<u8>>> {
        read_chunk(
            &self.key,
            &self.chunk_dir(manifest.id),
            manifest,
            file,
            index,
        )
    }

    fn load(&self, id: Uuid) -> Result<Stored> {
        ensure!(
            checked_metadata(&self.transfer_dir(id))?.is_dir(),
            "Invalid transfer record directory"
        );
        let plaintext = open(
            &self.key,
            &aad(id, b"record"),
            &self.record_path(id),
            MAX_DOC_BYTES,
        )?;
        let mut stored: Stored = serde_json::from_slice(&plaintext)?;
        ensure!(
            stored.record.manifest.id == id,
            "Invalid transfer record identifier"
        );
        ensure!(
            stored.next.len() == stored.record.manifest.files.len()
                && stored.record.destinations.len() == stored.next.len(),
            "Invalid transfer checkpoint"
        );
        ensure!(
            stored
                .next
                .iter()
                .zip(&stored.record.manifest.files)
                .all(|(next, file)| *next <= file.chunks),
            "Invalid transfer checkpoint"
        );
        if stored.record.status == Status::Paused
            && stored.record.local_hold.is_none()
            && stored.record.remote_hold.is_none()
        {
            // Older records only had a local pause flag. Keep that explicit
            // hold until its owner resumes it, including after an upgrade.
            stored.record.local_hold = Some(TransferAction::Pause);
        }
        stored.update_progress();
        Ok(stored)
    }

    fn save(&self, mut stored: Stored) -> Result<Record> {
        let id = stored.record.manifest.id;
        stored.record.updated_at = Utc::now().timestamp();
        stored.record.revision = stored.next_revision()?;
        stored.update_progress();
        let plaintext = Zeroizing::new(serde_json::to_vec(&stored)?);
        ensure!(
            plaintext.len() <= MAX_DOC_BYTES,
            "Transfer checkpoint exceeds the storage limit"
        );
        write_atomic(
            &self.record_path(id),
            &seal(&self.key, &aad(id, b"record"), &plaintext)?,
        )?;
        Ok(stored.record)
    }

    fn discard_payload(&self, id: Uuid) -> Result<()> {
        remove_file_if_present(&self.source_path(id))?;
        remove_dir_if_present(&self.chunk_dir(id))
    }

    fn prune(&self) -> Result<Vec<Record>> {
        let now = Utc::now().timestamp();
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let Some(id) = entry
                .file_name()
                .to_str()
                .and_then(|name| Uuid::parse_str(name).ok())
            else {
                continue;
            };
            if !self.record_path(id).exists() {
                // A process exit during queue preparation can leave encrypted
                // chunks without a committed manifest. They cannot be sent.
                remove_dir_if_present(&self.transfer_dir(id))?;
                continue;
            }
            let mut stored = self.load(id)?;
            // Publication links an already complete file from private staging.
            // An app exit during export can leave a private file to clean up.
            remove_dir_if_present(&self.export_staging(id))?;
            if stored.record.manifest.expires_at <= now
                && !stored.record.status.discarded()
                && stored.record.status != Status::Verified
            {
                stored.record.status = Status::Expired;
                stored.record.local_hold = None;
                stored.record.remote_hold = None;
                stored.record.pending_control = None;
                records.push(self.save(stored)?);
                self.discard_payload(id)?;
                continue;
            }
            let record = if stored.record.manifest.expires_at <= now
                && stored.record.pending_control.is_some()
            {
                stored.record.pending_control = None;
                self.save(stored)?
            } else {
                stored.record
            };
            if record.status == Status::Cancelled {
                let _ = self.discard_payload(id);
            } else if record.status.discarded() || record.manifest.expires_at <= now {
                self.discard_payload(id)?;
            }
            records.push(record);
        }
        Ok(records)
    }

    fn ensure_capacity(&self, records: &[Record]) -> Result<()> {
        if records.len() < MAX_RECORDS {
            return Ok(());
        }
        let now = Utc::now().timestamp();
        let record = records
            .iter()
            .filter(|record| {
                (record.pending_control.is_none() || record.manifest.expires_at <= now)
                    && (record.status.discarded()
                        || (record.status == Status::Verified
                            && (record.direction == Direction::Outgoing
                                || record.manifest.expires_at <= now)))
            })
            .min_by_key(|record| record.updated_at)
            .context(
                "Transfer history is full. Cancel an active transfer or wait for its expiration",
            )?;
        fs::remove_dir_all(self.transfer_dir(record.manifest.id))?;
        Ok(())
    }
}

/// Plaintext lives only in the caller's buffer and one zeroizing chunk buffer.
pub struct VerifiedReader {
    root: PathBuf,
    key: Zeroizing<[u8; 32]>,
    manifest: Manifest,
    file: u32,
    next: u32,
    buffer: Zeroizing<Vec<u8>>,
    position: usize,
    hasher: Option<Sha3_256Hasher>,
}

impl Read for VerifiedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let file = &self.manifest.files[self.file as usize];
        if self.position == self.buffer.len() && self.next < file.chunks {
            let chunk = read_chunk(&self.key, &self.root, &self.manifest, self.file, self.next)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Encrypted transfer chunk failed authentication",
                    )
                })?;
            self.hasher
                .as_mut()
                .ok_or_else(invalid_digest)?
                .update(&chunk);
            if self.next + 1 == file.chunks {
                let digest = self.hasher.take().ok_or_else(invalid_digest)?.finalize();
                if !provider::constant_time_eq(
                    hex::encode(digest).as_bytes(),
                    file.digest.as_bytes(),
                ) {
                    return Err(invalid_digest());
                }
            }
            self.buffer = chunk;
            self.position = 0;
            self.next += 1;
        }
        let available = &self.buffer[self.position..];
        let length = available.len().min(output.len());
        output[..length].copy_from_slice(&available[..length]);
        self.position += length;
        Ok(length)
    }
}

fn invalid_digest() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Verified transfer file changed")
}

fn aad(id: Uuid, scope: &[u8]) -> Vec<u8> {
    let mut aad = b"QG-XFER-storage-v1\0".to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(scope);
    aad
}

fn chunk_aad(id: Uuid, file: u32, index: u32) -> Vec<u8> {
    let mut aad = aad(id, b"chunk");
    aad.extend_from_slice(&file.to_be_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

fn chunk_path(root: &Path, file: u32, index: u32) -> PathBuf {
    root.join(format!("{file}-{index}.qgx"))
}

fn read_chunk(
    key: &[u8; 32],
    root: &Path,
    manifest: &Manifest,
    file: u32,
    index: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        checked_metadata(root)?.is_dir(),
        "Invalid encrypted chunk directory"
    );
    let expected = manifest.chunk_len(file, index)?;
    let chunk = open(
        key,
        &chunk_aad(manifest.id, file, index),
        &chunk_path(root, file, index),
        expected,
    )?;
    ensure!(chunk.len() == expected, "Invalid encrypted chunk length");
    Ok(chunk)
}

fn seal(master: &[u8; 32], aad: &[u8], bytes: &[u8]) -> Result<Vec<u8>> {
    // A fresh 256-bit salt gives each atomic write its own AES key, including
    // a retry after a crash between the chunk and its checkpoint writes.
    let salt = provider::random_array::<SALT_BYTES>();
    let mut key = Zeroizing::new([0u8; 32]);
    provider::hkdf_sha3_256(Some(&salt), master, aad, &mut *key)?;
    let sealed = provider::aes256gcm_seal(&key, aad, bytes)?;
    let mut envelope = Vec::with_capacity(OVERHEAD + sealed.ciphertext.len());
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&sealed.nonce);
    envelope.extend_from_slice(&sealed.tag);
    envelope.extend_from_slice(&sealed.ciphertext);
    Ok(envelope)
}

fn open(master: &[u8; 32], aad: &[u8], path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let metadata = checked_metadata(path)?;
    ensure!(metadata.is_file(), "Invalid encrypted transfer record");
    let size = metadata.len();
    ensure!(
        (OVERHEAD as u64..=(OVERHEAD + limit) as u64).contains(&size),
        "Invalid encrypted transfer record size"
    );
    let mut bytes = Vec::with_capacity(size as usize);
    read_file(path, &metadata)?
        .take(size + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == size,
        "Encrypted transfer record changed while reading"
    );
    let (salt, bytes) = bytes.split_at(SALT_BYTES);
    let (nonce, bytes) = bytes.split_at(NONCE_BYTES);
    let (tag, ciphertext) = bytes.split_at(TAG_BYTES);
    let mut key = Zeroizing::new([0u8; 32]);
    provider::hkdf_sha3_256(Some(salt), master, aad, &mut *key)?;
    Ok(Zeroizing::new(provider::aes256gcm_open(
        &key, nonce, aad, ciphertext, tag,
    )?))
}

fn private_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    ensure!(
        checked_metadata(path)?.is_dir(),
        "Invalid private transfer storage directory"
    );
    Ok(())
}

fn remove_file_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_dir_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            require_regular_path(&metadata)?;
            ensure!(metadata.is_dir(), "Invalid transfer storage directory");
            fs::remove_dir_all(path)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("qguard-xfer-test-{}", Uuid::new_v4()));
            private_dir(&path).unwrap();
            Self(path)
        }

        fn store(&self, name: &str) -> Store {
            Store::open(self.0.join(name), [7; 32]).unwrap()
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn upload(directory: &Directory, bytes: &[u8]) -> Upload {
        let source = directory.0.join("report.pdf");
        fs::write(&source, bytes).unwrap();
        Upload::prepare(
            "sender".into(),
            "recipient".into(),
            vec![selected_source(source).unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn consent_is_required_and_manifest_cannot_change() {
        let directory = Directory::new();
        let upload = upload(&directory, b"confidential");
        let manifest = upload.manifest().clone();
        let id = manifest.id;
        let receiver = directory.store("receiver");
        assert!(receiver
            .offer(manifest.clone(), "impersonator", "recipient")
            .is_err());
        assert!(receiver
            .offer(manifest.clone(), "sender", "unintended")
            .is_err());
        assert_eq!(
            receiver
                .offer(manifest.clone(), "sender", "recipient")
                .unwrap()
                .status,
            Status::AwaitingConsent
        );
        assert!(receiver.missing(id).is_err());
        assert!(receiver.put(id, 0, 0, b"confidential").is_err());
        assert!(receiver.read_verified(id, 0).is_err());
        let mut altered = manifest;
        altered.files[0].path = "different.pdf".into();
        assert!(receiver.offer(altered, "sender", "recipient").is_err());
        assert_eq!(receiver.reject(id).unwrap().status, Status::Rejected);
        assert!(receiver.accept(id).is_err());
    }

    #[test]
    fn resumes_after_restart_and_repairs_corrupt_checkpoint() {
        let directory = Directory::new();
        let mut bytes = vec![0x31; CHUNK_SIZE as usize];
        bytes.extend_from_slice(b"last chunk");
        let upload = upload(&directory, &bytes);
        let manifest = upload.manifest().clone();
        let id = manifest.id;
        let sender = directory.store("sender");
        let receiver = directory.store("receiver");
        sender.register_upload(&upload).unwrap();
        receiver
            .offer(manifest.clone(), "sender", "recipient")
            .unwrap();
        receiver.accept(id).unwrap();
        assert!(receiver.put(id, 0, 1, b"last chunk").is_err());
        receiver
            .put(id, 0, 0, &upload.read_chunk(0, 0).unwrap())
            .unwrap();
        assert_eq!(
            receiver.get(id).unwrap().completed_bytes,
            u64::from(CHUNK_SIZE)
        );
        receiver.interrupt(id).unwrap();
        drop((sender, receiver, upload));

        let sender = directory.store("sender");
        let receiver = directory.store("receiver");
        let upload = sender.open_upload(id).unwrap();
        assert_eq!(upload.manifest(), &manifest);
        let missing = receiver.missing(id).unwrap();
        assert_eq!(missing, vec![MissingFile { file: 0, next: 1 }]);
        assert_eq!(
            sender
                .record_remote_missing(id, &missing)
                .unwrap()
                .completed_bytes,
            u64::from(CHUNK_SIZE)
        );
        fs::write(receiver.chunk_path(id, 0, 0), b"corrupt").unwrap();
        assert_eq!(
            receiver.missing(id).unwrap(),
            vec![MissingFile { file: 0, next: 0 }]
        );
        assert_eq!(receiver.get(id).unwrap().completed_bytes, 0);

        for index in 0..2 {
            let chunk = upload.read_chunk(0, index).unwrap();
            receiver.put(id, 0, index, &chunk).unwrap();
            receiver.put(id, 0, index, &chunk).unwrap();
        }
        assert!(receiver.put(id, 0, 1, b"last chunx").is_err());
        assert_eq!(receiver.verify(id).unwrap().status, Status::Verified);
        assert_eq!(
            sender.mark_verified(id).unwrap().completed_bytes,
            bytes.len() as u64
        );
        let mut actual = Vec::new();
        receiver
            .read_verified(id, 0)
            .unwrap()
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(actual, bytes);
        assert!(!fs::read(receiver.chunk_path(id, 0, 1))
            .unwrap()
            .windows(10)
            .any(|bytes| bytes == b"last chunk"));
        let destination = directory.0.join("export.pdf");
        receiver.export_file(id, 0, &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        assert!(receiver.export_file(id, 0, &destination).is_err());
    }

    #[test]
    fn rejects_changed_source_and_wrong_final_digest() {
        let directory = Directory::new();
        let upload = upload(&directory, b"authentic");
        let manifest = upload.manifest().clone();
        let id = manifest.id;
        fs::write(directory.0.join("report.pdf"), b"impostors").unwrap();
        assert!(upload.read_chunk(0, 0).is_err());
        let receiver = directory.store("receiver");
        receiver.offer(manifest, "sender", "recipient").unwrap();
        receiver.accept(id).unwrap();
        receiver.put(id, 0, 0, b"impostors").unwrap();
        assert!(receiver.verify(id).is_err());
        assert_eq!(receiver.get(id).unwrap().status, Status::Failed);
        assert!(!receiver.chunk_dir(id).exists());
    }

    #[test]
    fn refuses_unsafe_paths_and_cross_record_chunk_replay() {
        for name in [
            "../escape",
            "C:/boot",
            "inside/../escape",
            "//remote/share",
            "one\\two",
            "com1.txt",
            "report.",
            "report:stream",
        ] {
            assert!(
                validate_relative_path(name).is_err(),
                "accepted unsafe name: {name}"
            );
        }
        let directory = Directory::new();
        let first = upload(&directory, b"original");
        let second = upload(&directory, b"separate");
        let receiver = directory.store("receiver");
        for upload in [&first, &second] {
            let manifest = upload.manifest().clone();
            let id = manifest.id;
            receiver.offer(manifest, "sender", "recipient").unwrap();
            receiver.accept(id).unwrap();
        }
        let first_id = first.manifest().id;
        let second_id = second.manifest().id;
        receiver.put(first_id, 0, 0, b"original").unwrap();
        receiver.put(second_id, 0, 0, b"separate").unwrap();
        fs::copy(
            receiver.chunk_path(first_id, 0, 0),
            receiver.chunk_path(second_id, 0, 0),
        )
        .unwrap();
        assert_eq!(
            receiver.missing(second_id).unwrap(),
            vec![MissingFile { file: 0, next: 0 }]
        );
    }

    #[test]
    fn pause_survives_restart_and_requires_local_resume() {
        let directory = Directory::new();
        let upload = upload(&directory, b"confidential");
        let manifest = upload.manifest().clone();
        let id = manifest.id;
        let receiver = directory.store("receiver");
        receiver
            .offer(manifest.clone(), "sender", "recipient")
            .unwrap();
        receiver.accept_with_destination(id, true).unwrap();
        assert_eq!(receiver.pause(id).unwrap().status, Status::Paused);
        drop(receiver);
        let receiver = directory.store("receiver");
        receiver.recover_interrupted().unwrap();
        let resumed_offer = receiver.offer(manifest, "sender", "recipient").unwrap();
        assert_eq!(resumed_offer.status, Status::Paused);
        assert!(resumed_offer.receive_into_vault);
        assert_eq!(receiver.interrupt(id).unwrap().status, Status::Paused);
        assert!(receiver.missing(id).is_err());
        assert!(receiver.put(id, 0, 0, b"confidential").is_err());
        receiver.resume(id).unwrap();
        receiver.put(id, 0, 0, b"confidential").unwrap();
        assert_eq!(receiver.verify(id).unwrap().status, Status::Verified);
    }

    #[test]
    fn peer_stop_and_resume_are_ordered_and_preserve_checkpoint_across_restart() {
        let directory = Directory::new();
        let bytes = b"checkpointed data";
        let upload = upload(&directory, bytes);
        let manifest = upload.manifest().clone();
        let id = manifest.id;
        let sender = directory.store("sender");
        let receiver = directory.store("receiver");
        sender.register_upload(&upload).unwrap();
        receiver.offer(manifest, "sender", "recipient").unwrap();
        receiver.accept(id).unwrap();
        let started = receiver.put(id, 0, 0, bytes).unwrap();
        assert!(started.started_at_ms.is_some());
        assert!(started.completed_at_ms.is_none());
        assert_eq!(started.verified_files, 0);
        assert_eq!(started.file_progress[0].completed_bytes, bytes.len() as u64);
        assert!(started.file_progress[0].payload_complete);

        let stop = sender.stop(id).unwrap().pending_control.unwrap();
        let stopped = receiver
            .apply_remote_control(id, stop.revision, stop.action)
            .unwrap();
        assert_eq!(stopped.status, Status::Stopped);
        assert_eq!(stopped.completed_bytes, started.completed_bytes);
        assert!(receiver.resume(id).is_err());
        assert!(receiver.verify(id).is_err());
        drop(receiver);

        let receiver = directory.store("receiver");
        receiver.recover_interrupted().unwrap();
        assert_eq!(receiver.get(id).unwrap().status, Status::Stopped);
        receiver.pause(id).unwrap();
        let resume = sender.resume(id).unwrap().pending_control.unwrap();
        assert!(resume.revision > stop.revision);
        assert_eq!(
            sender
                .ack_control(id, stop.revision)
                .unwrap()
                .pending_control,
            Some(resume)
        );
        let still_paused = receiver
            .apply_remote_control(id, resume.revision, resume.action)
            .unwrap();
        assert_eq!(still_paused.status, Status::Paused);
        let replay = receiver
            .apply_remote_control(id, stop.revision, stop.action)
            .unwrap();
        assert_eq!(replay.revision, still_paused.revision);
        assert_eq!(replay.status, Status::Paused);
        assert!(sender
            .ack_control(id, resume.revision)
            .unwrap()
            .pending_control
            .is_none());

        receiver.resume(id).unwrap();
        assert!(receiver.missing(id).unwrap().is_empty());
        let verified = receiver.verify(id).unwrap();
        assert_eq!(verified.started_at_ms, started.started_at_ms);
        assert!(verified.completed_at_ms.is_some());
        assert_eq!(verified.verified_files, 1);
    }

    #[test]
    fn authenticated_resume_cannot_accept_an_offer_for_the_recipient() {
        let directory = Directory::new();
        let upload = upload(&directory, b"requires consent");
        let manifest = upload.manifest().clone();
        let id = manifest.id;
        let receiver = directory.store("receiver");
        receiver.offer(manifest, "sender", "recipient").unwrap();
        let stopped = receiver
            .apply_remote_control(id, 1, TransferAction::Stop)
            .unwrap();
        assert_eq!(stopped.status, Status::AwaitingConsent);
        assert_eq!(stopped.remote_hold, Some(TransferAction::Stop));
        let released = receiver
            .apply_remote_control(id, 2, TransferAction::Resume)
            .unwrap();
        assert_eq!(released.status, Status::AwaitingConsent);
        assert!(released.remote_hold.is_none());
        assert!(receiver.start(id, Direction::Incoming).is_err());
        assert!(receiver.put(id, 0, 0, b"requires consent").is_err());
    }

    #[test]
    fn committed_integrity_receipt_survives_a_racing_cancel() {
        let directory = Directory::new();
        let upload = upload(&directory, b"verified data");
        let manifest = upload.manifest().clone();
        let id = manifest.id;
        let sender = directory.store("sender");
        let receiver = directory.store("receiver");
        sender.register_upload(&upload).unwrap();
        receiver.offer(manifest, "sender", "recipient").unwrap();
        receiver.accept(id).unwrap();
        receiver.put(id, 0, 0, b"verified data").unwrap();
        let verified = receiver.verify(id).unwrap();

        let cancel = sender.cancel(id).unwrap().pending_control.unwrap();
        let receipt = receiver
            .apply_remote_control(id, cancel.revision, cancel.action)
            .unwrap();
        assert_eq!(receipt.status, Status::Verified);
        assert_eq!(receipt.revision, verified.revision);
        assert_eq!(receipt.completed_at_ms, verified.completed_at_ms);
        assert!(receiver.cancel(id).is_err());
        let mut saved = Vec::new();
        receiver
            .read_verified(id, 0)
            .unwrap()
            .read_to_end(&mut saved)
            .unwrap();
        assert_eq!(saved, b"verified data");

        let reconciled = sender.mark_verified(id).unwrap();
        assert_eq!(reconciled.status, Status::Verified);
        assert!(reconciled.pending_control.is_none());
        assert_eq!(reconciled.completed_bytes, saved.len() as u64);
        assert_eq!(
            sender.mark_verified(id).unwrap().completed_at_ms,
            reconciled.completed_at_ms
        );
    }

    #[test]
    fn committed_cancel_retries_payload_cleanup_and_expires_undelivered_intent() {
        let directory = Directory::new();
        let upload = upload(&directory, b"cancelled data");
        let id = upload.manifest().id;
        let sender = directory.store("sender");
        sender.register_upload(&upload).unwrap();
        fs::write(sender.chunk_dir(id), b"blocked cleanup fixture").unwrap();

        let cancelled = sender.cancel(id).unwrap();
        assert_eq!(cancelled.status, Status::Cancelled);
        assert!(cancelled.pending_control.is_some());
        assert!(sender.open_upload(id).is_err());
        assert_eq!(sender.list().unwrap()[0].status, Status::Cancelled);
        fs::remove_file(sender.chunk_dir(id)).unwrap();
        private_dir(&sender.chunk_dir(id)).unwrap();
        let repeated = sender.cancel(id).unwrap();
        assert_eq!(repeated.pending_control, cancelled.pending_control);
        assert_eq!(repeated.revision, cancelled.revision);
        assert!(!sender.chunk_dir(id).exists());

        let mut stored = sender.load(id).unwrap();
        stored.record.manifest.expires_at = Utc::now().timestamp() - 1;
        sender.save(stored).unwrap();
        let expired = &sender.list().unwrap()[0];
        assert_eq!(expired.status, Status::Cancelled);
        assert!(expired.pending_control.is_none());
    }

    #[test]
    fn batch_handles_nested_folder_and_empty_file() {
        let directory = Directory::new();
        let selection = directory.0.join("Documents");
        fs::create_dir_all(selection.join("2026")).unwrap();
        fs::write(selection.join("2026").join("latest.txt"), b"verified").unwrap();
        let empty = directory.0.join("empty.txt");
        fs::write(&empty, []).unwrap();
        let selection = selected_source(selection).unwrap();
        let empty = selected_source(empty).unwrap();
        let upload =
            Upload::prepare("sender".into(), "recipient".into(), vec![selection, empty]).unwrap();
        let manifest = upload.manifest().clone();
        assert_eq!(manifest.files[0].path, "Documents/2026/latest.txt");
        assert_eq!(manifest.files[1].chunks, 0);
        let id = manifest.id;
        let receiver = directory.store("receiver");
        receiver.offer(manifest, "sender", "recipient").unwrap();
        receiver.accept(id).unwrap();
        assert_eq!(
            receiver.missing(id).unwrap(),
            vec![MissingFile { file: 0, next: 0 }]
        );
        receiver
            .put(id, 0, 0, &upload.read_chunk(0, 0).unwrap())
            .unwrap();
        assert_eq!(receiver.verify(id).unwrap().verified_files, 2);
        let mut empty = Vec::new();
        receiver
            .read_verified(id, 1)
            .unwrap()
            .read_to_end(&mut empty)
            .unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn rejects_declined_outgoing_and_erases_source_checkpoint() {
        let directory = Directory::new();
        let upload = upload(&directory, b"confidential");
        let id = upload.manifest().id;
        let sender = directory.store("sender");
        sender.register_upload(&upload).unwrap();
        assert!(sender.reject(id).is_err());
        assert_eq!(sender.reject_outgoing(id).unwrap().status, Status::Rejected);
        assert!(sender.open_upload(id).is_err());
        assert!(!sender.source_path(id).exists());
    }

    #[test]
    fn encrypted_outbound_queue_survives_restart_without_the_original_file() {
        let directory = Directory::new();
        let path = directory.0.join("queued-report.pdf");
        let mut expected = vec![0x45; CHUNK_SIZE as usize];
        expected.extend_from_slice(b"private queued tail");
        fs::write(&path, &expected).unwrap();
        let sender = directory.store("sender");
        let record = sender
            .queue_sources(
                "sender".into(),
                "recipient".into(),
                vec![SelectedSource::Path(selected_source(path.clone()).unwrap())],
            )
            .unwrap();
        let id = record.manifest.id;
        assert!(record.queued_locally);
        assert_eq!(record.completed_bytes, 0);
        assert!(!sender.source_path(id).exists());
        fs::remove_file(&path).unwrap();
        drop(sender);

        let sender = directory.store("sender");
        let upload = sender.open_upload(id).unwrap();
        let mut actual = upload.read_chunk(0, 0).unwrap().to_vec();
        actual.extend_from_slice(&upload.read_chunk(0, 1).unwrap());
        assert_eq!(actual, expected);
        assert!(!fs::read(sender.chunk_path(id, 0, 1))
            .unwrap()
            .windows(b"private queued tail".len())
            .any(|part| part == b"private queued tail"));
        fs::write(sender.chunk_path(id, 0, 1), b"tampered").unwrap();
        assert!(upload.read_chunk(0, 1).is_err());
        sender.cancel(id).unwrap();
        assert!(!sender.chunk_dir(id).exists());
    }

    #[test]
    fn queued_streams_measure_short_reads_and_reject_provider_size_changes() {
        struct ShortReads<'a>(&'a [u8]);
        impl Read for ShortReads<'_> {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                let length = output.len().min(self.0.len()).min(7);
                output[..length].copy_from_slice(&self.0[..length]);
                self.0 = &self.0[length..];
                Ok(length)
            }
        }
        let directory = Directory::new();
        let sender = directory.store("sender");
        let id = Uuid::new_v4();
        private_dir(&sender.chunk_dir(id)).unwrap();
        let bytes = b"document provider data of unknown length";
        let mut reader = ShortReads(bytes);
        let file = sender
            .stage_reader(
                id,
                0,
                "document.txt".into(),
                None,
                &mut reader,
                MAX_BYTES,
                &|| Ok(()),
            )
            .unwrap();
        assert_eq!(file.size, bytes.len() as u64);
        assert_eq!(file.chunks, 1);
        assert_eq!(file.digest, hex::encode(provider::sha3_256(bytes)));
        let mut reader = ShortReads(bytes);
        assert!(sender
            .stage_reader(
                id,
                1,
                "grew.txt".into(),
                Some(3),
                &mut reader,
                MAX_BYTES,
                &|| Ok(())
            )
            .is_err());
        let mut reader = ShortReads(bytes);
        assert!(sender
            .stage_reader(
                id,
                2,
                "shrunk.txt".into(),
                Some(1000),
                &mut reader,
                MAX_BYTES,
                &|| Ok(())
            )
            .is_err());
        let mut reader = ShortReads(bytes);
        assert!(sender
            .stage_reader(id, 3, "full.txt".into(), None, &mut reader, 3, &|| Ok(()))
            .is_err());
    }

    #[test]
    fn incomplete_queued_payloads_are_removed_and_completed_sends_release_storage() {
        let directory = Directory::new();
        let sender = directory.store("sender");
        let orphan = Uuid::new_v4();
        private_dir(&sender.chunk_dir(orphan)).unwrap();
        write_atomic(
            &sender.chunk_path(orphan, 0, 0),
            &seal(&sender.key, &chunk_aad(orphan, 0, 0), b"ciphertext source").unwrap(),
        )
        .unwrap();
        sender.list().unwrap();
        assert!(!sender.transfer_dir(orphan).exists());

        let source = directory.0.join("complete.txt");
        fs::write(&source, b"complete").unwrap();
        let record = sender
            .queue_sources(
                "sender".into(),
                "recipient".into(),
                vec![SelectedSource::Path(selected_source(source).unwrap())],
            )
            .unwrap();
        assert!(sender.chunk_dir(record.manifest.id).exists());
        sender.mark_verified(record.manifest.id).unwrap();
        assert!(!sender.chunk_dir(record.manifest.id).exists());
    }

    #[test]
    fn revoked_queue_authorization_removes_staged_bytes_before_publication() {
        let directory = Directory::new();
        let sender = directory.store("sender");
        let source = directory.0.join("revoked.bin");
        fs::write(&source, vec![0x61; CHUNK_SIZE as usize + 1]).unwrap();
        let revoked = std::cell::Cell::new(false);
        let result = sender.queue_sources_authorized(
            "sender".into(),
            "recipient".into(),
            vec![SelectedSource::Path(selected_source(source).unwrap())],
            || {
                let has_payload = fs::read_dir(&sender.root)?
                    .filter_map(|entry| entry.ok())
                    .any(|entry| {
                        fs::read_dir(entry.path().join("chunks"))
                            .is_ok_and(|mut chunks| chunks.next().is_some())
                    });
                if has_payload {
                    revoked.set(true);
                    bail!("Local authorization revoked");
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(revoked.get());
        assert!(sender.list().unwrap().is_empty());
        assert_eq!(fs::read_dir(&sender.root).unwrap().count(), 0);
    }

    #[test]
    #[ignore = "runs an explicit local storage benchmark and writes temporary files"]
    fn benchmark_transfer_storage() {
        use std::io::Write;
        use std::time::Instant;

        let mib = std::env::var("QGUARD_XFER_BENCH_MIB")
            .map(|value| value.parse::<u64>().unwrap())
            .unwrap_or(100);
        assert!([100, 500, 1024, 5120, 10240].contains(&mib));
        let size = mib * 1024 * 1024;
        let directory = Directory::new();
        let path = directory.0.join("benchmark.bin");
        let mut fixture = File::create(&path).unwrap();
        let buffer = vec![0x35; CHUNK_SIZE as usize];
        let mut remaining = size;
        while remaining > 0 {
            let length = remaining.min(u64::from(CHUNK_SIZE)) as usize;
            fixture.write_all(&buffer[..length]).unwrap();
            remaining -= length as u64;
        }
        fixture.sync_all().unwrap();
        drop(fixture);
        let path = selected_source(path).unwrap();
        let start = Instant::now();
        let upload = Upload::prepare("sender".into(), "recipient".into(), vec![path]).unwrap();
        let manifest = upload.manifest().clone();
        let prepare = start.elapsed();
        let id = manifest.id;
        let chunks = manifest.files[0].chunks;
        let stop = (chunks * 65) / 100;
        let receiver = directory.store("receiver");
        receiver.offer(manifest, "sender", "recipient").unwrap();
        receiver.accept(id).unwrap();

        let start = Instant::now();
        for chunk in 0..stop {
            receiver
                .put(id, 0, chunk, &upload.read_chunk(0, chunk).unwrap())
                .unwrap();
        }
        let first = start.elapsed();
        receiver.interrupt(id).unwrap();
        drop(receiver);

        let start = Instant::now();
        let receiver = directory.store("receiver");
        assert_eq!(
            receiver.missing(id).unwrap(),
            vec![MissingFile {
                file: 0,
                next: stop
            }]
        );
        let resume = start.elapsed();
        let start = Instant::now();
        for chunk in stop..chunks {
            receiver
                .put(id, 0, chunk, &upload.read_chunk(0, chunk).unwrap())
                .unwrap();
        }
        let transfer = first + start.elapsed();
        let start = Instant::now();
        assert_eq!(receiver.verify(id).unwrap().completed_bytes, size);
        let verify = start.elapsed();
        let start = Instant::now();
        assert_eq!(
            io::copy(&mut receiver.read_verified(id, 0).unwrap(), &mut io::sink()).unwrap(),
            size
        );
        let read = start.elapsed();
        println!("size_mib={mib} prepare_ms={} write_ms={} resume_recheck_ms={} verify_ms={} verified_read_ms={} storage_mib_per_sec={:.2}",
            prepare.as_millis(), transfer.as_millis(), resume.as_millis(), verify.as_millis(), read.as_millis(), mib as f64 / transfer.as_secs_f64());
    }
}
