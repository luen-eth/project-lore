//! Reading a `git-receive-pack` request for the leak scan: the command
//! list (pkt-lines), then the packfile, every object inflated and scanned
//! with `leakscan::Scanner`. Trees give the file names, so a blob is named
//! by its path and the name rules apply to it. Deltas are resolved against
//! a base inside the pack; a delta whose base is not in the pack (a thin
//! pack) has only its inserted text scanned. Everything is bounded: the
//! size of one object, the inflated total and the delta depth; past them
//! the push is "too large to check". Pure and synchronous — the git proxy
//! runs it on the blocking pool.
//!
//! The protocol follows git's `Documentation/gitprotocol-pack.txt`
//! (`update-request`, `report-status`) and `gitformat-pack.txt` (the pack
//! format).

use std::{
    collections::{HashMap, HashSet},
    io::Read,
    sync::Arc,
};

use flate2::{Decompress, FlushDecompress, Status};
use sha2::{Digest, Sha256};

use crate::leakscan::{Finding, Scanner, dedup, name_rule};

/// The bounds of one check.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The request as it arrives (and once gunzipped, if it was).
    pub max_request: usize,
    /// The inflated size of one object kept for scanning.
    pub max_object: usize,
    /// Every byte inflated or rebuilt from a delta, across the pack.
    pub max_total: u64,
    /// The longest delta chain followed.
    pub max_depth: usize,
    /// Resolved objects kept in memory as delta bases.
    pub max_cache: usize,
}

/// The bounds the git proxy uses.
pub const LIMITS: Limits = Limits {
    max_request: 256 * 1024 * 1024,
    max_object: 32 * 1024 * 1024,
    max_total: 1024 * 1024 * 1024,
    max_depth: 250,
    max_cache: 128 * 1024 * 1024,
};

/// The command list of a push: the refs it updates and the capabilities
/// the client asked for.
#[derive(Debug, Clone, Default)]
pub struct Commands {
    pub refs: Vec<String>,
    pub caps: Vec<String>,
    /// 20 for SHA-1 repositories, 32 for SHA-256.
    pub hash_len: usize,
    /// True when every command deletes its ref (no pack follows).
    pub deletes_only: bool,
    /// Every command as `(old, new, ref)`, the ids in lowercase hex.
    pub updates: Vec<(String, String, String)>,
    /// Where the pack starts.
    pack_at: usize,
}

impl Commands {
    /// True when the client asked for this capability.
    pub fn has(&self, capability: &str) -> bool {
        self.caps.iter().any(|cap| cap == capability)
    }
}

/// What the check concluded.
#[derive(Debug)]
pub enum Verdict {
    /// Nothing found; forward the push.
    Clean,
    /// Secrets or private files.
    Found(Vec<Finding>),
    /// Too large to check in full, and nothing found in what could be
    /// checked.
    TooLarge,
    /// The request could not be read: the reason, without any content.
    Malformed(String),
}

/// The check of one request: its command list when it could be read (so
/// a refusal can be answered in the protocol), and the verdict.
#[derive(Debug)]
pub struct Checked {
    pub commands: Option<Commands>,
    pub verdict: Verdict,
}

/// Reads and scans one `git-receive-pack` request body. `encoding` is its
/// `Content-Encoding`.
pub fn check_request(
    body: &[u8],
    encoding: Option<&str>,
    scanner: &Scanner,
    limits: &Limits,
) -> Checked {
    let decoded: Vec<u8>;
    let body = match encoding.map(|value| value.trim().to_ascii_lowercase()) {
        None => body,
        Some(value) if value.is_empty() || value == "identity" => body,
        Some(value) if value == "gzip" || value == "x-gzip" => {
            let mut out = Vec::new();
            let read = flate2::read::GzDecoder::new(body)
                .take(limits.max_request as u64 + 1)
                .read_to_end(&mut out);
            if read.is_err() {
                return Checked {
                    commands: None,
                    verdict: Verdict::Malformed("the gzip request body is damaged".into()),
                };
            }
            if out.len() > limits.max_request {
                return Checked {
                    commands: read_commands(&out).ok(),
                    verdict: Verdict::TooLarge,
                };
            }
            decoded = out;
            &decoded
        }
        Some(_) => {
            return Checked {
                commands: None,
                verdict: Verdict::Malformed("the request uses an unknown content encoding".into()),
            };
        }
    };
    let commands = match read_commands(body) {
        Ok(commands) => commands,
        Err(reason) => {
            return Checked {
                commands: None,
                verdict: Verdict::Malformed(reason),
            };
        }
    };
    let mut findings = Vec::new();
    for name in &commands.refs {
        for hit in scanner.hits(name.as_bytes()) {
            findings.push(Finding {
                rule: hit.rule,
                location: "a ref name".into(),
            });
        }
    }
    let pack = &body[commands.pack_at..];
    let verdict = if pack.is_empty() {
        if findings.is_empty() {
            Verdict::Clean
        } else {
            Verdict::Found(findings)
        }
    } else {
        let mut reader = Pack::new(pack, commands.hash_len, scanner, limits);
        let outcome = reader.read();
        findings.extend(reader.findings());
        let findings = dedup(findings);
        if !findings.is_empty() {
            Verdict::Found(findings)
        } else {
            match outcome {
                Ok(()) if reader.too_large => Verdict::TooLarge,
                Ok(()) => Verdict::Clean,
                Err(Fail::TooLarge) => Verdict::TooLarge,
                Err(Fail::Malformed(reason)) => Verdict::Malformed(reason),
                Err(Fail::Missing) => {
                    Verdict::Malformed("a delta's base could not be found".into())
                }
            }
        }
    };
    Checked {
        commands: Some(commands),
        verdict,
    }
}

/// One pkt-line at `at`: its payload (`None` for a flush) and where the
/// next one starts.
fn pkt_at(body: &[u8], at: usize) -> Result<(Option<&[u8]>, usize), String> {
    let head = body
        .get(at..at + 4)
        .ok_or_else(|| "the command list ends early".to_string())?;
    let len = std::str::from_utf8(head)
        .ok()
        .and_then(|hex| usize::from_str_radix(hex, 16).ok())
        .ok_or_else(|| "the command list is not made of pkt-lines".to_string())?;
    if len == 0 {
        return Ok((None, at + 4));
    }
    if len < 4 || at + len > body.len() {
        return Err("a pkt-line of the command list is damaged".into());
    }
    Ok((Some(&body[at + 4..at + len]), at + len))
}

fn hex_id_len(text: &str) -> Option<usize> {
    (matches!(text.len(), 40 | 64) && text.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(text.len() / 2)
}

/// The command list: shallow lines, then `old new ref` lines (the first
/// carrying the capabilities after a NUL), a flush, and the push options
/// when the client sends them. Where the pack starts is kept.
pub fn read_commands(body: &[u8]) -> Result<Commands, String> {
    let mut commands = Commands {
        deletes_only: true,
        ..Commands::default()
    };
    let mut at = 0;
    loop {
        let (payload, next) = pkt_at(body, at)?;
        at = next;
        let Some(payload) = payload else {
            break;
        };
        let mut line = payload.strip_suffix(b"\n").unwrap_or(payload);
        if commands.refs.is_empty() && line.starts_with(b"push-cert") {
            return Err("a signed push (push certificate) cannot be checked".into());
        }
        if line.starts_with(b"shallow ") {
            continue;
        }
        if commands.refs.is_empty()
            && let Some(nul) = line.iter().position(|byte| *byte == 0)
        {
            commands.caps = String::from_utf8_lossy(&line[nul + 1..])
                .split(' ')
                .filter(|cap| !cap.is_empty())
                .map(str::to_string)
                .collect();
            line = &line[..nul];
        }
        let text = std::str::from_utf8(line).map_err(|_| "a command is not text".to_string())?;
        let mut parts = text.splitn(3, ' ');
        let (Some(old), Some(new), Some(name)) = (parts.next(), parts.next(), parts.next()) else {
            return Err("a command is not `old new ref`".into());
        };
        let (Some(old_len), Some(new_len)) = (hex_id_len(old), hex_id_len(new)) else {
            return Err("a command does not carry object ids".into());
        };
        if old_len != new_len
            || (commands.hash_len != 0 && commands.hash_len != new_len)
            || name.is_empty()
        {
            return Err("the commands do not agree on the object id length".into());
        }
        commands.hash_len = new_len;
        if new.bytes().any(|byte| byte != b'0') {
            commands.deletes_only = false;
        }
        commands.refs.push(name.to_string());
        commands.updates.push((
            old.to_ascii_lowercase(),
            new.to_ascii_lowercase(),
            name.to_string(),
        ));
    }
    if commands.has("push-options") {
        loop {
            let (payload, next) = pkt_at(body, at)?;
            at = next;
            if payload.is_none() {
                break;
            }
        }
    }
    if commands.hash_len == 0 {
        commands.hash_len = if commands.has("object-format=sha256") {
            32
        } else {
            20
        };
    }
    commands.pack_at = at;
    Ok(commands)
}

/// One tree entry as `push_view` hands it out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: String,
    pub name: String,
    /// The object id, lowercase hex.
    pub id: String,
}

/// What a push carries, for the checks of a built-in agent's push: its
/// commands, and the commits (tree and parents) and trees its pack holds,
/// by lowercase hex id.
#[derive(Debug, Default)]
pub struct PushView {
    pub commands: Commands,
    pub commits: HashMap<String, (String, Vec<String>)>,
    pub trees: HashMap<String, Vec<TreeEntry>>,
    /// False when part of the pack could not be read in full (a delta
    /// against an object the pack does not carry, or an object past the
    /// limits): an object it holds may then be missing here.
    pub complete: bool,
}

fn hex(id: &[u8]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Reads one `git-receive-pack` request body for its commands, commits
/// and trees (see `PushView`). `encoding` is its `Content-Encoding`.
pub fn push_view(body: &[u8], encoding: Option<&str>, limits: &Limits) -> Result<PushView, String> {
    let decoded: Vec<u8>;
    let body = match encoding.map(|value| value.trim().to_ascii_lowercase()) {
        None => body,
        Some(value) if value.is_empty() || value == "identity" => body,
        Some(value) if value == "gzip" || value == "x-gzip" => {
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(body)
                .take(limits.max_request as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|_| "the gzip request body is damaged".to_string())?;
            if out.len() > limits.max_request {
                return Err("the push is too large to check".into());
            }
            decoded = out;
            &decoded
        }
        Some(_) => return Err("the request uses an unknown content encoding".into()),
    };
    let commands = read_commands(body)?;
    let pack = &body[commands.pack_at..];
    let mut view = PushView {
        complete: true,
        ..PushView::default()
    };
    if !pack.is_empty() {
        let scanner = Scanner::default();
        let mut reader = Pack::new(pack, commands.hash_len, &scanner, limits);
        match reader.read() {
            Ok(()) => {}
            Err(Fail::Malformed(reason)) => return Err(reason),
            Err(_) => view.complete = false,
        }
        if reader.too_large || reader.unresolved > 0 {
            view.complete = false;
        }
        for (id, (tree, parents)) in &reader.commits {
            view.commits.insert(
                hex(id),
                (hex(tree), parents.iter().map(|p| hex(p)).collect()),
            );
        }
        for (id, entries) in &reader.trees {
            view.trees.insert(
                hex(id),
                entries
                    .iter()
                    .map(|entry| TreeEntry {
                        mode: entry.mode.clone(),
                        name: entry.name.clone(),
                        id: hex(&entry.id),
                    })
                    .collect(),
            );
        }
    }
    view.commands = commands;
    Ok(view)
}

/// One pkt-line holding `payload`.
fn pkt_line(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
    out.extend_from_slice(payload);
    out
}

/// The `git-receive-pack` result that refuses every ref of the push:
/// `unpack ok`, then `ng <ref> <reason>` for each, as `report-status`
/// describes; with side-band, `messages` go first on band 2 (git prints
/// them as `remote: …`) and the status on band 1. `None` when the client
/// asked for no report.
pub fn refusal_report(commands: &Commands, messages: &[String], reason: &str) -> Option<Vec<u8>> {
    if !commands.has("report-status") && !commands.has("report-status-v2") {
        return None;
    }
    let reason: String = reason
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut status = pkt_line(b"unpack ok\n");
    for name in &commands.refs {
        status.extend(pkt_line(format!("ng {name} {reason}\n").as_bytes()));
    }
    status.extend_from_slice(b"0000");
    let band = if commands.has("side-band-64k") {
        Some(65515)
    } else if commands.has("side-band") {
        Some(995)
    } else {
        None
    };
    let Some(max) = band else {
        return Some(status);
    };
    let mut out = Vec::new();
    for message in messages {
        let line = format!("{message}\n");
        for chunk in line.as_bytes().chunks(max) {
            let mut payload = vec![2u8];
            payload.extend_from_slice(chunk);
            out.extend(pkt_line(&payload));
        }
    }
    for chunk in status.chunks(max) {
        let mut payload = vec![1u8];
        payload.extend_from_slice(chunk);
        out.extend(pkt_line(&payload));
    }
    out.extend_from_slice(b"0000");
    Some(out)
}

// ---------- The pack ----------

const COMMIT: u8 = 1;
const TREE: u8 = 2;
const BLOB: u8 = 3;
const TAG: u8 = 4;
const OFS_DELTA: u8 = 6;
const REF_DELTA: u8 = 7;

/// Why reading stopped.
#[derive(Debug)]
enum Fail {
    Malformed(String),
    TooLarge,
    /// A delta base that is not in the pack (yet).
    Missing,
}

fn malformed(reason: &str) -> Fail {
    Fail::Malformed(reason.to_string())
}

enum Base {
    None,
    Offset(usize),
    Id(Vec<u8>),
}

/// An object's content once inflated and, for a delta, rebuilt.
struct Resolved {
    kind: u8,
    data: Vec<u8>,
    /// False when the object is larger than `max_object` and only its
    /// start is kept.
    complete: bool,
}

/// One tree entry.
struct Entry {
    mode: String,
    name: String,
    id: Vec<u8>,
}

/// A blob's hits, named once the trees are known.
struct BlobHits {
    id: Option<Vec<u8>>,
    hits: Vec<crate::leakscan::Hit>,
}

/// A commit's tree and parents.
type CommitLinks = (Vec<u8>, Vec<Vec<u8>>);

struct Pack<'a> {
    data: &'a [u8],
    hash_len: usize,
    scanner: &'a Scanner,
    limits: &'a Limits,
    spent: u64,
    too_large: bool,
    cache: HashMap<usize, Arc<Resolved>>,
    cached: usize,
    /// Object id → offset, for every object resolved in full.
    ids: HashMap<Vec<u8>, usize>,
    blob_ids: HashSet<Vec<u8>>,
    trees: HashMap<Vec<u8>, Vec<Entry>>,
    roots: Vec<Vec<u8>>,
    /// Commit id → its tree and parents.
    commits: HashMap<Vec<u8>, CommitLinks>,
    /// Deltas whose base the pack does not carry (a thin pack).
    unresolved: usize,
    blobs: Vec<BlobHits>,
    found: Vec<Finding>,
}

impl<'a> Pack<'a> {
    fn new(data: &'a [u8], hash_len: usize, scanner: &'a Scanner, limits: &'a Limits) -> Self {
        Self {
            data,
            hash_len,
            scanner,
            limits,
            spent: 0,
            too_large: false,
            cache: HashMap::new(),
            cached: 0,
            ids: HashMap::new(),
            blob_ids: HashSet::new(),
            trees: HashMap::new(),
            roots: Vec::new(),
            commits: HashMap::new(),
            unresolved: 0,
            blobs: Vec::new(),
            found: Vec::new(),
        }
    }

    /// Reads the whole pack. An error stops it; what was read is still in
    /// the findings.
    fn read(&mut self) -> Result<(), Fail> {
        let data = self.data;
        if data.len() < 12 || &data[..4] != b"PACK" {
            return Err(malformed("the push does not carry a packfile"));
        }
        let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if version != 2 && version != 3 {
            return Err(malformed("the packfile version is not 2 or 3"));
        }
        let count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        if count > data.len() {
            return Err(malformed(
                "the packfile claims more objects than it can hold",
            ));
        }
        let mut at = 12;
        let mut deferred: Vec<usize> = Vec::new();
        for _ in 0..count {
            let this = at;
            let (kind, size, start, base) = self.header(at)?;
            let (bytes, end, complete) = self.inflate(start, size)?;
            at = end;
            match base {
                Base::None => {
                    let resolved = Arc::new(Resolved {
                        kind,
                        data: bytes,
                        complete,
                    });
                    self.remember(this, &resolved);
                    self.process(this, &resolved)?;
                }
                _ if !complete => self.too_large = true,
                Base::Offset(base_at) => self.rebuild(this, base_at, &bytes)?,
                Base::Id(id) => match self.ids.get(&id).copied() {
                    Some(base_at) => self.rebuild(this, base_at, &bytes)?,
                    None => deferred.push(this),
                },
            }
        }
        if data.len() - at != self.hash_len {
            return Err(malformed(
                "the packfile does not end where its object count says",
            ));
        }
        // Deltas whose base came later in the pack, until nothing more
        // resolves; what is left is based on objects the pack does not
        // carry, and only its inserted text can be checked.
        loop {
            let mut progress = false;
            let mut waiting = Vec::new();
            for offset in deferred {
                match self.resolve(offset, 0) {
                    Ok(resolved) => {
                        self.process(offset, &resolved)?;
                        progress = true;
                    }
                    Err(Fail::Missing) => waiting.push(offset),
                    Err(Fail::TooLarge) => self.too_large = true,
                    Err(fail) => return Err(fail),
                }
            }
            deferred = waiting;
            if !progress || deferred.is_empty() {
                break;
            }
        }
        self.unresolved = deferred.len();
        for offset in deferred {
            let (_, size, start, _) = self.header(offset)?;
            let (delta, _, complete) = self.inflate(start, size)?;
            if !complete {
                self.too_large = true;
            }
            self.scan_inserts(offset, &delta)?;
        }
        Ok(())
    }

    /// A delta whose base is not in the pack: the text it inserts is all
    /// that can be checked.
    fn scan_inserts(&mut self, offset: usize, delta: &[u8]) -> Result<(), Fail> {
        for run in delta_inserts(delta)? {
            for hit in self.scanner.hits(&run) {
                self.found.push(Finding {
                    rule: hit.rule,
                    location: format!(
                        "an edit to a file already in the repository (a delta at pack offset \
                         {offset})"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Rebuilds the delta at `this` (already inflated as `delta`) on the
    /// object at `base_at`, and processes it.
    fn rebuild(&mut self, this: usize, base_at: usize, delta: &[u8]) -> Result<(), Fail> {
        let base = match self.resolve(base_at, 1) {
            Ok(base) => base,
            Err(Fail::TooLarge) => {
                self.too_large = true;
                return Ok(());
            }
            // A chain that ends outside the pack: only the inserted text
            // of this delta can be checked.
            Err(Fail::Missing) => return self.scan_inserts(this, delta),
            Err(fail) => return Err(fail),
        };
        if !base.complete {
            self.too_large = true;
            return Ok(());
        }
        let (data, complete) = self.apply_delta(&base.data, delta)?;
        let resolved = Arc::new(Resolved {
            kind: base.kind,
            data,
            complete,
        });
        self.remember(this, &resolved);
        self.process(this, &resolved)
    }

    /// The object at `at`, inflated and rebuilt, from the cache when it is
    /// there.
    fn resolve(&mut self, at: usize, depth: usize) -> Result<Arc<Resolved>, Fail> {
        if let Some(found) = self.cache.get(&at) {
            return Ok(found.clone());
        }
        if depth > self.limits.max_depth {
            return Err(Fail::TooLarge);
        }
        let (kind, size, start, base) = self.header(at)?;
        let (bytes, _, complete) = self.inflate(start, size)?;
        let base_at = match base {
            Base::None => {
                let resolved = Arc::new(Resolved {
                    kind,
                    data: bytes,
                    complete,
                });
                self.remember(at, &resolved);
                return Ok(resolved);
            }
            Base::Offset(base_at) => base_at,
            Base::Id(id) => *self.ids.get(&id).ok_or(Fail::Missing)?,
        };
        if !complete {
            return Err(Fail::TooLarge);
        }
        let base = self.resolve(base_at, depth + 1)?;
        if !base.complete {
            return Err(Fail::TooLarge);
        }
        let (data, complete) = self.apply_delta(&base.data, &bytes)?;
        let resolved = Arc::new(Resolved {
            kind: base.kind,
            data,
            complete,
        });
        self.remember(at, &resolved);
        Ok(resolved)
    }

    /// Keeps a resolved object as a possible delta base while the cache
    /// has room.
    fn remember(&mut self, at: usize, resolved: &Arc<Resolved>) {
        if resolved.complete && self.cached + resolved.data.len() <= self.limits.max_cache {
            self.cached += resolved.data.len();
            self.cache.insert(at, resolved.clone());
        }
    }

    /// Scans one resolved object and records what the trees and commits
    /// say about names.
    fn process(&mut self, at: usize, resolved: &Resolved) -> Result<(), Fail> {
        if !resolved.complete {
            self.too_large = true;
        }
        let id = resolved
            .complete
            .then(|| object_id(resolved.kind, &resolved.data, self.hash_len));
        if let Some(id) = &id {
            self.ids.insert(id.clone(), at);
        }
        let short = id.as_deref().map(short_id).unwrap_or_else(|| "?".into());
        match resolved.kind {
            BLOB => {
                let hits = self.scanner.hits(&resolved.data);
                if let Some(id) = &id {
                    self.blob_ids.insert(id.clone());
                }
                if !hits.is_empty() {
                    self.blobs.push(BlobHits { id, hits });
                }
            }
            TREE => {
                let Some(id) = id else {
                    return Ok(());
                };
                let entries = parse_tree(&resolved.data, self.hash_len)?;
                self.trees.insert(id, entries);
            }
            COMMIT | TAG => {
                let what = if resolved.kind == COMMIT {
                    "commit"
                } else {
                    "tag"
                };
                self.found.extend(
                    self.scanner
                        .scan_content(&resolved.data, &format!("{what} {short}")),
                );
                if resolved.kind == COMMIT
                    && let Some(root) = resolved
                        .data
                        .strip_prefix(b"tree ")
                        .and_then(|rest| rest.split(|byte| *byte == b'\n').next())
                        .and_then(decode_hex)
                {
                    self.roots.push(root.clone());
                    if let Some(id) = &id {
                        let parents = resolved
                            .data
                            .split(|byte| *byte == b'\n')
                            .take_while(|line| !line.is_empty())
                            .filter_map(|line| line.strip_prefix(b"parent "))
                            .filter_map(decode_hex)
                            .collect();
                        self.commits.insert(id.clone(), (root, parents));
                    }
                }
            }
            _ => return Err(malformed("the packfile holds an unknown object type")),
        }
        Ok(())
    }

    /// Every finding: names and contents of the blobs (named by their
    /// paths), commit and tag messages, thin deltas.
    fn findings(&self) -> Vec<Finding> {
        // Full paths, walking from each commit's root tree through the
        // trees the pack carries; plain entry names for the rest.
        let mut paths: HashMap<&[u8], String> = HashMap::new();
        let mut visited: HashSet<&[u8]> = HashSet::new();
        for root in &self.roots {
            self.walk(root, "", 0, &mut paths, &mut visited);
        }
        let mut names: HashMap<&[u8], &str> = HashMap::new();
        for entries in self.trees.values() {
            for entry in entries {
                names.entry(entry.id.as_slice()).or_insert(&entry.name);
            }
        }
        let path_of = |id: &[u8]| -> Option<String> {
            paths
                .get(id)
                .cloned()
                .or_else(|| names.get(id).map(|name| name.to_string()))
        };

        let mut out = Vec::new();
        for entries in self.trees.values() {
            for entry in entries {
                if entry.mode == "40000" || entry.mode == "160000" {
                    continue;
                }
                if !self.blob_ids.contains(&entry.id) {
                    continue;
                }
                let path = path_of(&entry.id).unwrap_or_else(|| entry.name.clone());
                if let Some(rule) = name_rule(&path).or_else(|| name_rule(&entry.name)) {
                    out.push(Finding {
                        rule,
                        location: self.scanner.label(&path),
                    });
                }
            }
        }
        for blob in &self.blobs {
            let label = match blob.id.as_deref().and_then(path_of) {
                Some(path) => self.scanner.label(&path),
                None => format!(
                    "a new file (object {})",
                    blob.id
                        .as_deref()
                        .map(short_id)
                        .unwrap_or_else(|| "?".into())
                ),
            };
            for hit in &blob.hits {
                out.push(Finding {
                    rule: hit.rule,
                    location: format!("{label}, line {}", hit.line),
                });
            }
        }
        out.extend(self.found.iter().cloned());
        // A stable order: by location, so the same push reads the same.
        out.sort_by(|a, b| a.location.cmp(&b.location).then(a.rule.cmp(b.rule)));
        dedup(out)
    }

    fn walk<'s>(
        &'s self,
        tree: &[u8],
        prefix: &str,
        depth: usize,
        paths: &mut HashMap<&'s [u8], String>,
        visited: &mut HashSet<&'s [u8]>,
    ) {
        if depth > 64 {
            return;
        }
        let Some((key, entries)) = self.trees.get_key_value(tree) else {
            return;
        };
        if !visited.insert(key.as_slice()) {
            return;
        }
        for entry in entries {
            let path = if prefix.is_empty() {
                entry.name.clone()
            } else {
                format!("{prefix}/{}", entry.name)
            };
            if entry.mode == "40000" {
                self.walk(&entry.id, &path, depth + 1, paths, visited);
            } else {
                paths.entry(entry.id.as_slice()).or_insert(path);
            }
        }
    }

    /// Counts inflated or rebuilt bytes against the pack's budget.
    fn spend(&mut self, bytes: usize) -> Result<(), Fail> {
        self.spent += bytes as u64;
        if self.spent > self.limits.max_total {
            self.too_large = true;
            return Err(Fail::TooLarge);
        }
        Ok(())
    }

    fn byte(&self, at: usize) -> Result<u8, Fail> {
        self.data
            .get(at)
            .copied()
            .ok_or_else(|| malformed("the packfile ends inside an object header"))
    }

    /// An object header at `at`: type, inflated size, where the zlib data
    /// starts, and the delta base.
    fn header(&self, at: usize) -> Result<(u8, usize, usize, Base), Fail> {
        let mut pos = at;
        let mut byte = self.byte(pos)?;
        pos += 1;
        let kind = (byte >> 4) & 7;
        let mut size = (byte & 15) as usize;
        let mut shift = 4;
        while byte & 0x80 != 0 {
            byte = self.byte(pos)?;
            pos += 1;
            if shift > 56 {
                return Err(malformed("an object header is damaged"));
            }
            size |= ((byte & 0x7f) as usize) << shift;
            shift += 7;
        }
        let base = match kind {
            COMMIT | TREE | BLOB | TAG => Base::None,
            OFS_DELTA => {
                let mut byte = self.byte(pos)?;
                pos += 1;
                let mut distance = (byte & 0x7f) as usize;
                while byte & 0x80 != 0 {
                    byte = self.byte(pos)?;
                    pos += 1;
                    distance = distance
                        .checked_add(1)
                        .and_then(|value| value.checked_mul(128))
                        .map(|value| value + (byte & 0x7f) as usize)
                        .ok_or_else(|| malformed("a delta offset is damaged"))?;
                }
                if distance == 0 || distance > at {
                    return Err(malformed("a delta points outside the packfile"));
                }
                Base::Offset(at - distance)
            }
            REF_DELTA => {
                let id = self
                    .data
                    .get(pos..pos + self.hash_len)
                    .ok_or_else(|| malformed("the packfile ends inside an object header"))?
                    .to_vec();
                pos += self.hash_len;
                Base::Id(id)
            }
            _ => return Err(malformed("the packfile holds an unknown object type")),
        };
        Ok((kind, size, pos, base))
    }

    /// Inflates the zlib stream at `at`, which must give `declared` bytes.
    /// At most `max_object` bytes are kept; the whole stream is read to
    /// find where it ends. Returns the bytes, the offset after the stream
    /// and whether the bytes are complete.
    fn inflate(&mut self, at: usize, declared: usize) -> Result<(Vec<u8>, usize, bool), Fail> {
        let keep = declared.min(self.limits.max_object);
        let mut out = Vec::with_capacity(keep.min(1024 * 1024));
        let mut inflater = Decompress::new(true);
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let read = inflater.total_in() as usize;
            let written = inflater.total_out();
            let input = self
                .data
                .get(at + read..)
                .ok_or_else(|| malformed("an object's data ends early"))?;
            let status = inflater
                .decompress(input, &mut chunk, FlushDecompress::None)
                .map_err(|_| malformed("an object's data is not valid zlib"))?;
            let produced = (inflater.total_out() - written) as usize;
            self.spend(produced)?;
            let room = keep.saturating_sub(out.len());
            out.extend_from_slice(&chunk[..produced.min(room)]);
            if inflater.total_out() as usize > declared {
                return Err(malformed("an object is larger than its header says"));
            }
            match status {
                Status::StreamEnd => break,
                _ if produced == 0 && inflater.total_in() as usize == read => {
                    return Err(malformed("an object's data ends early"));
                }
                _ => {}
            }
        }
        if inflater.total_out() as usize != declared {
            return Err(malformed("an object's size does not match its header"));
        }
        Ok((
            out,
            at + inflater.total_in() as usize,
            declared <= self.limits.max_object,
        ))
    }

    /// The object a delta rebuilds from `base`; at most `max_object` bytes
    /// are kept.
    fn apply_delta(&mut self, base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, bool), Fail> {
        let (source, mut pos) = delta_size(delta, 0)?;
        let (target, next) = delta_size(delta, pos)?;
        pos = next;
        if source != base.len() {
            return Err(malformed("a delta does not fit its base"));
        }
        self.spend(target)?;
        let limit = self.limits.max_object;
        let mut out = Vec::with_capacity(target.min(limit));
        let mut total = 0usize;
        while pos < delta.len() {
            let op = delta[pos];
            pos += 1;
            let piece: &[u8] = if op & 0x80 != 0 {
                let mut offset = 0usize;
                let mut size = 0usize;
                for bit in 0..4 {
                    if op & (1 << bit) != 0 {
                        offset |= (*delta.get(pos).ok_or_else(|| malformed(DAMAGED_DELTA))?
                            as usize)
                            << (8 * bit);
                        pos += 1;
                    }
                }
                for bit in 0..3 {
                    if op & (0x10 << bit) != 0 {
                        size |= (*delta.get(pos).ok_or_else(|| malformed(DAMAGED_DELTA))? as usize)
                            << (8 * bit);
                        pos += 1;
                    }
                }
                if size == 0 {
                    size = 0x10000;
                }
                base.get(
                    offset
                        ..offset
                            .checked_add(size)
                            .ok_or_else(|| malformed(DAMAGED_DELTA))?,
                )
                .ok_or_else(|| malformed(DAMAGED_DELTA))?
            } else if op != 0 {
                let piece = delta
                    .get(pos..pos + op as usize)
                    .ok_or_else(|| malformed(DAMAGED_DELTA))?;
                pos += op as usize;
                piece
            } else {
                return Err(malformed(DAMAGED_DELTA));
            };
            total += piece.len();
            if total > target {
                return Err(malformed(DAMAGED_DELTA));
            }
            let room = limit.saturating_sub(out.len());
            out.extend_from_slice(&piece[..piece.len().min(room)]);
        }
        if total != target {
            return Err(malformed(DAMAGED_DELTA));
        }
        Ok((out, target <= limit))
    }
}

const DAMAGED_DELTA: &str = "a delta is damaged";

/// A delta's size field: little-endian groups of seven bits.
fn delta_size(delta: &[u8], mut pos: usize) -> Result<(usize, usize), Fail> {
    let mut value = 0usize;
    let mut shift = 0;
    loop {
        let byte = *delta.get(pos).ok_or_else(|| malformed(DAMAGED_DELTA))?;
        pos += 1;
        if shift > 56 {
            return Err(malformed(DAMAGED_DELTA));
        }
        value |= ((byte & 0x7f) as usize) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((value, pos));
        }
    }
}

/// The text a delta inserts, as runs of consecutive inserts (git inserts
/// at most 127 bytes per instruction, so a line spans several).
fn delta_inserts(delta: &[u8]) -> Result<Vec<Vec<u8>>, Fail> {
    let (_, pos) = delta_size(delta, 0)?;
    let (_, mut pos) = delta_size(delta, pos)?;
    let mut runs: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    while pos < delta.len() {
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            pos += (op & 0x7f).count_ones() as usize;
            if !current.is_empty() {
                runs.push(std::mem::take(&mut current));
            }
        } else if op != 0 {
            let piece = delta
                .get(pos..pos + op as usize)
                .ok_or_else(|| malformed(DAMAGED_DELTA))?;
            current.extend_from_slice(piece);
            pos += op as usize;
        } else {
            return Err(malformed(DAMAGED_DELTA));
        }
    }
    if !current.is_empty() {
        runs.push(current);
    }
    Ok(runs)
}

/// A tree's entries: `<mode> <name>\0<id>` each.
fn parse_tree(data: &[u8], hash_len: usize) -> Result<Vec<Entry>, Fail> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let space = data[pos..]
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| malformed("a tree is damaged"))?;
        let mode = String::from_utf8_lossy(&data[pos..pos + space]).into_owned();
        pos += space + 1;
        let nul = data[pos..]
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| malformed("a tree is damaged"))?;
        let name = String::from_utf8_lossy(&data[pos..pos + nul]).into_owned();
        pos += nul + 1;
        let id = data
            .get(pos..pos + hash_len)
            .ok_or_else(|| malformed("a tree is damaged"))?
            .to_vec();
        pos += hash_len;
        entries.push(Entry { mode, name, id });
    }
    Ok(entries)
}

fn decode_hex(hex: &[u8]) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    hex.chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
        })
        .collect()
}

fn short_id(id: &[u8]) -> String {
    id.iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// An object's id: SHA-1 (or SHA-256) of `<type> <size>\0<content>`.
pub fn object_id(kind: u8, data: &[u8], hash_len: usize) -> Vec<u8> {
    let name = match kind {
        COMMIT => "commit",
        TREE => "tree",
        BLOB => "blob",
        _ => "tag",
    };
    let header = format!("{name} {}\0", data.len());
    if hash_len == 32 {
        let mut hasher = Sha256::new();
        hasher.update(header.as_bytes());
        hasher.update(data);
        hasher.finalize().to_vec()
    } else {
        let mut hasher = Sha1::default();
        hasher.update(header.as_bytes());
        hasher.update(data);
        hasher.finish().to_vec()
    }
}

/// SHA-1, as git names objects with it. Only object ids are computed
/// with it; it secures nothing here.
struct Sha1 {
    state: [u32; 5],
    block: Vec<u8>,
    length: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xEFCD_AB89,
                0x98BA_DCFE,
                0x1032_5476,
                0xC3D2_E1F0,
            ],
            block: Vec::with_capacity(64),
            length: 0,
        }
    }
}

impl Sha1 {
    fn update(&mut self, mut data: &[u8]) {
        self.length += data.len() as u64;
        if !self.block.is_empty() {
            let take = (64 - self.block.len()).min(data.len());
            self.block.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.block.len() == 64 {
                let block: [u8; 64] = self.block[..].try_into().expect("64 bytes");
                self.compress(&block);
                self.block.clear();
            }
        }
        while data.len() >= 64 {
            let block: [u8; 64] = data[..64].try_into().expect("64 bytes");
            self.compress(&block);
            data = &data[64..];
        }
        self.block.extend_from_slice(data);
    }

    fn finish(mut self) -> [u8; 20] {
        let bits = self.length.wrapping_mul(8);
        let mut tail = std::mem::take(&mut self.block);
        tail.push(0x80);
        while tail.len() % 64 != 56 {
            tail.push(0);
        }
        tail.extend_from_slice(&bits.to_be_bytes());
        for block in tail.chunks(64) {
            let block: [u8; 64] = block.try_into().expect("64 bytes");
            self.compress(&block);
        }
        let mut out = [0u8; 20];
        for (index, word) in self.state.iter().enumerate() {
            out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for (index, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                block[index * 4],
                block[index * 4 + 1],
                block[index * 4 + 2],
                block[index * 4 + 3],
            ]);
        }
        for index in 16..80 {
            w[index] = (w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (index, word) in w.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        for (slot, value) in self.state.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{Compression, write::ZlibEncoder};

    use super::*;

    const ZERO: &str = "0000000000000000000000000000000000000000";

    /// A GitHub-shaped token built at run time, so this file holds none.
    fn token() -> String {
        ["gh", "p_", "Zq8Lm2Xv9Rt4Wp6Ky3Nb7Hc5Jd1Fg0Ts8QeA"].concat()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn hex(id: &[u8]) -> String {
        id.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// An object header: type and size, seven bits at a time.
    fn header(kind: u8, size: usize) -> Vec<u8> {
        let mut size = size;
        let mut first = (kind << 4) | (size & 15) as u8;
        size >>= 4;
        let mut out = Vec::new();
        if size > 0 {
            first |= 0x80;
        }
        out.push(first);
        while size > 0 {
            let mut byte = (size & 0x7f) as u8;
            size >>= 7;
            if size > 0 {
                byte |= 0x80;
            }
            out.push(byte);
        }
        out
    }

    /// git's encoding of an `OFS_DELTA` distance.
    fn distance(mut value: usize) -> Vec<u8> {
        let mut bytes = vec![(value & 0x7f) as u8];
        value >>= 7;
        while value > 0 {
            value -= 1;
            bytes.push(0x80 | (value & 0x7f) as u8);
            value >>= 7;
        }
        bytes.reverse();
        bytes
    }

    fn varint(mut value: usize) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    enum Op<'a> {
        Copy(usize, usize),
        Insert(&'a [u8]),
    }

    fn delta(source: usize, ops: &[Op]) -> Vec<u8> {
        let target: usize = ops
            .iter()
            .map(|op| match op {
                Op::Copy(_, len) => *len,
                Op::Insert(bytes) => bytes.len(),
            })
            .sum();
        let mut out = varint(source);
        out.extend(varint(target));
        for op in ops {
            match op {
                Op::Copy(offset, len) => {
                    out.push(0x80 | 0x0f | 0x30);
                    out.extend_from_slice(&(*offset as u32).to_le_bytes());
                    out.extend_from_slice(&(*len as u32).to_le_bytes()[..2]);
                }
                Op::Insert(bytes) => {
                    for chunk in bytes.chunks(127) {
                        out.push(chunk.len() as u8);
                        out.extend_from_slice(chunk);
                    }
                }
            }
        }
        out
    }

    /// Builds a version 2 pack, object by object.
    struct Builder {
        bytes: Vec<u8>,
        count: u32,
    }

    impl Builder {
        fn new() -> Self {
            let mut bytes = b"PACK".to_vec();
            bytes.extend_from_slice(&2u32.to_be_bytes());
            bytes.extend_from_slice(&0u32.to_be_bytes());
            Self { bytes, count: 0 }
        }

        fn object(&mut self, kind: u8, data: &[u8]) -> (usize, Vec<u8>) {
            let at = self.bytes.len();
            self.bytes.extend(header(kind, data.len()));
            self.bytes.extend(zlib(data));
            self.count += 1;
            (at, object_id(kind, data, 20))
        }

        fn ofs_delta(&mut self, base: usize, delta: &[u8]) -> usize {
            let at = self.bytes.len();
            self.bytes.extend(header(OFS_DELTA, delta.len()));
            self.bytes.extend(distance(at - base));
            self.bytes.extend(zlib(delta));
            self.count += 1;
            at
        }

        fn ref_delta(&mut self, base: &[u8], delta: &[u8]) -> usize {
            let at = self.bytes.len();
            self.bytes.extend(header(REF_DELTA, delta.len()));
            self.bytes.extend_from_slice(base);
            self.bytes.extend(zlib(delta));
            self.count += 1;
            at
        }

        fn finish(mut self) -> Vec<u8> {
            self.bytes[8..12].copy_from_slice(&self.count.to_be_bytes());
            let mut hasher = Sha1::default();
            hasher.update(&self.bytes);
            let trailer = hasher.finish();
            self.bytes.extend_from_slice(&trailer);
            self.bytes
        }
    }

    fn tree(entries: &[(&str, &str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (mode, name, id) in entries {
            out.extend_from_slice(format!("{mode} {name}\0").as_bytes());
            out.extend_from_slice(id);
        }
        out
    }

    fn commit(tree: &[u8], message: &str) -> Vec<u8> {
        format!(
            "tree {}\nauthor A <a@example.invalid> 1700000000 +0000\ncommitter A \
             <a@example.invalid> 1700000000 +0000\n\n{message}\n",
            hex(tree)
        )
        .into_bytes()
    }

    /// The request git sends: one command with the usual capabilities,
    /// a flush, the pack.
    fn request(pack: &[u8]) -> Vec<u8> {
        let line = format!(
            "{ZERO} {} refs/heads/main\0 report-status side-band-64k quiet object-format=sha1 \
             agent=git/2.47\n",
            "1".repeat(40)
        );
        let mut out = pkt_line(line.as_bytes());
        out.extend_from_slice(b"0000");
        out.extend_from_slice(pack);
        out
    }

    fn check(body: &[u8]) -> Checked {
        check_request(body, None, &Scanner::default(), &LIMITS)
    }

    fn found(checked: &Checked) -> Vec<String> {
        match &checked.verdict {
            Verdict::Found(findings) => findings.iter().map(Finding::to_string).collect(),
            other => panic!("expected findings, got {other:?}"),
        }
    }

    /// A commit, a tree with `config/app.py` in a subtree and `README.md`,
    /// and the blobs; `app` is the content of `config/app.py`.
    fn project(app: &[u8]) -> Vec<u8> {
        let mut pack = Builder::new();
        let (_, readme) = pack.object(BLOB, b"# Shop\n");
        let (_, app) = pack.object(BLOB, app);
        let (_, config) = pack.object(TREE, &tree(&[("100644", "app.py", &app)]));
        let (_, root) = pack.object(
            TREE,
            &tree(&[
                ("100644", "README.md", &readme),
                ("40000", "config", &config),
            ]),
        );
        pack.object(COMMIT, &commit(&root, "Add the shop"));
        request(&pack.finish())
    }

    #[test]
    fn object_ids_are_git_s() {
        let sha1 = |data: &[u8]| {
            let mut hasher = Sha1::default();
            hasher.update(data);
            hex(&hasher.finish())
        };
        assert_eq!(sha1(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha1(b"The quick brown fox jumps over the lazy dog"),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
        // Across block boundaries, fed in pieces.
        let long = vec![b'a'; 1_000_000];
        let mut hasher = Sha1::default();
        for piece in long.chunks(777) {
            hasher.update(piece);
        }
        assert_eq!(
            hex(&hasher.finish()),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
        // The empty blob, as `git hash-object` names it.
        assert_eq!(
            hex(&object_id(BLOB, b"", 20)),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
    }

    #[test]
    fn a_clean_push_is_clean() {
        let checked = check(&project(b"print('hello')\n"));
        assert!(matches!(checked.verdict, Verdict::Clean), "{checked:?}");
        let commands = checked.commands.unwrap();
        assert_eq!(commands.refs, vec!["refs/heads/main"]);
        assert!(commands.has("side-band-64k") && commands.has("report-status"));
        assert_eq!(commands.hash_len, 20);
    }

    #[test]
    fn a_secret_in_a_blob_is_named_by_its_path() {
        let app = format!("import os\nVALUE = '{}'\n", token());
        let checked = check(&project(app.as_bytes()));
        assert_eq!(
            found(&checked),
            vec!["github-token in `config/app.py`, line 2"]
        );
    }

    #[test]
    fn private_file_names_count_only_when_their_content_is_pushed() {
        let mut pack = Builder::new();
        let (_, env) = pack.object(BLOB, b"A=1\n");
        // `id_rsa` is listed, but its blob is not in the push: it is
        // already in the repository, and judged there.
        let old = object_id(BLOB, b"old key", 20);
        let (_, root) = pack.object(
            TREE,
            &tree(&[("100644", ".env", &env), ("100600", "id_rsa", &old)]),
        );
        pack.object(COMMIT, &commit(&root, "settings"));
        let checked = check(&request(&pack.finish()));
        assert_eq!(found(&checked), vec!["env-file in `.env`"]);
    }

    #[test]
    fn a_secret_in_a_commit_message_is_found() {
        let mut pack = Builder::new();
        let (_, root) = pack.object(TREE, b"");
        let (_, id) = pack.object(COMMIT, &commit(&root, &format!("oops {}", token())));
        let checked = check(&request(&pack.finish()));
        assert_eq!(
            found(&checked),
            vec![format!("github-token in commit {}, line 5", short_id(&id))]
        );
    }

    #[test]
    fn deltas_are_rebuilt_on_their_base_in_the_pack() {
        let base: Vec<u8> = (0..60)
            .map(|line| format!("line {line} of an ordinary file\n"))
            .collect::<String>()
            .into_bytes();
        let secret = format!("VALUE = '{}'\n", token());
        let mut target = base.clone();
        target.extend_from_slice(secret.as_bytes());

        // OFS_DELTA: the edited file, rebuilt and named by its tree.
        let mut pack = Builder::new();
        let (base_at, _) = pack.object(BLOB, &base);
        pack.ofs_delta(
            base_at,
            &delta(
                base.len(),
                &[Op::Copy(0, base.len()), Op::Insert(secret.as_bytes())],
            ),
        );
        let new_id = object_id(BLOB, &target, 20);
        let (_, root) = pack.object(TREE, &tree(&[("100644", "notes.txt", &new_id)]));
        pack.object(COMMIT, &commit(&root, "edit"));
        let checked = check(&request(&pack.finish()));
        assert_eq!(
            found(&checked),
            vec!["github-token in `notes.txt`, line 61"]
        );

        // REF_DELTA whose base comes later in the pack.
        let mut pack = Builder::new();
        let base_id = object_id(BLOB, &base, 20);
        pack.ref_delta(
            &base_id,
            &delta(
                base.len(),
                &[Op::Copy(0, 100), Op::Insert(secret.as_bytes())],
            ),
        );
        pack.object(BLOB, &base);
        let checked = check(&request(&pack.finish()));
        assert_eq!(found(&checked).len(), 1, "{checked:?}");
    }

    #[test]
    fn a_thin_delta_has_its_inserted_text_checked() {
        let base_id = object_id(BLOB, b"what the repository already has", 20);
        let secret = format!("value: '{}'\nmore text\n", token());
        let mut pack = Builder::new();
        let at = pack.ref_delta(
            &base_id,
            &delta(
                31,
                &[
                    Op::Copy(0, 10),
                    Op::Insert(secret.as_bytes()),
                    Op::Copy(10, 21),
                ],
            ),
        );
        let checked = check(&request(&pack.finish()));
        assert_eq!(
            found(&checked),
            vec![format!(
                "github-token in an edit to a file already in the repository (a delta at pack \
                 offset {at})"
            )]
        );
        // A clean thin delta passes.
        let mut pack = Builder::new();
        pack.ref_delta(
            &base_id,
            &delta(31, &[Op::Copy(0, 31), Op::Insert(b"one more line\n")]),
        );
        let checked = check(&request(&pack.finish()));
        assert!(matches!(checked.verdict, Verdict::Clean), "{checked:?}");
    }

    #[test]
    fn broken_requests_are_malformed() {
        let good = project(b"x = 1\n");
        let pack_at = read_commands(&good).unwrap().pack_at;
        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("no pkt-lines", b"hello world".to_vec()),
            ("cut command list", good[..20].to_vec()),
            ("not a pack", {
                let mut body = good[..pack_at].to_vec();
                body.extend_from_slice(b"JUNKJUNKJUNKJUNK");
                body
            }),
            ("cut pack", good[..good.len() - 40].to_vec()),
            ("extra bytes", {
                let mut body = good.clone();
                body.extend_from_slice(b"extra");
                body
            }),
        ];
        let mut version = good.clone();
        version[pack_at + 7] = 9;
        cases.push(("bad version", version));
        let mut damaged = good.clone();
        let middle = pack_at + 12 + 4;
        damaged[middle] ^= 0xff;
        damaged[middle + 1] ^= 0xff;
        cases.push(("damaged zlib", damaged));
        let signed = {
            let mut body = pkt_line(b"push-cert\0report-status\n");
            body.extend_from_slice(b"0000");
            body
        };
        cases.push(("push certificate", signed));
        for (name, body) in cases {
            let checked = check(&body);
            assert!(
                matches!(checked.verdict, Verdict::Malformed(_)),
                "{name}: {checked:?}"
            );
        }
    }

    #[test]
    fn deletes_need_no_pack() {
        let line = format!("{} {ZERO} refs/heads/old\0report-status\n", "2".repeat(40));
        let mut body = pkt_line(line.as_bytes());
        body.extend_from_slice(b"0000");
        let checked = check(&body);
        assert!(matches!(checked.verdict, Verdict::Clean));
        assert!(checked.commands.unwrap().deletes_only);
    }

    #[test]
    fn past_the_limits_a_push_is_too_large() {
        let body = project(&vec![b'a'; 5000]);
        let small_object = Limits {
            max_object: 1000,
            ..LIMITS
        };
        let checked = check_request(&body, None, &Scanner::default(), &small_object);
        assert!(matches!(checked.verdict, Verdict::TooLarge), "{checked:?}");
        let small_total = Limits {
            max_total: 2000,
            ..LIMITS
        };
        let checked = check_request(&body, None, &Scanner::default(), &small_total);
        assert!(matches!(checked.verdict, Verdict::TooLarge), "{checked:?}");
        // What was read before the limit still counts.
        let app = format!("{}\nVALUE = '{}'\n", "a".repeat(5000), token());
        let checked = check_request(
            &project(app.as_bytes()),
            None,
            &Scanner::default(),
            &Limits {
                max_object: 6000,
                max_total: 6000,
                ..LIMITS
            },
        );
        assert!(
            matches!(&checked.verdict, Verdict::Found(findings) if findings.len() == 1),
            "{checked:?}"
        );
    }

    #[test]
    fn a_gzip_request_is_read_too() {
        let app = format!("VALUE = '{}'\n", token());
        let body = project(app.as_bytes());
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&body).unwrap();
        let gzipped = encoder.finish().unwrap();
        let checked = check_request(&gzipped, Some("gzip"), &Scanner::default(), &LIMITS);
        assert_eq!(found(&checked).len(), 1);
        let checked = check_request(&body, Some("br"), &Scanner::default(), &LIMITS);
        assert!(matches!(checked.verdict, Verdict::Malformed(_)));
    }

    #[test]
    fn the_refusal_speaks_report_status() {
        let commands = read_commands(&project(b"x")).unwrap();
        let report = refusal_report(&commands, &["first line".into()], "lore: no").unwrap();
        let mut status = pkt_line(b"unpack ok\n");
        status.extend(pkt_line(b"ng refs/heads/main lore: no\n"));
        status.extend_from_slice(b"0000");
        let mut expected = pkt_line(b"\x02first line\n");
        let mut band = vec![1u8];
        band.extend_from_slice(&status);
        expected.extend(pkt_line(&band));
        expected.extend_from_slice(b"0000");
        assert_eq!(report, expected);

        // Without side-band, the status alone; without report-status,
        // nothing git would read.
        let mut plain = commands.clone();
        plain.caps = vec!["report-status".into()];
        assert_eq!(
            refusal_report(&plain, &["x".into()], "lore: no").unwrap(),
            status
        );
        plain.caps.clear();
        assert!(refusal_report(&plain, &[], "lore: no").is_none());
    }
}
