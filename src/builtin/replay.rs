//! The recent screen of a terminal session, kept in lore's memory so a
//! page that attaches to a running session is not blank.
//!
//! What a PTY printed is kept, in chunks, up to [`REPLAY_BYTES`]: the
//! oldest chunks go first. It lives only here, in memory: it is never
//! written to the database, to a file or to the log, and it goes when the
//! session ends.
//!
//! The bytes pass through a small VT parser on their way in, which does
//! three things:
//! - it leaves out the *queries* a program printed (device attributes,
//!   cursor position and status reports, mode and setting requests,
//!   capability requests, colour and clipboard queries, window reports).
//!   A terminal answers those by typing the answer, so replaying them to a
//!   page would type stale answers into the live program;
//! - it notes where in each chunk a replay may start: outside any escape
//!   sequence and at a whole character. A short sequence is held until it
//!   is complete and kept whole in one chunk; only a sequence longer than
//!   [`HOLD_BYTES`] (a long title or clipboard string, never a query)
//!   passes through as it comes, and a chunk that is entirely inside one
//!   is never where a replay starts;
//! - it follows the terminal modes a program switches with `CSI ? n h/l`
//!   (the alternate screen, the cursor keys, the cursor's visibility,
//!   mouse reporting, focus events, bracketed paste), with `ESC [` and
//!   the 8-bit `CSI` alike, so a replay that starts after a switch still
//!   sets them. Without that a full-screen program would replay on the
//!   wrong screen and the keys and the mouse would send what it does not
//!   expect.
//!
//! The replay only has to be close: lore resizes the PTY right after it,
//! which has the program draw its whole screen again.

use std::collections::VecDeque;

/// Most bytes kept per session.
pub const REPLAY_BYTES: usize = 512 * 1024;

/// Largest piece of input taken in one chunk: bigger writes are split, so
/// dropping the oldest chunk never drops much more than needed.
const CHUNK_BYTES: usize = 16 * 1024;

/// Longest sequence held whole; a longer one is not a query and passes
/// through as it comes.
const HOLD_BYTES: usize = 512;

/// The private modes followed, with whether each is on in a fresh
/// terminal. The three alternate-screen modes are one flag (`ALT`).
const MODES: [(u16, bool); 11] = [
    (1, false),    // application cursor keys
    (25, true),    // the cursor is shown
    (1000, false), // mouse: clicks
    (1002, false), // mouse: drags
    (1003, false), // mouse: any motion
    (1004, false), // focus in and out
    (1005, false), // mouse: UTF-8 coordinates
    (1006, false), // mouse: SGR coordinates
    (1015, false), // mouse: urxvt coordinates
    (2004, false), // bracketed paste
    (1049, false), // the alternate screen (also 47 and 1047)
];
const ALT: usize = MODES.len() - 1;

/// The followed modes, one bit each in the order of [`MODES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Modes(u16);

impl Default for Modes {
    fn default() -> Self {
        let mut bits = 0;
        for (index, (_, on)) in MODES.iter().enumerate() {
            if *on {
                bits |= 1 << index;
            }
        }
        Modes(bits)
    }
}

impl Modes {
    fn set(&mut self, mode: u16, on: bool) {
        let index = match mode {
            47 | 1047 | 1049 => ALT,
            _ => match MODES.iter().position(|(m, _)| *m == mode) {
                Some(index) => index,
                None => return,
            },
        };
        if on {
            self.0 |= 1 << index;
        } else {
            self.0 &= !(1 << index);
        }
    }

    /// What sets these modes in a terminal that was just reset.
    fn prefix(self) -> Vec<u8> {
        let fresh = Modes::default();
        let mut out = Vec::new();
        // The screen first: what follows is drawn on it.
        let order = std::iter::once(ALT).chain(0..ALT);
        for index in order {
            let on = self.0 & (1 << index) != 0;
            if on != (fresh.0 & (1 << index) != 0) {
                out.extend_from_slice(
                    format!("\x1b[?{}{}", MODES[index].0, if on { 'h' } else { 'l' }).as_bytes(),
                );
            }
        }
        out
    }
}

/// What kind of string a string sequence is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Text {
    Osc,
    Dcs,
    /// APC, PM, SOS: never a query.
    Other,
}

/// Where the parser is between two bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ground,
    /// Inside a multi-byte UTF-8 character: this many bytes to come.
    Utf8(u8),
    /// `0xC2` seen in the ground: a C1 control (U+0080 to U+009F) or a
    /// character follows.
    Lead,
    Escape,
    /// `ESC` and an intermediate byte (`ESC ( B`): one more byte ends it.
    EscapeIntermediate,
    Csi,
    Text(Text),
    /// `ESC` inside a string: `\` ends it.
    TextEscape(Text),
    /// `0xC2` inside a string: `0x9C` (ST) ends it.
    TextLead(Text),
}

/// The VT parser: what goes into the kept output, what is left out, the
/// modes.
#[derive(Debug, Clone)]
struct Parser {
    state: State,
    modes: Modes,
    /// The sequence being read, held until it is complete.
    held: Vec<u8>,
    /// The held sequence grew past `HOLD_BYTES`: the rest of it passes
    /// through as it comes.
    streaming: bool,
}

impl Default for Parser {
    fn default() -> Self {
        Self {
            state: State::Ground,
            modes: Modes::default(),
            held: Vec::new(),
            streaming: false,
        }
    }
}

/// One chunk's output while it is being made.
struct Out<'a> {
    data: &'a mut Vec<u8>,
    /// Where a replay may start in it, and the modes that hold there.
    start: &'a mut Option<(usize, Modes)>,
}

impl Out<'_> {
    /// Marks the current end as a place a replay may start.
    fn boundary(&mut self, modes: Modes) {
        if self.start.is_none() {
            *self.start = Some((self.data.len(), modes));
        }
    }
}

impl Parser {
    /// Starts holding a sequence.
    fn begin(&mut self, out: &mut Out, bytes: &[u8], state: State) {
        // A sequence starts where the ground was: a replay may start here.
        out.boundary(self.modes);
        self.held.clear();
        self.held.extend_from_slice(bytes);
        self.streaming = false;
        self.state = state;
    }

    /// One more byte of the sequence being read.
    fn hold(&mut self, out: &mut Out, byte: u8) {
        if self.streaming {
            out.data.push(byte);
            return;
        }
        self.held.push(byte);
        if self.held.len() > HOLD_BYTES {
            self.streaming = true;
            out.data.append(&mut self.held);
        }
    }

    /// The sequence being read is complete: kept unless it is a query.
    fn finish(&mut self, out: &mut Out) {
        self.state = State::Ground;
        if self.streaming {
            self.streaming = false;
            return;
        }
        let held = std::mem::take(&mut self.held);
        // Held from an earlier chunk, it starts this one at a place a
        // replay may start (the ground was before it).
        out.boundary(self.modes);
        self.apply(&held);
        if !is_query(&held) {
            out.data.extend_from_slice(&held);
        }
    }

    /// A sequence broken off (CAN, SUB): what was read stays, as the
    /// terminal shows it.
    fn abort(&mut self, out: &mut Out) {
        self.state = State::Ground;
        if !self.streaming {
            out.data.append(&mut self.held);
        }
        self.streaming = false;
    }

    fn byte(&mut self, out: &mut Out, byte: u8) {
        if matches!(byte, 0x18 | 0x1a)
            && !matches!(self.state, State::Ground | State::Utf8(_) | State::Lead)
        {
            self.hold(out, byte);
            self.abort(out);
            return;
        }
        match self.state {
            State::Ground => self.ground(out, byte),
            State::Utf8(need) => {
                if (0x80..0xc0).contains(&byte) {
                    out.data.push(byte);
                    self.state = if need > 1 {
                        State::Utf8(need - 1)
                    } else {
                        State::Ground
                    };
                } else {
                    // A broken character: start over with this byte.
                    self.state = State::Ground;
                    self.ground(out, byte);
                }
            }
            State::Lead => match byte {
                0x9b => self.begin(out, &[0xc2, 0x9b], State::Csi),
                0x9d => self.begin(out, &[0xc2, 0x9d], State::Text(Text::Osc)),
                0x90 => self.begin(out, &[0xc2, 0x90], State::Text(Text::Dcs)),
                0x98 | 0x9e | 0x9f => self.begin(out, &[0xc2, byte], State::Text(Text::Other)),
                0x80..=0xbf => {
                    out.boundary(self.modes);
                    out.data.extend_from_slice(&[0xc2, byte]);
                    self.state = State::Ground;
                }
                _ => {
                    out.data.push(0xc2);
                    self.state = State::Ground;
                    self.ground(out, byte);
                }
            },
            State::Escape => match byte {
                b'[' => {
                    self.hold(out, byte);
                    self.state = State::Csi;
                }
                b']' => {
                    self.hold(out, byte);
                    self.state = State::Text(Text::Osc);
                }
                b'P' => {
                    self.hold(out, byte);
                    self.state = State::Text(Text::Dcs);
                }
                b'_' | b'^' | b'X' => {
                    self.hold(out, byte);
                    self.state = State::Text(Text::Other);
                }
                0x20..=0x2f => {
                    self.hold(out, byte);
                    self.state = State::EscapeIntermediate;
                }
                0x1b => {
                    // A new escape: the old one is dropped, as a
                    // terminal drops it.
                    self.held.clear();
                    self.held.push(byte);
                }
                b'c' => {
                    self.hold(out, byte);
                    self.modes = Modes::default();
                    self.finish(out);
                }
                _ => {
                    self.hold(out, byte);
                    self.finish(out);
                }
            },
            State::EscapeIntermediate => {
                self.hold(out, byte);
                if !(0x20..=0x2f).contains(&byte) {
                    self.finish(out);
                }
            }
            State::Csi => match byte {
                0x40..=0x7e => {
                    self.hold(out, byte);
                    self.finish(out);
                }
                0x1b => {
                    self.abort(out);
                    self.begin(out, &[0x1b], State::Escape);
                }
                _ => self.hold(out, byte),
            },
            State::Text(kind) => match byte {
                0x07 if kind == Text::Osc => {
                    self.hold(out, byte);
                    self.finish(out);
                }
                0x1b => {
                    self.hold(out, byte);
                    self.state = State::TextEscape(kind);
                }
                0xc2 => {
                    self.hold(out, byte);
                    self.state = State::TextLead(kind);
                }
                _ => self.hold(out, byte),
            },
            State::TextEscape(kind) => {
                self.hold(out, byte);
                if byte == b'\\' {
                    self.finish(out);
                } else {
                    self.state = State::Text(kind);
                }
            }
            State::TextLead(kind) => {
                self.hold(out, byte);
                if byte == 0x9c {
                    self.finish(out);
                } else {
                    self.state = State::Text(kind);
                }
            }
        }
    }

    fn ground(&mut self, out: &mut Out, byte: u8) {
        match byte {
            0x1b => self.begin(out, &[0x1b], State::Escape),
            0xc2 => self.state = State::Lead,
            0x00..=0x7f => {
                out.boundary(self.modes);
                out.data.push(byte);
            }
            0xc3..=0xdf => {
                out.boundary(self.modes);
                out.data.push(byte);
                self.state = State::Utf8(1);
            }
            0xe0..=0xef => {
                out.boundary(self.modes);
                out.data.push(byte);
                self.state = State::Utf8(2);
            }
            0xf0..=0xf4 => {
                out.boundary(self.modes);
                out.data.push(byte);
                self.state = State::Utf8(3);
            }
            // A raw 8-bit C1 introducer, as xterm.js takes it.
            0x9b => self.begin(out, &[byte], State::Csi),
            0x9d => self.begin(out, &[byte], State::Text(Text::Osc)),
            0x90 => self.begin(out, &[byte], State::Text(Text::Dcs)),
            // Anything else stray is shown as it is, but is no place to
            // start.
            _ => out.data.push(byte),
        }
    }

    /// Mode switches and resets in a complete sequence.
    fn apply(&mut self, sequence: &[u8]) {
        let Some((marker, params, intermediates, last)) = csi_parts(sequence) else {
            return;
        };
        if intermediates == b"!" && last == b'p' && params.is_empty() {
            // `CSI ! p`, a soft reset, puts the cursor and the keys back.
            self.modes.set(1, false);
            self.modes.set(25, true);
            return;
        }
        if marker != Some(b'?') || !intermediates.is_empty() || !matches!(last, b'h' | b'l') {
            return;
        }
        for part in params.split(|b| *b == b';') {
            if let Some(mode) = std::str::from_utf8(part)
                .ok()
                .and_then(|text| text.parse::<u16>().ok())
            {
                self.modes.set(mode, last == b'h');
            }
        }
    }
}

/// The parts of a complete CSI sequence: its private marker (`?`, `>`,
/// `=`, `<`), parameters, intermediates and final byte.
/// A CSI sequence's private marker, parameters, intermediates and final
/// byte.
type CsiParts<'a> = (Option<u8>, &'a [u8], &'a [u8], u8);

fn csi_parts(sequence: &[u8]) -> Option<CsiParts<'_>> {
    let body = sequence
        .strip_prefix(b"\x1b[")
        .or_else(|| sequence.strip_prefix(&[0xc2, 0x9b]))
        .or_else(|| sequence.strip_prefix(&[0x9b]))?;
    let (&last, body) = body.split_last()?;
    let (marker, body) = match body.first() {
        Some(&m @ (b'?' | b'>' | b'=' | b'<')) => (Some(m), &body[1..]),
        _ => (None, body),
    };
    let split = body
        .iter()
        .position(|b| (0x20..=0x2f).contains(b))
        .unwrap_or(body.len());
    Some((marker, &body[..split], &body[split..], last))
}

/// The payload of a complete string sequence of this kind, without its
/// introducer and terminator.
fn text_payload(sequence: &[u8], kind: u8, c1: u8) -> Option<&[u8]> {
    let body = sequence
        .strip_prefix(&[0x1b, kind])
        .or_else(|| sequence.strip_prefix(&[0xc2, c1]))
        .or_else(|| sequence.strip_prefix(&[c1]))?;
    body.strip_suffix(b"\x1b\\")
        .or_else(|| body.strip_suffix(&[0xc2, 0x9c]))
        .or_else(|| body.strip_suffix(&[0x07]))
}

/// Whether a complete sequence asks the terminal for an answer, which it
/// would type back.
fn is_query(sequence: &[u8]) -> bool {
    // `ESC Z`: the old way of asking for the device attributes.
    if sequence == b"\x1bZ" {
        return true;
    }
    if let Some((marker, params, intermediates, last)) = csi_parts(sequence) {
        let first: Option<u16> = params
            .split(|b| *b == b';')
            .next()
            .and_then(|part| std::str::from_utf8(part).ok())
            .and_then(|text| text.parse().ok());
        return match (last, intermediates) {
            // Device attributes (`CSI c`, `CSI > c`, `CSI = c`).
            (b'c', b"") => true,
            // Status and cursor position reports (`CSI 5 n`, `CSI 6 n`,
            // `CSI ? 6 n`, …).
            (b'n', b"") => true,
            // Mode requests (`CSI Ps $ p`, `CSI ? Ps $ p`).
            (b'p', b"$") => true,
            // Window reports (`CSI 11/13/14/15/16/18/19/20/21 t`).
            (b't', b"") => {
                marker.is_none()
                    && matches!(first, Some(11 | 13 | 14 | 15 | 16 | 18 | 19 | 20 | 21))
            }
            // Terminal parameters (`CSI x`), the version (`CSI > q`), the
            // keyboard protocol (`CSI ? u`).
            (b'x', b"") => marker.is_none(),
            (b'q', b"") => marker == Some(b'>'),
            (b'u', b"") => marker == Some(b'?'),
            _ => false,
        };
    }
    if let Some(payload) = text_payload(sequence, b'P', 0x90) {
        // Setting requests (`DCS $ q … ST`), capability requests
        // (`DCS + q … ST`).
        return payload.starts_with(b"$q") || payload.starts_with(b"+q");
    }
    if let Some(payload) = text_payload(sequence, b']', 0x9d) {
        // Colour and clipboard queries end in `?` (`OSC 10 ; ?`,
        // `OSC 4 ; 1 ; ?`, `OSC 52 ; c ; ?`).
        return payload
            .split(|b| *b == b';')
            .skip(1)
            .any(|part| part == b"?");
    }
    false
}

/// One piece of output, with where a replay may start in it and the modes
/// that held there (`None`: it is all inside one long string).
#[derive(Debug)]
struct Chunk {
    data: Vec<u8>,
    start: Option<(usize, Modes)>,
}

/// The recent output of one session.
#[derive(Debug)]
pub struct Replay {
    chunks: VecDeque<Chunk>,
    bytes: usize,
    cap: usize,
    parser: Parser,
}

impl Default for Replay {
    fn default() -> Self {
        Self::new(REPLAY_BYTES)
    }
}

impl Replay {
    pub fn new(cap: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            bytes: 0,
            cap: cap.max(CHUNK_BYTES),
            parser: Parser::default(),
        }
    }

    /// Bytes kept now.
    #[cfg(test)]
    pub fn kept(&self) -> usize {
        self.bytes
    }

    /// Takes in what the terminal printed; the oldest output goes past
    /// the cap.
    pub fn push(&mut self, data: &[u8]) {
        for piece in data.chunks(CHUNK_BYTES) {
            let mut kept = Vec::with_capacity(piece.len());
            let mut start = None;
            {
                let mut out = Out {
                    data: &mut kept,
                    start: &mut start,
                };
                for byte in piece {
                    self.parser.byte(&mut out, *byte);
                }
            }
            if kept.is_empty() {
                continue;
            }
            self.bytes += kept.len();
            self.chunks.push_back(Chunk { data: kept, start });
        }
        while self.bytes > self.cap
            && let Some(oldest) = self.chunks.pop_front()
        {
            self.bytes -= oldest.data.len();
        }
    }

    /// What a page that just reset its terminal writes to show the recent
    /// screen: the modes as they stood where it starts, then the output.
    /// It starts at the first place a replay may start; chunks before it
    /// (the middle of one long string) are left out.
    pub fn snapshot(&self) -> Vec<u8> {
        let Some(first) = self.chunks.iter().position(|chunk| chunk.start.is_some()) else {
            return Vec::new();
        };
        let chunk = &self.chunks[first];
        let Some((start, modes)) = chunk.start else {
            return Vec::new();
        };
        let mut out = modes.prefix();
        out.reserve(self.bytes);
        out.extend_from_slice(&chunk.data[start..]);
        for chunk in self.chunks.iter().skip(first + 1) {
            out.extend_from_slice(&chunk.data);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modes_of(bytes: &[u8]) -> Modes {
        let mut replay = Replay::default();
        replay.push(bytes);
        replay.parser.modes
    }

    #[test]
    fn it_keeps_what_was_printed_in_order() {
        let mut replay = Replay::default();
        replay.push(b"one ");
        replay.push(b"two\r\n\x1b[1;31mred\x1b[0m \xc3\xa9t\xc3\xa9 \xe2\x94\x80");
        assert_eq!(
            replay.snapshot(),
            b"one two\r\n\x1b[1;31mred\x1b[0m \xc3\xa9t\xc3\xa9 \xe2\x94\x80"
        );
        assert_eq!(Replay::default().snapshot(), b"");
        // A sequence split between two writes is kept whole.
        let mut replay = Replay::default();
        replay.push(b"a\x1b[3");
        assert_eq!(replay.snapshot(), b"a");
        replay.push(b"1mb");
        assert_eq!(replay.snapshot(), b"a\x1b[31mb");
    }

    #[test]
    fn it_is_bounded_and_drops_the_oldest_first() {
        let mut replay = Replay::new(64 * 1024);
        for n in 0..10_000 {
            replay.push(format!("line {n:05}\r\n").as_bytes());
        }
        assert!(replay.kept() <= 64 * 1024, "{}", replay.kept());
        let text = String::from_utf8(replay.snapshot()).unwrap();
        assert!(text.ends_with("line 09999\r\n"));
        assert!(!text.contains("line 00000"));
        // One huge write is split, and the cap still holds.
        let mut replay = Replay::new(64 * 1024);
        replay.push(&vec![b'x'; 1024 * 1024]);
        assert!(replay.kept() <= 64 * 1024);
        assert!(replay.snapshot().len() >= 48 * 1024);
        // The default cap.
        let mut replay = Replay::default();
        for _ in 0..100 {
            replay.push(&[b'y'; 16 * 1024]);
        }
        assert!(replay.kept() <= REPLAY_BYTES);
        assert!(replay.kept() >= REPLAY_BYTES - CHUNK_BYTES);
    }

    #[test]
    fn a_replay_never_starts_inside_a_sequence_or_a_character() {
        // The first chunk ends inside a colour sequence, held until the
        // second finishes it; then the first chunk goes.
        let mut replay = Replay::new(16 * 1024);
        let mut first = vec![b'a'; 16 * 1024 - 3];
        first.extend_from_slice(b"\x1b[3");
        replay.push(&first);
        replay.push(b"1mred\x1b[0m");
        replay.push(&[b'b'; 16 * 1024 - 13]);
        let out = replay.snapshot();
        assert!(out.starts_with(b"\x1b[31mred\x1b[0m"), "{:?}", &out[..12]);
        // A character cut in two: the replay starts after it.
        let mut replay = Replay::new(16 * 1024);
        let mut first = vec![b'a'; 16 * 1024 - 1];
        first.push(0xc3);
        replay.push(&first);
        replay.push(&[0xa9, b'z']);
        replay.push(&[b'b'; 16 * 1024 - 2]);
        assert!(replay.snapshot().starts_with(b"z"));
        // A long string (a big clipboard copy) that fills whole chunks:
        // no replay starts inside it.
        let mut replay = Replay::new(32 * 1024);
        replay.push(b"before\x1b]52;c;");
        replay.push(&[b'Q'; 40 * 1024]);
        replay.push(b"\x07after");
        let out = replay.snapshot();
        assert!(out.starts_with(b"after"), "{:?}", &out[..20]);
    }

    #[test]
    fn modes_switched_before_the_kept_output_are_set_again() {
        let mut replay = Replay::new(16 * 1024);
        // A full-screen program: the alternate screen, hidden cursor,
        // SGR mouse and bracketed paste, then a lot of output.
        replay.push(b"\x1b[?1049h\x1b[?25l\x1b[?1000;1006h\x1b[?2004h");
        for _ in 0..3 {
            replay.push(&[b'.'; 16 * 1024]);
        }
        let out = replay.snapshot();
        let text = String::from_utf8_lossy(&out[..64]).to_string();
        assert!(text.starts_with("\x1b[?1049h"), "{text:?}");
        for mode in ["\x1b[?25l", "\x1b[?1000h", "\x1b[?1006h", "\x1b[?2004h"] {
            assert!(text.contains(mode), "{mode:?} in {text:?}");
        }
        // Switched off again: nothing to set.
        let mut replay = Replay::new(16 * 1024);
        replay.push(b"\x1b[?1049h\x1b[?2004h");
        replay.push(b"\x1b[?2004l\x1b[?1049l");
        for _ in 0..3 {
            replay.push(&[b'.'; 16 * 1024]);
        }
        assert!(replay.snapshot().starts_with(b"..."));
        // A full reset clears them; other sequences do not touch them.
        let modes = modes_of(b"\x1b[?1h\x1b[2J\x1b[1;1H\x1b[38;5;196mX\x1b]0;t\x1b\\");
        assert_eq!(modes.prefix(), b"\x1b[?1h");
        assert_eq!(modes_of(b"\x1b[?1h\x1bc"), Modes::default());
        // The 8-bit CSI, as U+009B and as a raw byte, switches them too;
        // a UTF-8 character whose last byte is 0x9B does not.
        assert_eq!(modes_of(b"\xc2\x9b?1049h").prefix(), b"\x1b[?1049h");
        assert_eq!(modes_of(b"\x9b?2004h").prefix(), b"\x1b[?2004h");
        assert_eq!(modes_of("Λ?2004h".as_bytes()), Modes::default());
    }

    #[test]
    fn queries_are_left_out_of_the_replay() {
        let queries: &[&[u8]] = &[
            b"\x1b[c",
            b"\x1b[0c",
            b"\x1b[>c",
            b"\x1b[>0c",
            b"\x1b[=c",
            b"\x1b[5n",
            b"\x1b[6n",
            b"\x1b[?6n",
            b"\x1b[?2004$p",
            b"\x1b[4$p",
            b"\x1bP$qm\x1b\\",
            b"\x1bP$q\"q\x1b\\",
            b"\x1bP+q544e\x1b\\",
            b"\x1b]4;1;?\x07",
            b"\x1b]10;?\x07",
            b"\x1b]11;?\x1b\\",
            b"\x1b]12;?\x07",
            b"\x1b]52;c;?\x07",
            b"\x1b[14t",
            b"\x1b[18t",
            b"\x1b[19t",
            b"\x1b[21t",
            b"\x1b[>q",
            b"\x1b[?u",
            b"\x1bZ",
            b"\xc2\x9bc",
            b"\x9b6n",
            b"\xc2\x90$qm\xc2\x9c",
        ];
        for query in queries {
            let mut replay = Replay::default();
            let mut input = b"x".to_vec();
            input.extend_from_slice(query);
            input.push(b'y');
            // Split anywhere, the result is the same.
            for split in 0..input.len() {
                let mut replay2 = Replay::default();
                replay2.push(&input[..split]);
                replay2.push(&input[split..]);
                assert_eq!(replay2.snapshot(), b"xy", "{query:?} split at {split}");
            }
            replay.push(&input);
            assert_eq!(replay.snapshot(), b"xy", "{query:?}");
        }
        // What only looks alike is kept.
        let kept: &[&[u8]] = &[
            b"\x1b[2J",
            b"\x1b[?1049h",
            b"\x1b[22;0t",
            b"\x1b[8;24;80t",
            b"\x1b]0;title\x07",
            b"\x1b]52;c;aGk=\x07",
            b"\x1b]10;#ffffff\x07",
            b"\x1bP1$r0m\x1b\\",
            b"\x1b[2 q",
            b"\x1b[>1u",
            b"\x1b(B",
        ];
        for sequence in kept {
            let mut replay = Replay::default();
            replay.push(sequence);
            assert_eq!(replay.snapshot(), *sequence, "{sequence:?}");
        }
    }
}
