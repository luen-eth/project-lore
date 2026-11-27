//! The recent screen of a terminal session, kept in lore's memory so a
//! page that attaches to a running session is not blank.
//!
//! What a PTY printed is kept as it came, in chunks, up to [`REPLAY_BYTES`]:
//! the oldest chunks go first. It lives only here, in memory: it is never
//! written to the database, to a file or to the log, and it goes when the
//! session ends.
//!
//! Raw bytes cut at an arbitrary place do not replay well, so two things
//! are tracked while the bytes pass:
//! - where in each chunk the first whole character outside an escape
//!   sequence starts, so a replay never begins inside a sequence;
//! - the terminal modes a program switches with `CSI ? n h/l` (the
//!   alternate screen, the cursor keys, the cursor's visibility, mouse
//!   reporting, focus events, bracketed paste) as they stood there, so a
//!   replay that starts after the switch still sets them. Without that a
//!   full-screen program would replay on the wrong screen and the keys
//!   and the mouse would send what it does not expect.
//!
//! The replay only has to be close: lore resizes the PTY right after it,
//! which has the program draw its whole screen again.

use std::collections::VecDeque;

/// Most bytes kept per session.
pub const REPLAY_BYTES: usize = 512 * 1024;

/// Largest chunk kept: bigger pieces are split, so dropping the oldest
/// chunk never drops much more than needed.
const CHUNK_BYTES: usize = 16 * 1024;

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

/// Where the parser is between two bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ground,
    Escape,
    /// `ESC` and an intermediate byte (`ESC ( B`): one more byte ends it.
    EscapeIntermediate,
    Csi,
    /// A string (OSC, DCS, APC, PM, SOS), ended by BEL or `ESC \`.
    Text,
    /// `ESC` inside a string: `\` ends it.
    TextEscape,
}

/// Longest parameter list read; a longer one is not a mode switch.
const MAX_PARAMS: usize = 64;

/// A small VT parser that only follows the modes.
#[derive(Debug, Clone)]
struct Parser {
    state: State,
    modes: Modes,
    params: Vec<u8>,
    private: bool,
    intermediate: bool,
}

impl Default for Parser {
    fn default() -> Self {
        Self {
            state: State::Ground,
            modes: Modes::default(),
            params: Vec::new(),
            private: false,
            intermediate: false,
        }
    }
}

impl Parser {
    fn byte(&mut self, byte: u8) {
        // CAN and SUB abort any sequence.
        if matches!(byte, 0x18 | 0x1a) && self.state != State::Text {
            self.state = State::Ground;
            return;
        }
        match self.state {
            State::Ground => {
                if byte == 0x1b {
                    self.state = State::Escape;
                }
            }
            State::Escape => match byte {
                b'[' => {
                    self.state = State::Csi;
                    self.params.clear();
                    self.private = false;
                    self.intermediate = false;
                }
                b']' | b'P' | b'_' | b'^' | b'X' => self.state = State::Text,
                0x20..=0x2f => self.state = State::EscapeIntermediate,
                0x1b => {}
                b'c' => {
                    // A full reset.
                    self.modes = Modes::default();
                    self.state = State::Ground;
                }
                _ => self.state = State::Ground,
            },
            State::EscapeIntermediate => {
                if !(0x20..=0x2f).contains(&byte) {
                    self.state = State::Ground;
                }
            }
            State::Csi => match byte {
                b'?' if self.params.is_empty() => self.private = true,
                0x30..=0x3f => {
                    if self.params.len() < MAX_PARAMS {
                        self.params.push(byte);
                    } else {
                        self.intermediate = true;
                    }
                }
                0x20..=0x2f => self.intermediate = true,
                0x40..=0x7e => {
                    self.finish(byte);
                    self.state = State::Ground;
                }
                0x1b => self.state = State::Escape,
                // Control characters inside a sequence act and are gone.
                _ => {}
            },
            State::Text => match byte {
                0x07 => self.state = State::Ground,
                0x1b => self.state = State::TextEscape,
                _ => {}
            },
            State::TextEscape => {
                self.state = if byte == b'\\' {
                    State::Ground
                } else {
                    State::Text
                };
            }
        }
    }

    fn finish(&mut self, last: u8) {
        if self.intermediate {
            // `CSI ! p`, a soft reset, puts the cursor and the keys back.
            if last == b'p' && self.params.is_empty() {
                self.modes.set(1, false);
                self.modes.set(25, true);
            }
            return;
        }
        if !self.private || !matches!(last, b'h' | b'l') {
            return;
        }
        let on = last == b'h';
        for part in self.params.split(|b| *b == b';') {
            if let Some(mode) = std::str::from_utf8(part)
                .ok()
                .and_then(|text| text.parse::<u16>().ok())
            {
                self.modes.set(mode, on);
            }
        }
    }
}

/// One piece of output, with where a replay may start in it and the modes
/// that held there.
#[derive(Debug)]
struct Chunk {
    data: Vec<u8>,
    start: usize,
    modes: Modes,
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
            let mut start = None;
            let mut modes = self.parser.modes;
            for (index, byte) in piece.iter().enumerate() {
                if start.is_none() && self.parser.state == State::Ground && byte & 0xc0 != 0x80 {
                    start = Some(index);
                    modes = self.parser.modes;
                }
                self.parser.byte(*byte);
            }
            self.chunks.push_back(Chunk {
                data: piece.to_vec(),
                start: start.unwrap_or(piece.len()),
                modes,
            });
            self.bytes += piece.len();
        }
        while self.bytes > self.cap
            && let Some(oldest) = self.chunks.pop_front()
        {
            self.bytes -= oldest.data.len();
        }
    }

    /// What a page that just reset its terminal writes to show the recent
    /// screen: the modes as they stood where it starts, then the output.
    pub fn snapshot(&self) -> Vec<u8> {
        let Some(first) = self.chunks.front() else {
            return Vec::new();
        };
        let mut out = first.modes.prefix();
        out.reserve(self.bytes);
        out.extend_from_slice(&first.data[first.start..]);
        for chunk in self.chunks.iter().skip(1) {
            out.extend_from_slice(&chunk.data);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_keeps_what_was_printed_in_order() {
        let mut replay = Replay::default();
        replay.push(b"one ");
        replay.push(b"two\r\n");
        assert_eq!(replay.snapshot(), b"one two\r\n");
        assert_eq!(Replay::default().snapshot(), b"");
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
        let mut replay = Replay::new(16 * 1024);
        // The first chunk ends inside a colour sequence, which the
        // second one finishes; then the first chunk goes.
        let mut first = vec![b'a'; 16 * 1024 - 3];
        first.extend_from_slice(b"\x1b[3");
        replay.push(&first);
        replay.push(b"1mred\x1b[0m");
        replay.push(&[b'b'; 16 * 1024 - 13]);
        let out = replay.snapshot();
        assert!(out.starts_with(b"red\x1b[0m"), "{:?}", &out[..12]);
        // A character cut in two: the replay starts after it.
        let mut replay = Replay::new(16 * 1024);
        let mut first = vec![b'a'; 16 * 1024 - 1];
        first.push(0xc3);
        replay.push(&first);
        replay.push(&[0xa9, b'z']);
        replay.push(&[b'b'; 16 * 1024 - 2]);
        assert!(replay.snapshot().starts_with(b"z"));
        // An OSC title split across chunks.
        let mut replay = Replay::new(16 * 1024);
        let mut first = vec![b'a'; 16 * 1024 - 4];
        first.extend_from_slice(b"\x1b]0;");
        replay.push(&first);
        replay.push(b"my title\x07after");
        replay.push(&[b'b'; 16 * 1024 - 14]);
        assert!(replay.snapshot().starts_with(b"after"));
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
        let mut parser = Parser::default();
        for byte in b"\x1b[?1h\x1b[2J\x1b[1;1H\x1b[38;5;196mX\x1b]0;t\x1b\\" {
            parser.byte(*byte);
        }
        assert_eq!(parser.modes.prefix(), b"\x1b[?1h");
        for byte in b"\x1bc" {
            parser.byte(*byte);
        }
        assert_eq!(parser.modes, Modes::default());
    }
}
