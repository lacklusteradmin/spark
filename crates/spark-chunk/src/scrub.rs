//! Metadata stripping. `Spark-build-notes.md` §1: "Strip EXIF client-side before
//! encryption."
//!
//! # Why this refuses formats it does not know
//!
//! The obvious design is a function that strips what it recognises and passes
//! everything else through. That function ships GPS coordinates the first time
//! someone sends a format it was not taught about, and nothing anywhere reports
//! a problem. Build-notes §1 again: "Never silently downgrade a privacy setting.
//! Disable the feature or warn loudly."
//!
//! So [`scrub`] returns an error for anything it cannot fully account for, and
//! [`Scrubbed`] — the only thing [`crate::media::seal`] accepts — has no other
//! constructor. Sending an unscrubbable file is not a thing the API can express.
//!
//! # Why not re-encode
//!
//! Decoding and re-encoding an image is the most thorough strip available and
//! would remove anything hidden in ways this does not anticipate. It also means
//! an image codec in the client: tens of thousands of lines of C-derived parsing
//! on attacker-supplied input, which is a far larger risk than the one it closes.
//! This walks container structure only, never pixel data, in a few hundred lines
//! that can be read in full.

use zeroize::Zeroizing;

/// A file that has been through [`scrub`].
///
/// The only way to obtain one. `crate::media::seal` takes it by reference, so
/// "EXIF cannot survive a send" is a property of the type system rather than a
/// rule someone has to remember at each call site.
pub struct Scrubbed {
    bytes: Zeroizing<Vec<u8>>,
    format: Format,
    removed: usize,
}

impl Scrubbed {
    /// The cleaned bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// What the file was recognised as.
    pub fn format(&self) -> Format {
        self.format
    }
    /// How many metadata segments were dropped. Worth surfacing: "0 removed" and
    /// "12 removed" are different stories to tell a user.
    pub fn removed(&self) -> usize {
        self.removed
    }
}

impl core::fmt::Debug for Scrubbed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Scrubbed({:?}, {} bytes, {} removed)",
            self.format,
            self.bytes.len(),
            self.removed
        )
    }
}

/// What a file was recognised as.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    /// JPEG. Metadata rides in APPn marker segments.
    Jpeg,
    /// PNG. Metadata rides in ancillary chunks.
    Png,
    /// Anything with no container metadata to strip: plain text, and the like.
    Opaque,
}

/// Strip metadata, or refuse.
pub fn scrub(bytes: &[u8]) -> Result<Scrubbed, ScrubError> {
    if bytes.is_empty() {
        return Err(ScrubError::Empty);
    }
    if bytes.starts_with(&[0xFF, 0xD8]) {
        return scrub_jpeg(bytes);
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return scrub_png(bytes);
    }
    // Anything that is not a container this module understands. A text note or a
    // serialized structure has no metadata to carry; an unrecognised *image* is
    // refused, because it is exactly the case where guessing loses.
    if looks_like_media(bytes) {
        return Err(ScrubError::UnknownFormat);
    }
    Ok(Scrubbed {
        bytes: Zeroizing::new(bytes.to_vec()),
        format: Format::Opaque,
        removed: 0,
    })
}

/// Magic numbers of formats known to carry metadata that this module cannot
/// strip. Listed so they are refused rather than waved through as `Opaque`.
fn looks_like_media(b: &[u8]) -> bool {
    const MAGIC: [&[u8]; 8] = [
        b"GIF87a",
        b"GIF89a",
        b"RIFF",                 // WebP, WAV, AVI
        b"\x00\x00\x00\x18ftyp", // MP4/HEIC family
        b"\x00\x00\x00\x20ftyp",
        b"II*\x00",       // TIFF little-endian, and bare EXIF
        b"MM\x00*",       // TIFF big-endian
        b"\x1aE\xdf\xa3", // Matroska / WebM
    ];
    MAGIC.iter().any(|m| b.starts_with(m)) || (b.len() > 12 && &b[4..8] == b"ftyp")
}

/// JPEG: keep the frame and the scan, drop every APPn and COM segment.
///
/// APP1 is EXIF and XMP, APP2 is ICC and MPF, APP13 is IPTC and Photoshop
/// resources. Rather than enumerate which are dangerous, this drops all of them:
/// the ones that matter for display are the quantization and Huffman tables and
/// the frame header, none of which are APPn.
fn scrub_jpeg(b: &[u8]) -> Result<Scrubbed, ScrubError> {
    let mut out = Vec::with_capacity(b.len());
    let mut removed = 0usize;
    let mut i = 0usize;

    out.extend_from_slice(&[0xFF, 0xD8]);
    i += 2;

    loop {
        // Markers may be preceded by fill bytes.
        while i < b.len() && b[i] == 0xFF && b.get(i + 1) == Some(&0xFF) {
            i += 1;
        }
        if i + 1 >= b.len() {
            return Err(ScrubError::Truncated);
        }
        if b[i] != 0xFF {
            return Err(ScrubError::Truncated);
        }
        let marker = b[i + 1];
        i += 2;

        match marker {
            // Start of scan: entropy-coded data runs to the end. Copy verbatim;
            // this module never walks pixel data.
            0xDA => {
                out.push(0xFF);
                out.push(marker);
                out.extend_from_slice(&b[i..]);
                return Ok(Scrubbed {
                    bytes: Zeroizing::new(out),
                    format: Format::Jpeg,
                    removed,
                });
            }
            0xD9 => {
                out.extend_from_slice(&[0xFF, 0xD9]);
                return Ok(Scrubbed {
                    bytes: Zeroizing::new(out),
                    format: Format::Jpeg,
                    removed,
                });
            }
            // Standalone markers: no length field.
            0x01 | 0xD0..=0xD7 => {
                out.push(0xFF);
                out.push(marker);
            }
            _ => {
                if i + 1 >= b.len() {
                    return Err(ScrubError::Truncated);
                }
                let len = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
                if len < 2 || i + len > b.len() {
                    return Err(ScrubError::Truncated);
                }
                let is_metadata = (0xE0..=0xEF).contains(&marker) || marker == 0xFE;
                if is_metadata {
                    removed += 1;
                } else {
                    out.push(0xFF);
                    out.push(marker);
                    out.extend_from_slice(&b[i..i + len]);
                }
                i += len;
            }
        }
    }
}

/// PNG: keep the critical chunks and the ones needed to render, drop the rest.
///
/// An allow-list, not a deny-list. PNG is extensible, so a deny-list is wrong the
/// day someone defines a new chunk type — and private chunks are legal and can
/// hold anything at all.
fn scrub_png(b: &[u8]) -> Result<Scrubbed, ScrubError> {
    const KEEP: [&[u8; 4]; 7] = [
        b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"sRGB",
    ];

    let mut out = Vec::with_capacity(b.len());
    out.extend_from_slice(&b[..8]);
    let mut i = 8usize;
    let mut removed = 0usize;

    while i < b.len() {
        if i + 8 > b.len() {
            return Err(ScrubError::Truncated);
        }
        let len = u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as usize;
        let kind: [u8; 4] = b[i + 4..i + 8].try_into().expect("4 bytes");
        let total = 12 + len; // length + type + data + CRC
        if i + total > b.len() {
            return Err(ScrubError::Truncated);
        }
        if KEEP.contains(&&kind) {
            out.extend_from_slice(&b[i..i + total]);
        } else {
            removed += 1;
        }
        i += total;
        if &kind == b"IEND" {
            break;
        }
    }
    Ok(Scrubbed {
        bytes: Zeroizing::new(out),
        format: Format::Png,
        removed,
    })
}

/// Why a file was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScrubError {
    /// Nothing to send.
    Empty,
    /// A container that carries metadata this module cannot strip. Refused
    /// rather than passed through: a format nobody taught this about is exactly
    /// where guessing loses.
    UnknownFormat,
    /// The file ends in the middle of a structure.
    Truncated,
}

impl core::fmt::Display for ScrubError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("nothing to send"),
            Self::UnknownFormat => {
                f.write_str("this file type may carry location data Spark cannot remove")
            }
            Self::Truncated => f.write_str("file ends unexpectedly"),
        }
    }
}
impl core::error::Error for ScrubError {}
