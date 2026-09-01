//! "GPS EXIF cannot survive a send", and what happens to a format we cannot strip.

use spark_chunk::media;
use spark_chunk::scrub::*;

/// A minimal JPEG carrying an APP1 EXIF segment with a GPS IFD tag in it.
fn jpeg_with_gps() -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8];

    // APP1 / EXIF, holding a recognisable GPS payload.
    let mut exif = b"Exif\x00\x00".to_vec();
    exif.extend_from_slice(b"II*\x00\x08\x00\x00\x00");
    exif.extend_from_slice(b"GPSLatitude 51.5074 GPSLongitude -0.1278");
    v.extend_from_slice(&[0xFF, 0xE1]);
    v.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
    v.extend_from_slice(&exif);

    // APP13 / IPTC, a second place location hides.
    let iptc = b"Photoshop 3.0\x00 City: London";
    v.extend_from_slice(&[0xFF, 0xED]);
    v.extend_from_slice(&((iptc.len() + 2) as u16).to_be_bytes());
    v.extend_from_slice(iptc);

    // A comment segment.
    let com = b"taken on my phone";
    v.extend_from_slice(&[0xFF, 0xFE]);
    v.extend_from_slice(&((com.len() + 2) as u16).to_be_bytes());
    v.extend_from_slice(com);

    // A quantization table, which must survive.
    let dqt = [0u8; 65];
    v.extend_from_slice(&[0xFF, 0xDB]);
    v.extend_from_slice(&((dqt.len() + 2) as u16).to_be_bytes());
    v.extend_from_slice(&dqt);

    // Start of scan, then entropy-coded data.
    v.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]);
    v.extend_from_slice(b"PIXELDATA-PIXELDATA");
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

fn png_with_metadata() -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    let chunk = |kind: &[u8; 4], data: &[u8]| {
        let mut c = (data.len() as u32).to_be_bytes().to_vec();
        c.extend_from_slice(kind);
        c.extend_from_slice(data);
        c.extend_from_slice(&[0, 0, 0, 0]); // CRC; not checked by the scrubber
        c
    };
    v.extend_from_slice(&chunk(b"IHDR", &[0u8; 13]));
    v.extend_from_slice(&chunk(b"eXIf", b"II*\x00GPSLatitude 51.5074"));
    v.extend_from_slice(&chunk(b"tEXt", b"Comment\x00taken at home"));
    v.extend_from_slice(&chunk(b"iTXt", b"Location\x00\x00\x00\x00\x00London"));
    v.extend_from_slice(&chunk(b"IDAT", b"PIXELDATA"));
    v.extend_from_slice(&chunk(b"IEND", b""));
    v
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn gps_exif_cannot_survive_a_jpeg_send() {
    let raw = jpeg_with_gps();
    assert!(
        contains(&raw, b"GPSLatitude"),
        "the fixture has no GPS to remove"
    );

    let clean = scrub(&raw).expect("a JPEG is scrubbable");
    assert_eq!(clean.format(), Format::Jpeg);
    assert_eq!(
        clean.removed(),
        3,
        "APP1, APP13 and COM should all have gone"
    );

    for leak in [
        &b"GPSLatitude"[..],
        b"GPSLongitude",
        b"City: London",
        b"taken on my phone",
        b"Exif",
    ] {
        assert!(
            !contains(clean.as_bytes(), leak),
            "{:?} survived",
            String::from_utf8_lossy(leak)
        );
    }

    // And the image is still an image: header, tables and pixels intact.
    assert!(clean.as_bytes().starts_with(&[0xFF, 0xD8]));
    assert!(
        contains(clean.as_bytes(), b"PIXELDATA"),
        "pixel data was damaged"
    );
    assert!(
        contains(clean.as_bytes(), &[0xFF, 0xDB]),
        "the quantization table was dropped"
    );
}

#[test]
fn metadata_cannot_survive_a_png_send() {
    let raw = png_with_metadata();
    let clean = scrub(&raw).expect("a PNG is scrubbable");
    assert_eq!(clean.format(), Format::Png);
    assert_eq!(
        clean.removed(),
        3,
        "eXIf, tEXt and iTXt should all have gone"
    );

    for leak in [&b"GPSLatitude"[..], b"taken at home", b"London", b"eXIf"] {
        assert!(
            !contains(clean.as_bytes(), leak),
            "{:?} survived",
            String::from_utf8_lossy(leak)
        );
    }
    assert!(contains(clean.as_bytes(), b"IDAT") && contains(clean.as_bytes(), b"PIXELDATA"));
    assert!(contains(clean.as_bytes(), b"IHDR"));
}

#[test]
fn png_keeps_only_an_allow_list() {
    // A deny-list is wrong the day someone defines a new chunk type, and private
    // chunks are legal and can hold anything at all.
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    let chunk = |kind: &[u8; 4], data: &[u8]| {
        let mut c = (data.len() as u32).to_be_bytes().to_vec();
        c.extend_from_slice(kind);
        c.extend_from_slice(data);
        c.extend_from_slice(&[0, 0, 0, 0]);
        c
    };
    v.extend_from_slice(&chunk(b"IHDR", &[0u8; 13]));
    v.extend_from_slice(&chunk(b"spRk", b"a private chunk nobody has heard of"));
    v.extend_from_slice(&chunk(b"IDAT", b"PIXELDATA"));
    v.extend_from_slice(&chunk(b"IEND", b""));

    let clean = scrub(&v).unwrap();
    assert!(
        !contains(clean.as_bytes(), b"nobody has heard of"),
        "an unknown chunk was kept"
    );
    assert_eq!(clean.removed(), 1);
}

#[test]
fn a_format_we_cannot_strip_is_refused_not_forwarded() {
    // The whole point. A pass-through would ship GPS the first time someone sends
    // a format this was not taught about, and nothing would report a problem.
    for (name, bytes) in [
        ("HEIC", b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00".to_vec()),
        ("WebP", b"RIFF\x24\x00\x00\x00WEBPVP8 ".to_vec()),
        ("TIFF", b"II*\x00\x08\x00\x00\x00GPSLatitude".to_vec()),
        ("GIF", b"GIF89a\x01\x00\x01\x00".to_vec()),
    ] {
        assert_eq!(
            scrub(&bytes).unwrap_err(),
            ScrubError::UnknownFormat,
            "{name} was forwarded instead of refused"
        );
    }
}

#[test]
fn plain_bytes_pass_through_as_opaque() {
    // A text note has no container metadata. Refusing it would be theatre.
    let c = scrub(b"just some text").expect("text is sendable");
    assert_eq!(c.format(), Format::Opaque);
    assert_eq!(c.removed(), 0);
    assert_eq!(c.as_bytes(), b"just some text");

    assert_eq!(scrub(b"").unwrap_err(), ScrubError::Empty);
}

#[test]
fn a_truncated_file_is_refused() {
    let raw = jpeg_with_gps();
    assert_eq!(
        scrub(&raw[..raw.len() / 3]).unwrap_err(),
        ScrubError::Truncated
    );

    let png = png_with_metadata();
    assert_eq!(scrub(&png[..20]).unwrap_err(), ScrubError::Truncated);
}

#[test]
fn sealing_media_is_only_reachable_through_the_scrubber() {
    // `media::seal` takes a `Scrubbed`, which has no other constructor. The
    // guarantee is the type, not a rule at each call site.
    let clean = scrub(&jpeg_with_gps()).unwrap();
    let (name, key, chunk) = media::seal(&clean);

    let opened = media::open(&chunk, &key).unwrap();
    assert!(!contains(&opened, b"GPSLatitude"), "GPS reached the chunk");
    assert_eq!(media::name_of(&chunk), name);

    // Dedup still holds on the scrubbed form: two people sending the same photo
    // produce one chunk even if their originals differed only in metadata.
    let (n2, _) = media::capability(&scrub(&jpeg_with_gps()).unwrap());
    assert_eq!(name, n2);
}

#[test]
fn two_photos_differing_only_in_metadata_deduplicate() {
    // The pleasant side effect: scrubbing before hashing means the same picture
    // from two phones is one chunk, not two.
    let mut a = jpeg_with_gps();
    let mut b = jpeg_with_gps();
    // Give b a different comment segment; everything else is identical.
    let com = b"a different camera";
    b.splice(2..2, {
        let mut seg = vec![0xFF, 0xFE];
        seg.extend_from_slice(&((com.len() + 2) as u16).to_be_bytes());
        seg.extend_from_slice(com);
        seg
    });
    assert_ne!(a, b, "the fixtures are identical");

    let (na, _) = media::capability(&scrub(&a).unwrap());
    let (nb, _) = media::capability(&scrub(&b).unwrap());
    assert_eq!(na, nb, "metadata differences defeated dedup");
    a.clear();
}
