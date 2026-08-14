// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for `tpt-cms`: decode of CMS structures and signature
//! verification wiring (using a deterministic mock crypto backend, since no
//! real cryptographic primitives live in this crate).

use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_cms::content_info::ContentInfo;
use tpt_cms::enveloped_data::EnvelopedData;
use tpt_cms::oid;
use tpt_cms::signed_data::SignedData;
use tpt_cms::verify::{verify, VerificationResult};
use tpt_x509::verify::{SignatureVerifier, VerifyError};

// --- Minimal DER encoding helpers (definite lengths, DER) -------------------

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        let mut n = content.len();
        let mut tmp = [0u8; 5];
        let mut i = tmp.len();
        while n > 0 {
            i -= 1;
            tmp[i] = (n & 0xff) as u8;
            n >>= 8;
        }
        out.push(0x80 | (tmp.len() - i) as u8);
        out.extend_from_slice(&tmp[i..]);
    }
    out.extend_from_slice(content);
    out
}

macro_rules! seq {
    ($($p:expr),* $(,)?) => {{
        let mut v = Vec::new();
        $( v.extend_from_slice($p.as_ref()); )*
        tlv(0x30, &v)
    }};
}
macro_rules! set {
    ($($p:expr),* $(,)?) => {{
        let mut v = Vec::new();
        $( v.extend_from_slice($p.as_ref()); )*
        tlv(0x31, &v)
    }};
}

fn oid(bytes: &[u8]) -> Vec<u8> {
    tlv(0x06, bytes)
}
fn integer(bytes: &[u8]) -> Vec<u8> {
    tlv(0x02, bytes)
}
fn octet(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}
fn utf8(bytes: &[u8]) -> Vec<u8> {
    tlv(0x0c, bytes)
}
fn implicit0(content: &[u8]) -> Vec<u8> {
    tlv(0xa0, content)
}
fn explicit0(content: &[u8]) -> Vec<u8> {
    tlv(0xa0, content)
}

// --- OID constants ----------------------------------------------------------

const ID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const ID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const RSA_ENC: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];

/// A deterministic stand-in for a real digest (FNV-1a, expanded to 32 bytes).
fn mock_digest(data: &[u8]) -> Vec<u8> {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut out = vec![0u8; 32];
    for i in 0..8 {
        out[i] = (h >> (8 * i)) as u8;
    }
    out
}

/// A mock backend: digest = `mock_digest`; a signature "verifies" iff it is
/// byte-equal to the to-be-signed message. This exercises the full wiring
/// (content digesting, message-digest attribute check, signed-attribute
/// re-encoding) without any real cryptography.
struct MockVerifier;

impl SignatureVerifier for MockVerifier {
    fn digest(&self, _alg_oid: &[u8], data: &[u8]) -> Result<Vec<u8>, VerifyError> {
        Ok(mock_digest(data))
    }
    fn verify_signature(
        &self,
        _sig: &[u8],
        _key: &[u8],
        _pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, VerifyError> {
        Ok(message == signature)
    }
}

// --- Certificate + SignerIdentifier builders --------------------------------

fn name() -> Vec<u8> {
    // RDNSequence with a single commonName (2.5.4.3) "A".
    let atv = seq!(oid(&[0x55, 0x04, 0x03]), utf8(b"A"));
    let rdn = set!(atv);
    seq!(rdn)
}

fn certificate() -> Vec<u8> {
    let serial = integer(&[0x01]);
    let sig_alg = seq!(oid(SHA256_RSA));
    let issuer = name();
    let validity = seq!(tlv(0x17, b"250101000000Z"), tlv(0x17, b"300101000000Z"));
    let subject = name();
    let spki = seq!(seq!(oid(RSA_ENC)), tlv(0x03, &[0x00, 0x01, 0x02, 0x03]));
    let tbs = seq!(serial, sig_alg.clone(), issuer, validity, subject, spki);
    seq!(tbs, sig_alg, tlv(0x03, &[0x00, 0xaa]))
}

fn signer_id() -> Vec<u8> {
    seq!(name(), integer(&[0x01]))
}

// --- SignedData builders ----------------------------------------------------

fn signed_data_no_signed_attrs() -> Vec<u8> {
    let version = integer(&[0x01]);
    let digest_algorithms = set!(seq!(oid(SHA256)));
    let encap = seq!(oid(ID_DATA), explicit0(&octet(b"hello")));
    let certs = implicit0(&certificate());
    let signer = seq!(
        integer(&[0x01]),
        signer_id(),
        seq!(oid(SHA256)),
        seq!(oid(SHA256_RSA)),
        octet(b"hello"), // signature == content (so the mock verifies)
    );
    let signer_infos = set!(signer);
    seq!(version, digest_algorithms, encap, certs, signer_infos)
}

fn signed_data_with_signed_attrs() -> Vec<u8> {
    let content_buf = b"hello";
    let digest = mock_digest(content_buf);

    // signedAttrs content: SET OF { content-type, message-digest } (DER order).
    let attr_ct = seq!(oid(oid::ATTR_CONTENT_TYPE), set!(oid(ID_DATA)));
    let attr_md = seq!(oid(oid::ATTR_MESSAGE_DIGEST), set!(octet(&digest)));
    let set_content = [attr_ct.clone(), attr_md.clone()].concat();
    let tbs = set!(&set_content);

    let version = integer(&[0x01]);
    let digest_algorithms = set!(seq!(oid(SHA256)));
    let encap = seq!(oid(ID_DATA), explicit0(&octet(content_buf)));
    let certs = implicit0(&certificate());
    let signed_attrs = tlv(0x80, &set_content);
    let signer = seq!(
        integer(&[0x01]),
        signer_id(),
        seq!(oid(SHA256)),
        signed_attrs,
        seq!(oid(SHA256_RSA)),
        octet(&tbs), // signature == re-encoded SET OF signed attributes
    );
    let signer_infos = set!(signer);
    seq!(version, digest_algorithms, encap, certs, signer_infos)
}

fn content_info(inner: &[u8]) -> Vec<u8> {
    seq!(oid(ID_SIGNED_DATA), explicit0(inner))
}

// --- Tests ------------------------------------------------------------------

#[test]
fn decode_signed_data_no_signed_attrs() {
    let buf = content_info(&signed_data_no_signed_attrs());
    let ci = ContentInfo::decode(&mut Reader::new(&buf, Config::der()))
        .expect("ContentInfo decodes");
    assert_eq!(ci.content_type.0, ID_SIGNED_DATA);
    let sd: SignedData<'_> = ci.decode_content().expect("SignedData decodes");
    assert!(sd.is_pkcs7_legacy()); // version 1 with IssuerAndSerialNumber is legacy-shaped
    assert_eq!(sd.content_bytes(), Some(&b"hello"[..]));
    assert_eq!(sd.signer_infos.len(), 1);
    assert!(sd.signer_infos[0].signed_attrs.is_none());
}

#[test]
fn verify_signed_data_no_signed_attrs() {
    let buf = content_info(&signed_data_no_signed_attrs());
    let ci = ContentInfo::decode(&mut Reader::new(&buf, Config::der()))
        .expect("ContentInfo decodes");
    let sd: SignedData<'_> = ci.decode_content().expect("SignedData decodes");
    let results = verify(&sd, &MockVerifier, None, &[]).expect("verify runs");
    assert_eq!(results, vec![VerificationResult::Success]);
}

#[test]
fn verify_signed_data_bad_signature() {
    let buf = content_info(&signed_data_no_signed_attrs());
    let ci = ContentInfo::decode(&mut Reader::new(&buf, Config::der()))
        .expect("ContentInfo decodes");
    let sd: SignedData<'_> = ci.decode_content().expect("SignedData decodes");
    // Tamper: a signature that no longer equals the content must fail.
    let mut sd2 = sd;
    sd2.signer_infos[0].signature = b"tampered";
    let results = verify(&sd2, &MockVerifier, None, &[]).expect("verify runs");
    assert_eq!(results, vec![VerificationResult::SignatureInvalid]);
}

#[test]
fn verify_signed_data_with_signed_attrs() {
    let buf = content_info(&signed_data_with_signed_attrs());
    let ci = ContentInfo::decode(&mut Reader::new(&buf, Config::der()))
        .expect("ContentInfo decodes");
    let sd: SignedData<'_> = ci.decode_content().expect("SignedData decodes");
    assert!(sd.signer_infos[0].signed_attrs.is_some());
    let results = verify(&sd, &MockVerifier, None, &[]).expect("verify runs");
    assert_eq!(results, vec![VerificationResult::Success]);
}

#[test]
fn verify_detached_missing_content() {
    // Build a SignedData with no eContent, then verify without external content.
    let buf = content_info(&signed_data_no_signed_attrs());
    let ci = ContentInfo::decode(&mut Reader::new(&buf, Config::der()))
        .expect("ContentInfo decodes");
    let mut sd: SignedData<'_> = ci.decode_content().expect("SignedData decodes");
    sd.e_content = None;
    let err = verify(&sd, &MockVerifier, None, &[]);
    assert!(err.is_err());
}

#[test]
fn decode_enveloped_data_key_transport() {
    // EnvelopedData with a single KeyTransRecipientInfo.
    let version = integer(&[0x00]);
    let ktri = seq!(
        integer(&[0x00]),
        signer_id(),
        seq!(oid(RSA_ENC)),
        octet(&[0x11, 0x22, 0x33]),
    );
    let recipient_infos = set!(ktri);
    let eci = seq!(oid(ID_DATA), seq!(oid(SHA256)), tlv(0x80, b"cipher"));
    let ed = seq!(version, recipient_infos, eci);
    let ci_buf = content_info(&ed);

    let ci = ContentInfo::decode(&mut Reader::new(&ci_buf, Config::der())).expect("ContentInfo decodes");
    let ed: EnvelopedData<'_> = ci.decode_content().expect("EnvelopedData decodes");
    assert_eq!(ed.version, 0);
    assert_eq!(ed.recipient_infos.len(), 1);
    let kt = ed.recipient_infos[0].as_key_trans().expect("is KeyTrans");
    assert_eq!(kt.encrypted_key, &[0x11, 0x22, 0x33]);
    assert_eq!(ed.encrypted_content_info.encrypted_content.unwrap().0, b"cipher");
}
