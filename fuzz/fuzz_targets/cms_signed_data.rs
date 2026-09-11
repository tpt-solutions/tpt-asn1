// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz target: CMS inner content types (RFC 5652 / PKCS#7).
//!
//! Exercises `SignedData`, `EnvelopedData`, `DigestedData`, `EncryptedData`,
//! `SignerInfo`, and the recipient-info / attribute decoders against arbitrary
//! bytes. Content is decoded both standalone (when the input is itself a
//! content structure) and via `ContentInfo::decode_content`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_asn1_core::decode::Decode;
use tpt_asn1_core::reader::{Config, Reader};
use tpt_asn1_cms::content_info::ContentInfo;
use tpt_asn1_cms::enveloped_data::{DigestedData, EncryptedData, EnvelopedData};
use tpt_asn1_cms::recipient_info::RecipientInfo;
use tpt_asn1_cms::signed_data::SignedData;
use tpt_asn1_cms::signer_info::SignerInfo;

fuzz_target!(|data: &[u8]| {
    for config in [Config::der(), Config::ber()] {
        let mut r = Reader::new(data, config);
        let _ = SignedData::decode(&mut r);

        let mut r = Reader::new(data, config);
        let _ = EnvelopedData::decode(&mut r);

        let mut r = Reader::new(data, config);
        let _ = DigestedData::decode(&mut r);

        let mut r = Reader::new(data, config);
        let _ = EncryptedData::decode(&mut r);

        let mut r = Reader::new(data, config);
        let _ = SignerInfo::decode(&mut r);

        let mut r = Reader::new(data, config);
        let _ = RecipientInfo::decode(&mut r);
    }

    // Whole-buffer strict-DER entry points.
    let _ = tpt_asn1_cms::content_info::decode(data);

    // If the input decodes as a valid ContentInfo, decode its inner content too.
    if let Ok(ci) = ContentInfo::decode(&mut Reader::new(data, Config::der())) {
        let _ = ci.decode_content::<SignedData<'_>>();
        let _ = ci.decode_content::<EnvelopedData<'_>>();
        let _ = ci.decode_content::<DigestedData<'_>>();
        let _ = ci.decode_content::<EncryptedData<'_>>();
    }
});