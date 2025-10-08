// Copyright 2025 Snowflake Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{fs::OpenOptions, io::Write};

use aead::{OsRng, rand_core::RngCore};

use crate::{
    Error, FloeAead, FloeCryptor, FloeDecryptor, FloeEncryptor, FloeHash, FloeKey,
    FloeParameterSpec, GCM256_IV256_1M, GCM256_IV256_4K, Result,
};

const AAD: &[u8] = b"This is AAD";

fn encrypt_random(
    params: FloeParameterSpec,
    len: usize,
    random_key: bool,
) -> Result<(Vec<u8>, Vec<u8>, FloeKey)> {
    let mut pt = vec![0u8; len];
    OsRng.fill_bytes(&mut pt);

    let key = if random_key {
        FloeKey::new_random(params)?
    } else {
        FloeKey::new(&[0u8; 32], params)?
    };

    let mut encryptor = FloeEncryptor::new(&key, AAD)?;

    let mut ct = encryptor.get_header().to_vec();
    let mut ct_segment = vec![0u8; encryptor.get_output_size()];
    for segment in pt.chunks(encryptor.get_input_size()) {
        if segment.len() == encryptor.get_input_size() {
            encryptor.process_segment(segment, &mut ct_segment)?;
            ct.extend(&ct_segment);
        } else {
            encryptor.process_last_segment(segment, &mut ct_segment)?;
            ct.extend(&ct_segment[..encryptor.size_of_last_output(segment.len())?]);
        }
    }
    if !encryptor.is_closed() {
        encryptor.process_last_segment(&[], &mut ct_segment)?;
        ct.extend(&ct_segment[..encryptor.size_of_last_output(0)?]);
    }
    encryptor.finish()?;
    Ok((pt, ct, key))
}

fn decrypt_kat(key: &FloeKey, pt: &[u8], ct: &[u8]) -> Result<()> {
    let mut decryptor = FloeDecryptor::new(key, AAD, ct)?;

    let mut decrypted = vec![];
    let mut pt_segment = vec![0u8; decryptor.get_output_size()];

    for segment in ct[key.get_parameters().get_header_length()..].chunks(decryptor.get_input_size())
    {
        if segment.len() == decryptor.get_input_size() {
            decryptor.process_segment(segment, &mut pt_segment)?;
            decrypted.extend(&pt_segment);
        } else {
            decryptor.process_last_segment(segment, &mut pt_segment)?;
            decrypted.extend(&pt_segment[..decryptor.size_of_last_output(segment.len())?]);
        }
    }
    decryptor.finish()?;
    assert_eq!(pt, &decrypted);
    Ok(())
}

const KAT_LOCATION: &str = "kats";

fn read_hex_file(file_name: &str) -> Result<Vec<u8>> {
    std::fs::read_to_string(file_name)
        .map_err(Error::internal)
        .map(|s| hex::decode(s.trim()).map_err(Error::internal))?
}

#[test]
fn gcm256_4k_empty() -> Result<()> {
    let (pt, ct, key) = encrypt_random(GCM256_IV256_4K, 0, true)?;
    decrypt_kat(&key, &pt, &ct)
}

#[test]
fn gcm256_1m_empty() -> Result<()> {
    let (pt, ct, key) = encrypt_random(GCM256_IV256_1M, 0, true)?;
    decrypt_kat(&key, &pt, &ct)
}

fn test_kat(params: FloeParameterSpec, p_name: &str, name: &str) -> Result<()> {
    let pt_file = format!("{}/{}_{}_pt.txt", KAT_LOCATION, name, p_name);
    let ct_file = format!("{}/{}_{}_ct.txt", KAT_LOCATION, name, p_name);
    let pt = read_hex_file(&pt_file)?;
    let ct = read_hex_file(&ct_file)?;
    let key = FloeKey::new(&[0u8; 32], params)?;
    decrypt_kat(&key, &pt, &ct)
}

#[test]
#[ignore = "generate new KATs"]
fn generate_kats() -> Result<()> {
    let p64 = FloeParameterSpec::new(FloeAead::AesGcm256, FloeHash::Sha384, 64)?;

    let rotation =
        FloeParameterSpec::new_explicit(FloeAead::AesGcm256, FloeHash::Sha384, 40, 32, Some(-4));

    for p in [GCM256_IV256_4K, GCM256_IV256_1M, p64, rotation] {
        let p_name = if p == GCM256_IV256_4K {
            "GCM256_IV256_4K"
        } else if p == GCM256_IV256_1M {
            "GCM256_IV256_1M"
        } else if p == p64 {
            "GCM256_IV256_64"
        } else if p == rotation {
            "rotation"
        } else {
            todo!("Unsupported KAT type")
        };
        let (pt, ct, _) = if p == rotation {
            encrypt_random(p, 10 * p.get_encrypted_segment_length() + 3, false)?
        } else {
            encrypt_random(p, 2 * p.get_encrypted_segment_length() + 3, false)?
        };
        let file_name = format!("{}/rust_{}_pt.txt", KAT_LOCATION, p_name);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_name)
            .map_err(Error::internal)?;
        file.write_all(hex::encode(pt).as_bytes())
            .map_err(Error::internal)?;

        let file_name = format!("{}/rust_{}_ct.txt", KAT_LOCATION, p_name);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_name)
            .map_err(Error::internal)?;
        file.write_all(hex::encode(ct).as_bytes())
            .map_err(Error::internal)?;
    }
    Ok(())
}

#[test]
fn kats() -> Result<()> {
    let p64 = FloeParameterSpec::new(FloeAead::AesGcm256, FloeHash::Sha384, 64)?;

    let rotation =
        FloeParameterSpec::new_explicit(FloeAead::AesGcm256, FloeHash::Sha384, 40, 32, Some(-4));

    for source in ["java", "go", "pub_java", "rust"] {
        for p in [GCM256_IV256_4K, GCM256_IV256_1M, p64, rotation] {
            let p_name = if p == GCM256_IV256_4K {
                "GCM256_IV256_4K"
            } else if p == GCM256_IV256_1M {
                "GCM256_IV256_1M"
            } else if p == p64 {
                "GCM256_IV256_64"
            } else if p == rotation {
                "rotation"
            } else {
                todo!("Unsupported KAT type")
            };
            test_kat(p, p_name, source)?;
        }
    }

    // There are a few Java generated only KATs
    let segment_test_params = FloeParameterSpec::new(FloeAead::AesGcm256, FloeHash::Sha384, 40)?;
    test_kat(segment_test_params, "lastSegAligned", "java")?;
    test_kat(segment_test_params, "lastSegEmpty", "java")?;
    Ok(())
}

#[test]
fn invalid_key_length() -> Result<()> {
    let key = FloeKey::new(&[0u8; 33], GCM256_IV256_1M);
    assert!(key.is_err());
    Ok(())
}