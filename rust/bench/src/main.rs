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

use floe::{Result, FloeCryptor, FloeEncryptor, FloeDecryptor, FloeKey, GCM256_IV256_4K};

use criterion::*;
// use criterion::measurement::*;
use criterion::profiler::Profiler;

use std::{time::Duration, alloc::{GlobalAlloc, System}, sync::atomic::{AtomicUsize, Ordering}};

use rand::rngs::{OsRng};
use rand::TryRngCore;

use aead::{Aead, Payload, KeyInit};
use aes_gcm::Aes256Gcm;

#[global_allocator]
static ALLOC: ProfilingAllocator<System> = ProfilingAllocator::new(System);

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("GCM256_IV256_4K");
    let _run_time = Duration::from_secs(30);
    
    let mut aad = vec![0u8; 32];
    OsRng.try_fill_bytes(&mut aad).unwrap();
    let key = FloeKey::new_random(GCM256_IV256_4K).unwrap();
    let mut raw_gcm_key = vec![0u8; 32];
    OsRng.try_fill_bytes(&mut raw_gcm_key).unwrap();
    let gcm_key = Aes256Gcm::new_from_slice(&raw_gcm_key).unwrap();
    // let pt_lengths = [1024_usize, 2048, 4096, 8192, 1024*16, 1024*128, 1024*1024, 1024*1024*2, 1024*1024*16];
    let pt_lengths = [1024_usize*1024*16];
    // group.warm_up_time(_run_time);
    // group.measurement_time(_run_time);
    for pt_len in pt_lengths {
        let mut pt = vec![0u8; pt_len];
        OsRng.try_fill_bytes(&mut pt).unwrap();
        group.throughput(Throughput::Bytes(pt_len as u64));
        let ct = floe_encrypt(&pt, &aad, &key).unwrap();
        group.bench_function(format!("Encrypt {}", pt_len), |b| b.iter(|| floe_encrypt(&pt, &aad, &key)));
        group.bench_function(format!("Decrypt {}", pt_len), |b| b.iter(|| floe_decrypt(&ct, &aad, &key)));
    }
    group.finish();
    let mut gcm_group = c.benchmark_group("GCM-256");
    // gcm_group.warm_up_time(_run_time);
    // gcm_group.measurement_time(_run_time);
    for pt_len in pt_lengths {
        let mut pt = vec![0u8; pt_len];
        OsRng.try_fill_bytes(&mut pt).unwrap();
        gcm_group.throughput(Throughput::Bytes(pt_len as u64));
        let ct = gcm_encrypt(&pt, &aad, &gcm_key).unwrap();
        gcm_group.bench_function(format!("Encrypt {}", pt_len), |b| b.iter(|| gcm_encrypt(&pt, &aad, &gcm_key)));
        gcm_group.bench_function(format!("Decrypt {}", pt_len), |b| b.iter(|| gcm_decrypt(&ct, &aad, &gcm_key)));
    }
    gcm_group.finish();
}

pub fn heap_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("GCM256_IV256_4K");
    let _run_time = Duration::from_secs(30);
    
    let mut aad = vec![0u8; 32];
    OsRng.try_fill_bytes(&mut aad).unwrap();
    let key = FloeKey::new_random(GCM256_IV256_4K).unwrap();
    let mut raw_gcm_key = vec![0u8; 32];
    OsRng.try_fill_bytes(&mut raw_gcm_key).unwrap();
    let gcm_key = Aes256Gcm::new_from_slice(&raw_gcm_key).unwrap();
    let pt_lengths = [1024_usize]; //, 2048, 4096, 8192, ];// 1024*16, 1024*128, 1024*1024]; //, 1024*1024*2, 1024*1024*16];
    // group.warm_up_time(_run_time);
    // group.measurement_time(_run_time);
    for pt_len in pt_lengths {
        let mut pt = vec![0u8; pt_len];
        OsRng.try_fill_bytes(&mut pt).unwrap();
        // group.throughput(Throughput::Bytes(pt_len as u64));
        let ct = floe_encrypt(&pt, &aad, &key).unwrap();
        group.bench_function(format!("Encrypt {}", pt_len), |b| b.iter(|| floe_encrypt(&pt, &aad, &key)));
        group.bench_function(format!("Decrypt {}", pt_len), |b| b.iter(|| floe_decrypt(&ct, &aad, &key)));
    }
    group.finish();
    let mut gcm_group = c.benchmark_group("GCM-256");
    // gcm_group.warm_up_time(_run_time);
    // gcm_group.measurement_time(_run_time);
    for pt_len in pt_lengths {
        let mut pt = vec![0u8; pt_len];
        OsRng.try_fill_bytes(&mut pt).unwrap();
        // gcm_group.throughput(Throughput::Bytes(pt_len as u64));
        let ct = gcm_encrypt(&pt, &aad, &gcm_key).unwrap();
        gcm_group.bench_function(format!("Encrypt {}", pt_len), |b| b.iter(|| gcm_encrypt(&pt, &aad, &gcm_key)));
        gcm_group.bench_function(format!("Decrypt {}", pt_len), |b| b.iter(|| gcm_decrypt(&ct, &aad, &gcm_key)));
    }
    gcm_group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_group!(
    name = mem_benches;
    config = Criterion::default().with_profiler(MemoryProfiler);
    targets = criterion_benchmark
);
criterion_main!(mem_benches);


fn floe_encrypt(
    pt: &[u8],
    aad: &[u8],
    key: &FloeKey
) -> Result<Vec<u8>> {
    let mut encryptor = FloeEncryptor::new(key, aad)?;

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
    Ok(ct)
}

fn floe_decrypt(
    ct: &[u8],
    aad: &[u8],
    key: &FloeKey
) -> Result<()> {
    let mut decryptor = FloeDecryptor::new(key, aad, ct)?;
    let mut pt_segment = vec![0u8; decryptor.get_output_size()];

    for segment in ct[key.get_parameters().get_header_length()..].chunks(decryptor.get_input_size())
    {
        if segment.len() == decryptor.get_input_size() {
            decryptor.process_segment(segment, &mut pt_segment)?;
        } else {
            decryptor.process_last_segment(segment, &mut pt_segment)?;
        }
    }
    decryptor.finish()
}

fn gcm_encrypt(
    pt: &[u8],
    aad: &[u8],
    key: &Aes256Gcm
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut nonce).unwrap();

    let payload = Payload { msg: pt, aad };
    let mut ct = vec![];
    ct.extend(&nonce);
    ct.extend(key.encrypt((&nonce).into(), payload)?);
    Ok(ct)
}

fn gcm_decrypt(
    ct: &[u8],
    aad: &[u8],
    key: &Aes256Gcm
) -> Result<()> {
    let nonce = &ct[0..12];
    let payload = Payload { msg: &ct[12..], aad };
    key.decrypt(nonce.into(), payload)?;
    Ok(())
}

struct ProfilingAllocator<T: GlobalAlloc> {
    delegate: T,
    count: AtomicUsize
}

impl<T: GlobalAlloc> ProfilingAllocator<T> {
    pub const fn new(delegate: T) -> Self {
        Self {
            delegate,
            count: AtomicUsize::new(0)
        }
    }

    pub fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    pub fn clear(&self) {
        self.count.store(0, Ordering::SeqCst);
    }
}


unsafe impl<T: GlobalAlloc> GlobalAlloc for ProfilingAllocator<T> {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        self.count.fetch_add(layout.size(), Ordering::SeqCst);
        unsafe {
            self.delegate.alloc(layout)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        unsafe{
        self.delegate.dealloc(ptr, layout);
    }
    }
}

struct MemoryProfiler;

impl Profiler for MemoryProfiler {
    fn start_profiling(&mut self, _: &str, _: &std::path::Path) {
        ALLOC.clear();
    }

    fn stop_profiling(&mut self, _: &str, _: &std::path::Path) {
        let size = ALLOC.count() / 1024;
        println!("; allocated {} KiB <<<<<<<<<<<<<<<<<<<<<<", size);
    }
}