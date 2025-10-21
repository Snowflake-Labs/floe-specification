# FLOE Specification

Fast Lightweight Online Encryption (FLOE) is a secure random access authenticated encryption (raAE) scheme as defined in a soon to be published paper.
All raAE schemes are also nOAE2 secure as defined by [HRRV15](https://eprint.iacr.org/2015/189).
FLOE is inspired heavily by the work in HRRV15 and others.
FLOE can be thought of as a family of algorithms, each specified by a set a parameters.
(This is similar to how [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) is defined.)

This specification defined four *public* functions for the random access case (raAE): `startEncryption`, `encyptSegment` and their decryption equivalents.
For usecases that do not require random access, we strongly recommend that instead of exposing `encryptSegment` and `decryptSegment` that you expose the sequention/online equivalents of them:
`encryptOnlineSegment`, `encryptLastSegment`, and their decryption equivalents.
These four methods (along with the two `start` functions) support the nOAE2/online/sequential use case and are harder to misuse.
An implementation may not choose to expose those methods directly to callers but instead implement its own API on top of the "official" FLOE functions.

## Terminology

Both FLOE and its internal AEAD use data of similar types (keys, IVs, AADs, etc.).
In all cases we explicitly specify which we're referring to.

All lengths are in bytes unless otherwise specified.

## Parameters

FLOE is parameterized by four values:

- `AEAD`  
  Used to actually encrypt the data
- `KDF`  
  Used to derive keys for the AEAD and other values
- `FLOE_IV_LEN`
  The length, in bytes, of the FLOE IV  
- `ENC_SEG_LEN`  
  The length of a single segment of a FLOE ciphertext.
  It is necessarily longer than the associated plaintext data for a segment.

These parameters then define a large number of derived parameters.

Currently, only `ENC_SEG_LEN` can take different values.
The other three parameters are *fixed* as follows:

- **AEAD:** AES-GCM-256
- **KDF:** HKDF-EXPAND-SHA-384
- **FLOE_IV_LEN:** 32

### Derived Parameters

These parameters are all defined implicitly by selection of one of the main parameters listed above.

|  `AEAD` | `AEAD_ID` | `AEAD_KEY_LEN` | `AEAD_IV_LEN` | `AEAD_TAG_LEN` | `AEAD_ROTATION_MASK` | `AEAD_MAX_SEGMENTS` |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| AES-GCM-256 | 0 | 32 | 12 | 16 | 20 | 2<sup>40</sup> |

- `AEAD_ID`  
  An integer representing the selected AEAD
- `AEAD_KEY_LEN`  
  The length, in bytes, of the key expected by the AEAD
- `AEAD_IV_LEN`  
  The length, in bytes, of the IV expected by the AEAD
- `AEAD_TAG_LEN`  
  The length, in bytes, of the tag returned by the AEAD
- `AEAD_ROTATION_MASK`
  A non-negative integer value designating how many segments can be encrypted before deriving a new encryption key.
  Specifically, 2<sup>`AEAD_ROTATION_MASK`</sup> segments are encrypted under a single key.
- `AEAD_MAX_SEGMENTS`  
  The maximum number of segments in a FLOE ciphertext which uses the selected AEAD.
  Implementations may place lower limits on what they are willing to produce or accept.

| `KDF` | `KDF_ID` | `KDF_LEN` |
| :---- | :---- | :---- |
| HKDF-EXPAND-SHA-384 | 0 | 48 |

- `KDF_ID`  
  An integer representing the selected KDF
- `KDF_INTERMEDIATE_KEY_LEN`  
  An integer representing the length, in bytes, of the key to derive for use as a KDF key

## FLOE Ciphertext Layout

A FLOE ciphertext consists of two parts: `FLOE_HEADER` and `FLOE_BODY`

The `FLOE_HEADER` consists of three parts:

1. Parameter Information: 10 bytes  
   `PARAM_ENCODE(params)`  
2. IV: `FLOE_IV_LEN` bytes  
3. Header tag: `32` bytes  
   Output of `FLOE_KDF(key, iv, aad, "HEADER_TAG:", 32)`

The `FLOE_BODY` consists of zero or more internal segments and a single final segment.
Each internal segment is exactly `ENC_SEG_LEN` bytes long.
The final segment may be between `AEAD_IV_LEN + AEAD_TAG_LEN + 4` and `ENC_SEG_LEN` (inclusive) bytes long.

A segment consists of four pieces:

1. A final length value encoded with `I2BE(*, 4)`  
   This value is max (`0xFFFFFFFF`) for all non-final segments and is the *total encrypted segment length* of the last segment.
   This means that it includes the lengths of the: length value, AEAD IV, AEAD ciphertext, and AEAD tag
2. A random IV of `AEAD_IV_LEN` bytes  
3. A ciphertext encrypted with the AEAD.
  (The length is implicit and can be derived from context.)  
4. The tag of `AEAD_TAG_LEN` bytes

## Key Generation

FLOE keys MUST be of equal length to `AEAD_KEY_LEN`.
They MUST meet the standard security requirements for symmetric keys of that length. ([NIST SP 800-133](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-133r2.pdf), Section 6\)

## Implementation

### External Functions

These are functions that are not specific to FLOE and are likely provided by external or standard libraries.
While their behavior is defined, their implementation is out of scope for this specification.

- `I2BE(val, len) -> bytes`  
  Encodes `val` as an unsigned big-endian value of exactly `len` bytes.
  It will never be called with a value out of range.
- `RND(len) -> bytes`  
  Returns `len` cryptographically random bytes.
- `AEAD_ENC(key, data, aad) -> (iv, ct, tag)`  
  The encryption function as defined by the AEAD.
  Internal IV generation is as defined by the algorithm, and thus generally equivalent to `iv = RND(AEAD_IV_LEN)`.
- `AEAD_DEC(key, iv, ct, aad, tag) -> pt`  
  The decryption function as defined by the AEAD.
  On failure **throws** an appropriate exception.
- `KDF(prk, info, len) -> bytes`  
  The KDF as defined by `KDF`.
- `len(a) -> int`  
  Returns the length of byte-string `a`.
- `a || b -> bytes`  
  Concatenation. Returns the concatenation of byte strings `a` and `b`.
- `assert(val)`  
  If `val` is false, then **throws** an appropriate exception. This exception is permitted to be meaningful and indicate where and how the failed assertion occurred.
- `ctEq(val1, val2)`  
  Checks `val1` and `val2` for equality *in constant time*. Returns `true` or `false` as appropriate.
- `throw(msg)`  
  Throws an exception with the specified message.

### Internal Functions

These are FLOE-specific functions that may need to be implemented.
None of these are exposed to callers.
Depending on how you implement the code, these may be inlined, provided by the programming language, or otherwise refactored.

- `SPLIT(data, prefix_len, suffix_len) -> (prefix, body, suffix)`  
    Takes the byte string `data` and splits it into three parts `prefix`, `body`, and `suffix` such that:  
  - `prefix` is exactly `prefix_len` bytes long  
  - `suffix` is exactly `suffix_len` bytes long  
  - `prefix || body || suffix = data`  
  - It aborts if the above is not possible
- `PARAM_ENCODE(params) -> bytes`  
  Defined as `I2BE(AEAD_ID, 1) || I2BE(HASH_ID, 1) || I2BE(ENC_SEG_LEN, 4) || I2BE(FLOE_IV_LEN, 4)`.
  The output is always exactly 10 bytes long.
- `FLOE_KDF(key, iv, aad, purpose, len) -> byte[len]`  
  Defined as `KDF(key, PARAM_ENCODE(params) || iv || purpose || aad, len)` where `params` is implicit from the context.
- `MASK(val, bits) -> int`  
  Returns `val` with bits of its low-order bits masked to `0` values.
- `DERIVE_KEY(key, iv, aad, segmentNumber) -> key`  
  Defined as `FLOE_KDF(key, iv, aad, "DEK:" || I2BE(MASK(segmentNumber, AEAD_ROTATION_MASK), 8), AEAD_KEY_LEN)`.
  This value may be internally cached by implementations.

### Semi-Public Functions (Random Access)

FLOE can be defined in terms of four functions which support random access (as per the raAE definition).
Generally these methods should be internal implementation details because they are not necessarily safe for direct access by developers.
However, depending on the specific use-case, these APIs may be the correct level of abstraction to be made public.
They are more challenging to use correctly because they no longer protect the developer from a number of mistakes:

- They do not enforce that all required segments are encrypted.  
- They do not enforce that `encryptSegment` is never called multiple times for a given position/terminal indicator
- They do not prevent encryption of segments with higher positions than the terminal segment
- If a decryptor does not already know the correct length of the ciphertext (i.e., maximum position) then it is difficult for them to distiguish truncation versus just trying to read past the end.
- If an adversary can cause a decryptor to attempt decryption of a valid segment with the incorrect position/terminal indicator, then FLOE loses commitment properties.

In practice, this means that these API should likely not be exposed directly to developers but instead be use to construct higher-level (safe) APIs.
For example, a developer of a client-side encryption library for cloud block storage, might choose to use FLOE.
While they could simply use the online APIs above to stream the file to the cloud, using these random access APIs would permit them to spin up a number of threads to encrypt (and possibly upload) segments in parallel.
Similarly, they could use these random access APIs to do random reads of the uploaded object.

```txt
startEncryption(key, aad) -> (State, Header)
  iv = RND(FLOE_IV_LEN)

  HeaderPrefix = PARAM_ENCODE(params) || iv
  HeaderTag = FLOE_KDF(key, iv, aad, "HEADER_TAG:", 32)
  MessageKey = FLOE_KDF(key, iv, aad, "MESSAGE_KEY:", KDF_LEN)
  Header = HeaderPrefix || HeaderTag

  State = {MessageKey, iv, aad}
  return (State, Header)
```

```txt
startDecryption(key, aad, header) -> State
  EncodedParams = PARAM_ENCODE(params)
  assert(len(header) == FLOE_IV_LEN + len(EncodedParams) + 32)

  (HeaderParams, iv, HeaderTag) = SPLIT(header, len(EncodedParams), 32)
  assert(HeaderParams == EncodedParams)

  ExpectedHeaderTag = FLOE_KDF(key, iv, aad, "HEADER_TAG:")
  if ctEq(ExpectedHeaderTag, HeaderTag) == FALSE: // Must be constant time
    throw("Invalid Header Tag")

  MessageKey = FLOE_KDF(key, iv, aad, "MESSAGE_KEY:", KDF_LEN)
  State = {MessageKey, iv, aad}
  return State
```

```txt
encryptSegment(State, plaintext, position, is_final) -> (State, EncryptedSegment)
  assert(len(plaintext) >= 0)
  if is_final:
    assert(len(plaintext) <= ENC_SEG_LEN - AEAD_IV_LEN - AEAD_TAG_LEN - 4)
    aad_tail = 0x01
  else:
    assert(len(plaintext) == ENC_SEG_LEN - AEAD_IV_LEN - AEAD_TAG_LEN - 4)
    aad_tail = 0x00

  aead_key = DERIVE_KEY(state.MessageKey, state.iv, state.aad, position) 
  aead_iv = RND(AEAD_IV_LEN)
  aead_aad = I2BE(position, 8) || aad_tail
  (aead_ciphertext, tag) = AEAD_ENC(aead_key, aead_iv, plaintext, aead_aad)

  if is_final:
    FinalSegementLength = 4 + AEAD_IV_LEN + len(aead_ciphertext) + AEAD_TAG_LEN
    segment_header = I2BE(FinalSegementLength, 4) || aead_iv || aead_ciphertext || tag
  else:
    segment_header = 0xFFFFFFFF

  EncryptedSegment = segment_header || aead_iv || aead_ciphertext || tag
  return (State, EncryptedSegment)
```

```txt
decryptSegment(State, EncryptedSegment, position, is_final) -> (State, Plaintext)
  if is_final:
    assert(len(EncryptedSegment) >= AEAD_IV_LEN + AEAD_TAG_LEN + 4)
    assert(len(EncryptedSegment) <= ENC_SEG_LEN)
    assert(BE2I(EncryptedSegment[:4]) == len(EncryptedSegment))
    aad_tail = 0x01
  else:
    assert(len(EncryptedSegment) == ENC_SEG_LEN)
    assert(BE2I(EncryptedSegment[:4]) == 0xFFFFFFFF)
    aad_tail = 0x00

  aead_key = DERIVE_KEY(state.MessageKey, state.iv, state.aad, position)
  (aead_iv, aead_ciphertext, tag) = SPLIT(EncryptedSegment[4:], AEAD_IV_LEN, AEAD_TAG_LEN)
  aead_aad = I2BE(position, 8) || aad_tail

  // Next line will throw if AEAD decryption fails
  Plaintext = AEAD_DEC(aead_key, aead_iv, aead_ciphertext, aead_aad)

  return (State, Plaintext)
```

### Public Streaming/Online Function

These functions provide a safe interface to FLOE and are the recommended public API.

```txt
startOnlineEncryption(key, aad) -> (State, Header)
  (State, Header) = startEncryption(key, aad)
  State.Counter = 0
  State.Closed = False
  return (State, Header)
```

```txt
encryptOnlineSegment(State, plaintext) -> (State, EncryptedSegment)
  assert(State.Closed == False)
  assert(State.Counter != AEAD_MAX_SEGMENTS - 1)

  (State, EncryptedSegment) = encryptSegment(State, plaintext, State.Counter, False)

  State.Counter++
  return (State, EncryptedSegment)
```

```txt
encryptLastSegment(State, plaintext) -> EncryptedSegment
  assert(State.Closed == False)
  
  (State, EncryptedSegment) = encryptSegment(State, plaintext, State.Counter, True)

  State.Closed = True
  return EncryptedSegment
```

```txt
startOnlineDecryption(key, aad, header) -> State
  State = startDecryption(key, aad, header)
  State.Counter = 0
  State.Closed = False
  return State
```

```txt
decryptOnlineSegment(State, EncryptedSegment) -> (State, Plaintext)
  assert(State.Closed == False)
  assert(State.Counter != AEAD_MAX_SEGMENTS - 1)

  (State, Plaintext) = decryptSegment(State, EncryptedSegment, State.Counter, False)

  State.Counter++
  return (State, Plaintext)
```

```txt
decryptLastSegment(State, EncryptedSegment) -> Plaintext
  assert(State.Closed == False)

  (State, Plaintext) = decryptSegment(State, EncryptedSegment, State.Counter, True)

  State.Closed = True
  return Plaintext
```

#### Auxiliary Public Online Decryption Function

This is a helper function which makes the FLOE API nicer to use but has no impact on its correctness or security properties.

```txt
decryptAnyOnlineSegment(State, EncryptedSegment) -> (State, Plaintext)
  if BE2I(EncryptedSegment[:4]) == 0xFFFFFFFF:
    return decryptSegment(State, EncryptedSegment)
  else:
    return decryptLastSegment(State, EncryptedSegment)
```

## License

Copyright (c) Snowflake Inc. All rights reserved.
Licensed under the Apache 2.0 license.
