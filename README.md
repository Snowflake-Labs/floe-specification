# Fast Lightweight Online Encryption (FLOE)

Fast Lightweight Online Encryption (FLOE) is a cryptographic construction designed by [Snowflake](https://www.snowflake.com/) for the encryption of large files.
This repository contains the [public specification](spec/README.md) of FLOE, known answer tests (in `kats/`), and reference code in several different languages.
The source code is all released under the Apache 2.0 license.

If any security issues are found with FLOE or the implementations, please contact us at [security@snowflake.com](mailto:security@snowflake.com).

## Motivation

Snowflake, like many other companies, needs to works with very large files containing sensitive data.
Encryption is one of many tools that we use to protect this data and fulfill our promises to our customers.
Unfortunately, we determined that there are no good existing cryptographic constructions for the symmetric encryption of multi-gigabyte files.

All existing constructions fail one or more of our three primary requirements:

- Authenticated encryption  
  Essentially, this means that an attacker must not be able to cause incorrect data to be decrypted.
- Bounded memory  
  Regardless of the data size, an implementation must be able to successfully encrypt/decrypt it using a constant amount of memory.
- FIPS Compatible  
  The construction must be able to be implemented using nothing more than FIPS validated cryptographic modules in fully compliant ways.

The first of these requirements is a basic requirement of any modern cryptographic construction.
However, the need to validate the data upon decryption causes most constructions (such as AES-GCM) to need to hold the entire plaintext in memory before releasing it to the caller.
In the case of a 2 gigabyte file, this means you are spending 2 gigabytes of memory just to hold data which you might normally be able to handle in a streaming manner.
(For example, if you are downloading and decrypting a file from the network as part of writing it to local storage, you should not need to hold the whole file in memory at once. Instead, you should be able to stream it while only maintaining a small buffer of active data.)
The "streaming" property described above is what is known technically as "online encryption."

Once we determined that there we no existing solutions, we came up with a list of additional requirements for FLOE.
While none of these requirements would have prevented us from adopting an existing solution,
if we need to build something new anyway, we want the result to be better in as many ways as possible.

- Useful error messages  
  Many cryptographic constructions only tell callers that something has failed and cannot give greater insight into what went wrong.
  This can make encrypted systems very challenging to debug.
  FLOE gives (safe) useful error messages when decrypting which help with debugging.
- Commitment  
  Some cryptographic constructions allow attackers (who know the keys) to craft a single ciphertext which can be decrypted by multiple keys.
  In certain limited protocols this can lead to other protocol-specific problems.
  Because FLOE is committing, an attacker cannot do this.
- Random access reads  
  We don't always want to decrypt an entire file in order from the beginning to the end.
  Sometimes we want to read and decrypt arbitrary subsections of it.
  FLOE must allow us to decrypt arbitrary subsections (subject to some reasonable overhead) while still giving us the same security properties for all read data we'd get for the entire file.
- Easy to implement safely  
  Implementation flaws in cryptographic code are often more significant than algorithmic flaws.
  FLOE is designed to be easy to safely implement given nothing more than SHA-256 and AES-GCM.
- Misuse resistant
  Many otherwise secure cryptographic algorithms break when misused.
  For symmetric encryption, this is primarily through IV reuse, key wearout, or key misuse.
  FLOE is designed to defend against all three of these issues.
  FLOE does not take in an external IV.
  Internal KDFs mean that a single key can be used to encrypt at least **INSERT_VALUE** messages before cryptographic wearout occurs.
  The internal KDF also makes it highly unlikely that even if a key were to be used with FLOE and another cryptographic algorithm that the security of data *encrypted with FLOE* would remain intact.
- Externally reviewed  
  Any cryptographic proposal must be carefully reviewed by numerous experts.
  In addition to our in house cryptographers, we also consulted with experts from a major university.
  The paper has not been published yet but will be linked here as soon as it is available.
  As of now, no security issues have been found with the design.

## Building

All code in this repository is built using [Bazel](https://bazel.build/) and can be built with `bazel build //...`.
Tests can be run with `bazel test //...`.
Builds and tests for a specific language can be run by specifying the language: `bazel build //java/...`, `bazel build //cpp/...`, etc.

## Disclaimers

The code contained within this repository is *teaching* code and is intended to demonstrate how to implement FLOE in a language of your choice.
The different languages were implemented using slightly different strategies to have the results be more appropriate to each language and also demonstrate a variety of techniques you might choose to use in *your* implementation.

While we have taken efforts to ensure that this code is bug-free, we make no warranties as to its fit for any purpose, including production deployment.
You may find that the code in this repository meets your requirements with minimal modifications.
If so, great!
If not, modify it or build your own.

It is our hope that as FLOE becomes adopted by industry, multiple production ready packages will be made available for consumption.
Please let us know about them via a issue or pull request so that we can evaluate it and decide if we want to add it to our list.

## Other implementations

| Name | Language(s) | Maintainer | Notes |
|-|-|-|-|
| [floe](https://github.com/snowflakedb/floe) | Java | Snowflake | Implementation used by Snowflake for client side code

## License

Copyright (c) Snowflake Inc. All rights reserved.
Licensed under the Apache 2.0 license.
