# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3-beta] - 2024-08-6

### Added
- Utilities sidecar library for easy note encryption (noscryptutil.h)
- Utilities for padding calculations
- Prints the name of the configured crypto backend during build
- Many internal hardening improvments (span pass-by-value, span validation functions)
- `NCEncryptionGetIvSize()` function to determine the size of the IV for a chosen encryption spec (nip04 or nip44)

### Fixed
- OpenSSL EVP incorrect cipher initialization vector
- OpenSSL HKDF incorrect key derivation when switching to EVP api
- Some missing calling convention macros for public api functions

### Changed
- Updated libsecp256k1 to v0.5.1
- Updated OpenSSL to v3.3.1
- Converted `NCToSecKey()` and `NCToPubKey()` to a explicitly named macros
- Converted error code helper functions from header-only functions to standard api
- Added helper functions to alter the `NCEncryptionArgs` api. Altering fields directly is now deprecated.
- Public API visibility for non-Windows platforms now defaults to `extern`
- **Breaking:** Changed the `nonce32` and `hmacKeyOut32` properties of the `NCEncryptionArgs` struct to `nonceData` and `keyData` respectively. ABI is still compatible, but API has changed. Again mutating this structure manually is now deprecated.
- Unified some API naming conventions for better consistency

### Removed
- `NC_ENCRYPTION_NONCE_SIZE` macro for better forward compatability
- `NC_NIP04_AES_IV_SIZE` macro for better forward compatability 

## [0.1.2] - 2024-05-29

### Added

- `NCGetSharedContext()` to get a process-wide shared context.
- C++ extern wrappers noscrypt.h public api
- Integrated test exe to cmake ctest

### Fixed

- Potential memory leak for openssl evp contexts during error conditions.
- mbedtls dependency compilation when using fetch for release builds.
- fPIC errors for libsecp256k1.

### Changed

- Update libsecp256k1 to v0.5.0.
- **Breaking:** `NCValidateSecretKey()` retruns NC_SUCCESS instead of 1.
- Builds using OpenSSL as a crypto backend no longer require the monocypher dependency.

### Removed

- NCContext structure defintion.
- Internal headers from the public include directory.

[unreleased]: https://github.com/VnUgE/noscrypt/compare/v0.1.3-beta...HEAD
[0.1.3-beta]: https://github.com/VnUgE/noscrypt/compare/v0.1.2...v0.1.3-beta
[0.1.2]: https://github.com/VnUgE/noscrypt/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/VnUgE/noscrypt/compare/v0.1.0...v0.1.1
