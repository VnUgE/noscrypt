# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- **Breaking** `NCValidateSecretKey()` retruns NC_SUCCESS instead of 1.
- Builds using OpenSSL as a crypto backend no longer require the monocypher dependency.

### Removed

- NCContext structure defintion.
- Internal headers from the public include directory.

[unreleased]: https://github.com/VnUgE/noscrypt/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/VnUgE/noscrypt/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/VnUgE/noscrypt/compare/v0.1.0...v0.1.1
