# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.11]

### Added
- Added nuget.config to the root of the repository for easier access to vnlib packages.

### Updated
- Updated `mbedTLS` to version `3.6.4`
- Updated openSSL headers to version `3.5.1`
- Updated vnlib.core to version `0.1.2-rc.6`

### Changed
- Building no longer requires manually adding vnlib release nuget feed to your package sources.

## [0.1.10]

### Added
- CI builds are now versioned using Major.Minor.Patch.BuildNumber format in reflection with the new semver Major.Minor.Patch-Meta.BuildNumber versioning scheme on the website.

### Changed
- Replaced deprecated Windows cryptographic APIs with modern equivalents in `test.c`.
- Adjusted GitVersion configuration to use `ContinuousDelivery` mode.
- Improved task management and build configurations in `Taskfile.yaml` and `Module.Taskfile.yaml`.
- CMakePresets were updated/adjusted for easier development, still not considered stable though. Users should still use Taskfile for building.

### Updated
- `mbedTLS` to version `3.6.3.1` (no code changes, build-change release).
- `.NET` dependencies in the `VNLib.Utils.Cryptography.Noscrypt` wrapper to `0.1.2-rc.1`.

### Fixed
- Corrected typos and improved comments in `CMakeLists.txt`.

## [0.1.9]

### Added
- C# .NET 8.0 library wrapper for noscrypt
- Full NIP44 vector testing for encryption

### Changed
- **Deprecated** `NC_NIP04_IV_SIZE` and `NC_NIP44_IV_SIZE` macros. Use `NCEncryptionGetIvSize()` at runtime instead.
- **Breaking** Renamed `nonceData` field in `NCEncryptionArgs` to `ivData` for consistency with public-facing terminology. ABI is still compatible, but API has changed. 
This is a breaking change for any code that directly mutates the `NCEncryptionArgs` struct, which is discouraged.

### Updated
- Updated mbedtls to v3.6.3, see [release notes](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-3.6.3) for all security fixes 
- Updated OpenSSL headers to v3.5.0 

## [0.1.8]

### Added
- Vendored modified copies of libsecp256k1 and mbedtls
- Tests for nip04 padding schemes
- More internal struct initialization

### Changed
- Added `const` to `NCVerifyMac()` and `NCVerifyMacEx()` args parameter. Maybe a breaking change on some platforms.
- WSL is no longer required on Windows systems when compiling mbedtls variant 
- A globally installed libsecp256k1 library is preferred over the vendored source code, and dynamically linked. If not found, falls back to vendored source code.
- Internal move to `span_t` for better memory safety
- Enabled `-Werror` for all gcc builds
- Added extra gcc warnings for better code quality
 
### Updated
- Updated monocypher to v4.0.2
- Updated openssl headers to match v3.4.1 (no header changes were found in diff)
- `NCUtilGetEncryptionPaddedSize()` and `NCUtilGetEncryptionBufferSize()` now correctly pad for AES nip04 messages

## [0.1.7]
 
### Added
- Initialize stack buffers to zero before use in noscrypt.c

### Fixed
- `NCVerifyDigest()` now correctly returns `E_OPERATION_FAILED` when signature verification fails

## [0.1.6]

### Added
- Security policy for the module
- Valgrind memory checking during unit testing
- Fully automated integration testing for Windows and Linux deployments
- Automated tests for all crypto backends (MbedTLS, OpenSSL, BCrypt)
  
### Fixed
- [#9](https://www.vaughnnugent.com/resources/software/modules/noscrypt-issues?id=53) - Convert all OpenSSL APIs to use the EVP API and unify its usage. Also fixes some detected memory leaks that were undocumented.

### Changed
- Updated OpenSSL to v3.4.0
- Updated MbedTLS to v3.6.2
- Updated libsecp256k1 to v0.6.0
- `NCUtilGetEncryptionPaddedSize()` no longer validates input sizes against nip44 message sizes [(correct behavior)](https://github.com/paulmillr/nip44/issues/21)
- Now requires 32-bit minimum CPU word size when using OpenSSL as a crypto backend

### Removed
- **Breaking:** Noscrypt no longer builds and links against mbedtls using CMake. You may manually install and link against mbedtls, or use the Taskfile to do it for you.
- `NC_FETCH_MBEDTLS` CMake directive was removed, see previous point.

## [0.1.5]

### Added
- `NCUtilContextAlloc()` and `NCUtilContextFree()` utilities for dynamic library context allocation

### Changed
- Public and Secret key structure definition names have been correctly namespaced __(no breaking changes)__  

## [0.1.4]

### Fixed
- [#8](https://www.vaughnnugent.com/resources/software/modules/noscrypt-issues?id=51) - an issue where nip44 encryption fails on reusable cipher instances

## [0.1.3]

### Added
- Utilities sidecar library for easy note encryption [(noscryptutil.h)](https://github.com/VnUgE/noscrypt/blob/v0.1.3/include/noscryptutil.h)
- Utilities for padding calculations
- Prints the name of the configured crypto backend during build
- Many internal hardening improvements (span pass-by-value, span validation functions)
- `NCEncryptionGetIvSize()` function to determine the size of the IV for a chosen encryption spec (nip04 or nip44)

### Fixed
- OpenSSL EVP incorrect cipher initialization vector
- OpenSSL HKDF incorrect key derivation when switching to EVP API
- Some missing calling convention macros for public API functions

### Changed
- Updated libsecp256k1 to v0.5.1
- Updated OpenSSL to v3.3.1
- Converted `NCToSecKey()` and `NCToPubKey()` to explicitly named macros
- Converted error code helper functions from header-only functions to standard API
- Added helper functions to alter the `NCEncryptionArgs` API. Altering fields directly is now deprecated.
- Public API visibility for non-Windows platforms now defaults to `extern`
- **Breaking:** Changed the `nonce32` and `hmacKeyOut32` properties of the `NCEncryptionArgs` struct to `nonceData` and `keyData` respectively. ABI is still compatible, but API has changed. Again, mutating this structure manually is now deprecated.
- Unified some API naming conventions for better consistency

### Removed
- `NC_ENCRYPTION_NONCE_SIZE` macro for better forward compatibility
- `NC_NIP04_AES_IV_SIZE` macro for better forward compatibility 

## [0.1.2]

### Added

- `NCGetSharedContext()` to get a process-wide shared context.
- C++ extern wrappers for noscrypt.h public API
- Integrated test exe to CMake ctest

### Fixed

- Potential memory leak for OpenSSL EVP contexts during error conditions.
- mbedtls dependency compilation when using fetch for release builds.
- fPIC errors for libsecp256k1.

### Changed

- Updated libsecp256k1 to v0.5.0.
- **Breaking:** `NCValidateSecretKey()` returns NC_SUCCESS instead of 1.
- Builds using OpenSSL as a crypto backend no longer require the monocypher dependency.

### Removed

- NCContext structure definition.
- Internal headers from the public include directory.

[unreleased]: https://github.com/VnUgE/noscrypt/compare/v0.1.11...HEAD
[0.1.11]: https://github.com/VnUgE/noscrypt/compare/v0.1.10...v0.1.11
[0.1.10]: https://github.com/VnUgE/noscrypt/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/VnUgE/noscrypt/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/VnUgE/noscrypt/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/VnUgE/noscrypt/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/VnUgE/noscrypt/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/VnUgE/noscrypt/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/VnUgE/noscrypt/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/VnUgE/noscrypt/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/VnUgE/noscrypt/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/VnUgE/noscrypt/compare/v0.1.0...v0.1.1
