
# noscrypt  

<h4 align="left">
  <a href="https://github.com/VnUgE/noscrypt/blob/master/LICENSE">
    <img src="https://img.shields.io/badge/license-LGPL2.1-green.svg" alt="LGPL2.1" />
  </a>
  <a href="https://www.vaughnnugent.com/Resources/Software/Modules/noscrypt-issues">
    <img src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fwww.vaughnnugent.com%2Fapi%2Fgit%2Fissues%3Fmodule%3Dnoscrypt&query=%24%5B'result'%5D.length&label=all%20issues" alt="Issues"/>
  </a>
  <a href="https://github.com/VnUgE/noscrypt/tags">
    <img src="https://img.shields.io/github/v/tag/vnuge/noscrypt" alt="Latest tag"/>
  </a>
</h4>

*A compact, C90 cross-platform, cryptography library built specifically for nostr*

## What is noscrypt?
A high-level C utility library built specifically for nostr cryptography operations such as those defined in NIP-01, NIP-04 (incomplete), and NIP-44. Noscrypt simplifies key generation, note signing & verification, NIP-44 data encryption for private messages, and much more. Noscrypt has very low dependency requirements with a focus on portability and performance for desktop and progress toward embedded systems.

## API Example
```C
NCValidateSecretKey()
NCGetPublicKey()
NCSignData()
NCVerifyData()
NCEncrypt()
NCDecrypt()
NCComputeMac()
NCVerifyMac()
... extended functions
```

## Motivation
At the time of building this project there were no C-only libraries that exposed functionality for nostr-specific cryptography. It is easy to use the secp256k1 library [incorrectly](https://www.vaughnnugent.com/blog/d9ab8a46cfa8d6bd59cf048fec8d73ffc44f881c). During development of [NVault](https://www.vaughnnugent.com/resources/software/modules/nvault), NIP-44 was released and it became clear that existing libraries were insufficient for proper and safe nostr cryptographic operations. Noscrypt was built from the ground up with a focus on correctness, trusted and tested dependencies, performance, and minimal resource requirements.

### Testing
Testing is and will remain critical to a cryptography library. The goal is to achieve enterprise-level testing and security coverage. There are basic API validation and correctness tests that can be built into the `nctest` executable. Alongside that, a fully automated testing suite is provided using the [C# interop](wrappers/dotnet/VNLib.Utils.Cryptography.Noscrypt/tests/), including validation against the official NIP-44 [vector file](https://github.com/paulmillr/nip44/blob/main/nip44.vectors.json). Native C90 testing using only stdlibs is planned for the future.

### Security
- Constant-time comparison for all timing-sensitive operations
- No dynamic memory allocations in the core library
- Platform-dispatched secure zeroing
- Pluggable crypto backends — only load what you need, reducing attack surface
- Span-based buffer abstraction with bounds enforcement
- Public API input validation enabled by default
- Stack protection enabled for GCC and MSVC builds

### Quality Assurance
- 100% CI test pass required before merging
- Valgrind-verified for memory leaks and overflows
- Validated against official NIP-44 test vectors
- Carefully selected, widely used, and audited cryptographic backends

## Platform Support
The following table lists the supported platforms and cryptography backends. Additional backends may be specified at build time; otherwise safe defaults are selected for the target platform.

| Arch | Support | Notes | Tested |
| ----- | ---------- | ------- | ------- |
| Windows | OpenSSL (3.0+), Mbed-TLS, BCrypt | NT 6.1 + | ✅ |
| Linux   | OpenSSL (3.0+), Mbed-TLS         | GCC only | ✅ |
| FreeBSD | OpenSSL (3.0+), Mbed-TLS         | GCC Only |    |

## Security Policy
Please see the [SECURITY.md](SECURITY.md) file for more information on how to report security issues.

## Getting started
Please use the following links to obtain packages and extended documentation.

[__Project homepage__](https://www.vaughnnugent.com/resources/software/modules/noscrypt)  
[__Startup & Install Guide__](https://www.vaughnnugent.com/resources/software/articles/62ca932f68b8e0b1b99dca6e1c9ffe5538205efb)  
[__Extended Documentation__](https://www.vaughnnugent.com/resources/software/articles?tags=docs,_noscrypt)  

### Super quick start
If you are wanting to get started quickly, these steps will get you up and running. See the website documentation for the authoritative reference.

#### Prerequisites
- Supported operating system and compiler from table above
- [CMake](https://cmake.org/download) build system
- [Taskfile.dev](https://taskfile.dev) (v3.45+) to execute build recipes

To build and install noscrypt:
```shell
mkdir noscrypt/ && cd noscrypt/
wget https://www.vaughnnugent.com/public/resources/software/builds/noscrypt/<master-git-hash>/noscrypt/noscrypt-src.tgz
tar -xzf noscrypt-src.tgz
task
sudo task install
```

## Notes
#### Builds
Build packages are fully automated and signed with PGP. 

**It is highly recommended that you use the signed packages from the website in your application.** You should avoid using git, github, or other git-based mirrors (git submodules) to include noscrypt in your production application. This is because automated builds may generate artifacts, move directories, verification, or otherwise optimize source for production use.

#### Branches
Two long-lived branches are used for development. `master` is considered as stable as a release tag, `develop` is a staging branch for all changes before they are merged into master. When submitting patches please target the latest develop branch.

#### Windows Dlls
MSVC pre-compiled packages are available for download on the website package page. Currently these support Windows NT version 1904 (10/Server 2016 and later) running amd64 processors.

#### Contributing
Please see the Startup & Install guide above for instructions on how contributions are expected to be received. PRs and issues are disabled on all git platforms. Please see the website for support channels.  

## License
The software in this repository is licensed to you under the GNU Lesser GPL v2.1 or later. `SPDX-License-Identifier: LGPL-2.1-or-later` see the [LICENSE](LICENSE) file for more details.

Copyright (c) 2023-2026 Vaughn Nugent

### Cryptography Notice
This software contains cryptographic components and may be subject to export control laws and regulations in your jurisdiction. This software is developed in the United States of America. Users are responsible for compliance with all applicable local, national, and international laws regarding the import, export, re-export, and use of encryption software. This software is publicly available and may qualify for exceptions under certain export control regimes, but no guarantee is made regarding legal compliance in any particular jurisdiction.

## Donations
If you would like to support this project, donations are welcome and much appreciated.

Bitcoin: `bc1qgj4fk6gdu8lnhd4zqzgxgcts0vlwcv3rqznxn9`  
Lightning: ChipTuner@coinos.io

I am also a member of [GitCitadel](https://next.nostrudel.ninja/#/wiki/topic/gitcitadel-project) — feel free to [send some sats](https://geyser.fund/project/gitcitadel) that way too!

