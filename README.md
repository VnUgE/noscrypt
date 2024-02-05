# noscrypt
*A compact, C90 cross-platform, cryptography library built specifically for nostr*

At the moment this library is a work in progress, and will be more extensively tested using the suggested nip-44 vector files in [NVault](https://github.com/VnUgE/NVault)

## What is noscrypt?
A high-level C utility library built specifically for nostr cryptography operations such as those defined in NIP-01 and the new NIP-44. It was designed to simplify the operations that the secp256k1 library was used for, along with data encryption for the new sepc.  

API Example:
```C
NCValidateSecretKey()
NCGetPublicKey()
NCSignData()
NCVerifyData()
NCEncrypt()
NCDecrypt()
... extended functions
```

There are no functions that handle key generation, because secp256k1 simply requires a 32byte random number that needs to only be validated. I assume most applications will prefer and or have better random number generators than I can assume. Use your preferred or platform CSRNG.  

## Motivation
At the time of building this project I have not come across any C-only libraries that exposed functionality for nostr specific cryptography. IMO it is easy to use the secp256k1 library incorrectly. In the process of building [NVault](https://github.com/VnUgE/NVault) NIP-44 came out in December and I realized my libraries were falling short for my needs for proper and safe nostr cryptographic operations, and I needed to start over and start with a good base that has all the basic  functionality built with trusted and tested libraries.  

I wanted a compact and efficient utility library that was portable across systems and runtimes. I will primarily be using this library in a .NET environment, but would like to make a hardware signer sometime. 

### Dependency choices
I carefully chose [mbedTls](https://github.com/Mbed-TLS/mbedtls) and [libsecp256k1](https://github.com/bitcoin-core/secp256k1)  for the following reasons
- Modern, well tested and well trusted  
- Fully open source and actively maintained  
- Absolutely no runtime memory allocations  
- Built for use in embedded applications  
- Simple installations  
- Great cross-platform build support  

Initially I wanted to use [MonoCypher](https://monocypher.org/) for its compatibility and compactness but it did not have support for hdkf which is required for NIP-44.  

### Future Goals
- Good support for embedded platforms that wish to implement nostr specific features (would be fun!)  
- Over all better testing suite  

## Packages and Docs
GitHub is simply a mirror for my projects. Extended documentation, pre-compiled binaries and source code bundles are always available on my website, along with PGP signatures and checksums.    

[Docs and Articles](https://www.vaughnnugent.com/resources/software/articles?tags=docs,_noscrypt)  
[Builds and Source](https://www.vaughnnugent.com/resources/software/modules/noscrypt)  

## Getting the package
There are 3 ways to get the source code to build this project.  
1. Clone the GitHub repo `git clone https://github.com/VnUgE/noscrypt.git`  
2. Download an archive from my website above  
3. Download a github archive or release when they are available  

## Compilation
This project was built from the start using cmake as the build platform so it is easily cross platform. Builds produce a shared library and a static library so you can choose how to link it with your project.  

### Prerequisites
Before building this library you must install the following dependencies 
- [secp256k1](https://github.com/bitcoin-core/secp256k1)  
- [mbedtls](https://github.com/Mbed-TLS/mbedtls)  

These libraries must be installed where cmake can find them, the easiest way is to just install them globally. So for Windows, this means the .lib files need to be available on the system PATH or safe search directories. The build process will fail if those libraries are not available. Follow the instructions for building and installing the libraries using `cmake` before continuing.  For Linux libraries must be available in one of the the `lib/` base directories.

*It is recommended to download the release archives of mbedtls and secp256k1 instead of cloning the repositories.*  

### Windows users
Windows users can download pre-compiled x64 binaries from my website above when a build is run.  You will still need to manually install dependencies

### Instructions
Use the following cmake commands to generate and compile the library on your system. This assumes you are in the directory containing the `CMakeLists.txt` file  
```shell
cmake -B./build/
cmake --build build/ --config Release
```

By default building of the test executables are disabled. At the moment testing is very basic, but will grow as time goes on. To enable testing set the `-DENABLE_TESTS=ON` flag during the first stage generation process
```shell
cmake -B./build/ -DENABLE_TESTS=ON
```

This will produce the `nctests` executable file in the build directory. This will likely change a bit in the future.  

## Notes
**Builds** build packages on my website are "manual" I use an internal tool called *vnbuild* that just does the work of preparing a package, but I have to run it myself.  

### Branches
There are currently 2 branches I use because of my build process. `develop` and `master`. All changes happen in develop, then are merged to master when I feel like they are stable enough. After some testing and time, a tag and release will become available.   

## License
The software in this repository is licensed to you under the GNU Lesser GPL v2.1 or later. `SPDX-License-Identifier: LGPL-2.1-or-later` see the [LICENSE](LICENSE) file for more details.    

## Donations
If you feel so inclined to support me an this project, donations are welcome and much appreciated.   

BTC On-Chain: ``bc1qgj4fk6gdu8lnhd4zqzgxgcts0vlwcv3rqznxn9``  

