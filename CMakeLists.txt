# CMakeList.txt : CMake project for noscrypt, include source and define
# project specific logic here.
#

cmake_minimum_required (VERSION 3.10)

option(NC_BUILD_TESTS "Build tests" OFF)
option(NC_DISABLE_INPUT_VALIDATION "Disables public function input validation" OFF)
option(NC_FETCH_MBEDTLS "Fetch Mbed-TLS from it's source repository locally" OFF)
option(NC_INCLUDE_MONOCYPHER "Statically link to vendored monocypher library" ON)
set(CRYPTO_LIB "none" CACHE STRING "The crypto library to link to (mbedtls, openssl, none)")
set(CRYPTO_LIB_DIR "" CACHE STRING "The path to the crypto library if it's not globally available")

string(TOLOWER ${CMAKE_BUILD_TYPE} build_type)

include(FetchContent)

#SET SECP256k VARS
set(SECP256K1_BUILD_BENCHMARK OFF)
set(SECP256K1_BUILD_TESTS OFF)
set(SECP256K1_BUILD_EXAMPLES OFF)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF)
set(SECP256K1_BUILD_STATIC ON)
set(SECP256K1_ENABLE_MODULE_ECDH ON)
set(SECP256K1_ENABLE_MODULE_RECOVERY ON)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON)
set(SECP256K1_INSTALL OFF)
set(SECP256K1_DISABLE_SHARED ON)			#disales shared library output

FetchContent_Declare(
  libsecp256k1
  GIT_REPOSITORY		https://github.com/bitcoin-core/secp256k1
  GIT_TAG				1ad5185cd42c0636104129fcc9f6a4bf9c67cc40 # release-0.4.1
  GIT_PROGRESS			TRUE
)

FetchContent_MakeAvailable(libsecp256k1)

#Include mbedtls if enabled
if(NC_FETCH_MBEDTLS)

	set(ENABLE_PROGRAMS OFF)
	set(ENABLE_TESTING OFF)
	set(USE_SHARED_MBEDTLS_LIBRARY OFF)
	set(USE_STATIC_MBEDTLS_LIBRARY ON)
	set(DISABLE_PACKAGE_CONFIG_AND_INSTALL OFF)
	set(MBEDTLS_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_custom_config.h" CACHE STRING "" FORCE)

	FetchContent_Declare(
	  libmbedtls
	  GIT_REPOSITORY        https://github.com/Mbed-TLS/mbedtls.git
	  GIT_TAG               v3.6.0
	  GIT_PROGRESS          TRUE
	)

	FetchContent_MakeAvailable(libmbedtls)

	set(CRYPTO_LIB "mbedtls")		#enable linking to mbedtls
endif()


#-----------------------------
#		MAIN PROJECT
#-----------------------------

project(noscrypt C)

include_directories(include)				#include the 'include' directory for the project
set(CMAKE_C_STANDARD 90)					#Setup the compiler options for c90 shared library
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(NOSCRYPT_SRCS 
	"src/noscrypt.c"	
	"src/crypto/nc-crypto.c"				#pulls in c impl files as needed
)

set(NOSCRYPT_HEADERS
	"include/noscrypt.h"
	"include/platform.h"
	"include/nc-util.h"
	"src/crypto/nc-crypto.h"
)

#static/shared library
add_library(${CMAKE_PROJECT_NAME} SHARED ${NOSCRYPT_SRCS} ${NOSCRYPT_HEADERS})
add_library(${CMAKE_PROJECT_NAME}_static STATIC ${NOSCRYPT_SRCS} ${NOSCRYPT_HEADERS})
target_compile_features(${CMAKE_PROJECT_NAME} PUBLIC c_std_90)	#force compiler to use c90 standard for library

#link libsecp256k1
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE secp256k1)
target_link_libraries(${CMAKE_PROJECT_NAME}_static PRIVATE secp256k1)


#############################################
#
#		Configure crypto library linking
#
#############################################


#if mbedtls linking is enabled target the library
if(CRYPTO_LIB STREQUAL "mbedtls")

	message(STATUS "Linking to MbedTLS crypto library")

	target_include_directories(${CMAKE_PROJECT_NAME} SYSTEM PRIVATE vendor)
	target_include_directories(${CMAKE_PROJECT_NAME}_static SYSTEM PRIVATE vendor)

	if(NC_FETCH_MBEDTLS)
		#link to included mbedtls
		target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE mbedcrypto PRIVATE mbedtls)
		target_link_libraries(${CMAKE_PROJECT_NAME}_static PRIVATE mbedcrypto PRIVATE mbedtls)
	else()
		#find the library
		find_library(MBEDTLS_LIB_CRYPTO
			NAMES mbedcrypto libmbedcrypto 
			PATHS ${CRYPTO_LIB_DIR}
		)
		
		find_library(MBEDTLS_LIB_TLS
			NAMES mbedtls libmbedtls
			PATHS ${CRYPTO_LIB_DIR}
		)

		message(STATUS "Found mbedtls crypto library at ${MBEDTLS_LIB_CRYPTO}")
		message(STATUS "Found mbedtls tls library at ${MBEDTLS_LIB_TLS}")

		#link to the library
		target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${MBEDTLS_LIB_CRYPTO} PRIVATE ${MBEDTLS_LIB_TLS})
		target_link_libraries(${CMAKE_PROJECT_NAME}_static PRIVATE ${MBEDTLS_LIB_CRYPTO} PRIVATE ${MBEDTLS_LIB_TLS})
	endif()

	#enable mbedtls crypto library bindings
	target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE MBEDTLS_CRYPTO_LIB)
	target_compile_definitions(${CMAKE_PROJECT_NAME}_static PRIVATE MBEDTLS_CRYPTO_LIB)

elseif(CRYPTO_LIB STREQUAL "openssl")

	#link to openssl
	message(STATUS "Linking to OpenSSL crypto library")
	target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE OpenSSL::Crypto)
	target_link_libraries(${CMAKE_PROJECT_NAME}_static PRIVATE OpenSSL::Crypto)

	#enable openssl crypto library bindings
	target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE OPENSSL_CRYPTO_LIB)
	target_compile_definitions(${CMAKE_PROJECT_NAME}_static PRIVATE OPENSSL_CRYPTO_LIB)

else()
	#the library should be self sufficient in handling default crypto implementations
	
endif()

add_compile_definitions($<$<CONFIG:Debug>:DEBUG>)
add_compile_definitions(NOSCRYPT_EXPORTING)			#enable exporting symbols

if(NC_DISABLE_INPUT_VALIDATION)
	target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE NC_INPUT_VALIDATION_OFF)
endif()

#setup flags for windows compilation
if(MSVC)

	#link bcrypt for Windows platforms
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE "bcrypt.lib")
	target_link_libraries(${CMAKE_PROJECT_NAME}_static PRIVATE "bcrypt.lib")
	
    #global windows cl flags
	target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE
		/sdl						#enable additional security checks
		/TC							#compile as c
		/GS							#buffer security check
		
		$<$<CONFIG:Debug>:/FC>				#show full path in diagnostics
		$<$<CONFIG:Debug>:/showIncludes>	#show a list of all included header files during build
		
		$<$<CONFIG:Debug>:/wd4820>	#disable warnings for struct padding and spectre mitigation wuen WX is enabled
		$<$<CONFIG:Debug>:/wd5045>	#disable warnings for spectre mitigation insertion

		#for debug configs
		$<$<CONFIG:Debug>:/options:strict>
		$<$<CONFIG:Debug>:/Wall>	#enable all warnings
		$<$<CONFIG:Debug>:/WX>		#warnings as errors (only for our project)
		$<$<CONFIG:Debug>:/Zi>		#enable rich debug info
		$<$<CONFIG:Debug>:/Zo>
	)

	#set build macros
	target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE
		$<$<CONFIG:DEBUG>:DEBUG>
		$<$<CONFIG:RELEASE>:RELEASE>
	)

#configure gcc flags
elseif(CMAKE_COMPILER_IS_GNUCC)

	target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -Wextra -fstack-protector)

	#if debug build enable additional debug flags
	if(build_type STREQUAL "debug")
		target_compile_options(
			${CMAKE_PROJECT_NAME} 
			PRIVATE 
		
			-g
			-Og
			-Wall
			-Werror
			-pedantic
		)
	endif()
endif()

#############################################
#
#	Build/link monocypher 
#
#############################################

# Monocypher only provides a few fallback functions
# for builds that don't use a more complete library
# implementation. Specifically cha-cha20 and secure 
# erase functions.

if(NC_INCLUDE_MONOCYPHER)

	target_include_directories(${CMAKE_PROJECT_NAME} SYSTEM PRIVATE "vendor/monocypher")	
	target_include_directories(${CMAKE_PROJECT_NAME}_static SYSTEM PRIVATE "vendor/monocypher")	

	#add monocypher as a static dep to the project
	add_library(monocypher STATIC 
		"vendor/monocypher/monocypher.c"
		"vendor/monocypher/monocypher.h"
	)

	target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE monocypher)
	target_link_libraries(${CMAKE_PROJECT_NAME}_static PRIVATE monocypher)
	
	target_compile_features(monocypher PRIVATE c_std_99)			#targets c99

	if(MSVC)		
		target_compile_options(monocypher PRIVATE
			/sdl						#enable additional security checks
			/TC							#compile as c
			/GS							#buffer security check
		)

		#enable monocypher crypto library bindings
		target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE NC_ENABLE_MONOCYPHER)
		target_compile_definitions(${CMAKE_PROJECT_NAME}_static PRIVATE NC_ENABLE_MONOCYPHER)

	elseif(CMAKE_COMPILER_IS_GNUCC)
		#from monocypher's Makefile
		target_compile_options(monocypher PRIVATE -pedantic -Wall -Wextra -O3 -march=native)

		#enable monocypher crypto library bindings
		target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE NC_ENABLE_MONOCYPHER)
		target_compile_definitions(${CMAKE_PROJECT_NAME}_static PRIVATE NC_ENABLE_MONOCYPHER)
	else()
		message(WARNING "Monocypher is not supported on this platform")
	endif()
endif()


#TESTS
if(NC_BUILD_TESTS)

	#add test executable and link to library
	add_executable(nctest tests/test.c)
	target_link_libraries(nctest ${CMAKE_PROJECT_NAME}_static)
	target_include_directories(nctest PRIVATE include)

	#enable c11 for testing
	target_compile_features(nctest PRIVATE c_std_11)
endif()


# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()