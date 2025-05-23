﻿# Copyright (c) 2024 Vaughn Nugent
# See the LICENSE in this directory for terms of use
#
# This file configures noscrypt with best defaults as possible while offering 
# some freedom in terms of crypto libraries if desired. Some defaults and 
# worst case fallback functions are defined and will get better as time goes on
# 

cmake_minimum_required (VERSION 3.10)

project(
	noscrypt
	LANGUAGES C
	DESCRIPTION "A compact, C90 cross-platform, cryptography library built specifically for nostr"
	HOMEPAGE_URL "https://www.vaughnnugent.com/resources/software/modules/noscrypt"
	VERSION ${CMAKE_PROJECT_VERSION}
)

set(_NC_PROJ_NAME "noscrypt")

option(NC_BUILD_TESTS "Build tests" OFF)
option(NC_ENABLE_UTILS "Enables the sidecar utility library" OFF)
option(NC_DISABLE_INPUT_VALIDATION "Disables public function input validation" OFF)
option(NC_INCLUDE_MONOCYPHER "Statically link to vendored monocypher library" ON)
set(CRYPTO_LIB "" CACHE STRING "The crypto library to link to (mbedtls, openssl, bcrypt)")
set(CRYPTO_LIB_DIR "" CACHE STRING "The path to the crypto library if it's not globally available")
set(SECP256K1_LIB_DIR "" CACHE STRING "An optional path to search for the secp256k1 library if not globally installed")

string(TOLOWER ${CMAKE_BUILD_TYPE} build_type)

#list of noscrypt project defitnions
set(NC_PROJ_DEFINITIONS "")

include(FetchContent)

if(SECP256K1_LIB_DIR)

	#search for an existing library, it's a required dependency
	find_library(secp256k1
		NAMES secp256k1 libsecp256k1 
		PATHS ${SECP256K1_LIB_DIR}
		REQUIRED
	)

else()

  #try to find the library globally
  find_library(secp256k1 NAMES secp256k1 libsecp256k1)

endif()

if(NOT secp256k1)

   message(STATUS "No secp256k1 library was found, falling back to build local copy")

	#Use the inlcuded libsecp256k1 source, and build a minimal static library 
	set(SECP256K1_BUILD_BENCHMARK OFF)
	set(SECP256K1_BUILD_TESTS OFF)
	set(SECP256K1_BUILD_EXAMPLES OFF)
	set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF)
	set(SECP256K1_ENABLE_MODULE_ECDH ON)
	set(SECP256K1_ENABLE_MODULE_RECOVERY OFF)
	set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON)
	set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON)
	set(SECP256K1_ENABLE_MODULE_ELLSWIFT OFF)
	set(SECP256K1_INSTALL OFF)
	set(SECP256K1_DISABLE_SHARED ON)			#disales shared library output

	add_subdirectory(vendor/secp256k1)
	
	#Must force FPIC when using secp256k1 since noscrypt is also a library
	set_target_properties(
		secp256k1 
		secp256k1_precomputed 
		
		PROPERTIES 
		POSITION_INDEPENDENT_CODE  ON
	)
	
endif()

#-----------------------------
#		MAIN PROJECT
#-----------------------------

set(NOSCRYPT_SRCS 
	"src/noscrypt.c"	
	"src/hkdf.c"
	"src/nc-crypto.c"				#pulls in c impl files as needed
)

set(NOSCRYPT_HEADERS
	"include/noscrypt.h"
	"include/platform.h"
	"src/nc-util.h"
	"src/hkdf.h"
	"src/nc-crypto.h"
)

#if utils are enabled, add the source files
if(NC_ENABLE_UTILS)
	list(APPEND NOSCRYPT_SRCS "src/noscryptutil.c")
	list(APPEND NOSCRYPT_HEADERS "include/noscryptutil.h")

	#notify the project that utils are enabled
	list(APPEND NC_PROJ_DEFINITIONS NC_ENABLE_UTILS)
endif()

#static/shared library
add_library(${_NC_PROJ_NAME} SHARED ${NOSCRYPT_SRCS} ${NOSCRYPT_HEADERS})
add_library(${_NC_PROJ_NAME}_static STATIC ${NOSCRYPT_SRCS} ${NOSCRYPT_HEADERS})
set_target_properties(${_NC_PROJ_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)		#fPIC for shared library

#set specific cmake commands to target our projects only
set_target_properties(
	${_NC_PROJ_NAME} 
	${_NC_PROJ_NAME}_static 
	
	#Setup the compiler options for c90 standard
	PROPERTIES 
	C_STANDARD 90
	C_STANDARD_REQUIRED ON
	C_EXTENSIONS ON			#enables c++ style comments (only required for mbedtls stuff)
)

target_compile_features(${_NC_PROJ_NAME} PRIVATE c_std_90)	#force compiler to use c90 standard for library
target_compile_features(${_NC_PROJ_NAME}_static PRIVATE c_std_90)	#force compiler to use c90 standard for library

target_include_directories(${_NC_PROJ_NAME} PRIVATE include)
target_include_directories(${_NC_PROJ_NAME}_static PRIVATE include)

#link libsecp256k1
target_link_libraries(${_NC_PROJ_NAME} PRIVATE secp256k1)
target_link_libraries(${_NC_PROJ_NAME}_static PRIVATE secp256k1)

#make vendored headers available to the project
target_include_directories(${_NC_PROJ_NAME} SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/vendor)
target_include_directories(${_NC_PROJ_NAME}_static SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/vendor)

#############################################
#
#		Configure crypto library linking
#
#############################################

#try to load openssl quietly in order to check for its availability
find_package(OpenSSL QUIET)

#setup default linking to crypto libraries for certain plaftorms. 
#Windows defaults to bcrypt, openssl otherwise if installed
if(CRYPTO_LIB STREQUAL "")	
  if(MSVC)
	set(CRYPTO_LIB "bcrypt")
  elseif(OPENSSL_FOUND)
	set(CRYPTO_LIB "openssl")
  endif()
  message(STATUS "No crypto library was specified, defaulting to '${CRYPTO_LIB}'")
endif()


#if mbedtls linking is enabled target the library
if(CRYPTO_LIB STREQUAL "mbedtls")

	#make vendored mbedtls headers available to the project
	target_include_directories(${_NC_PROJ_NAME} SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/vendor/mbedtls/include)
	target_include_directories(${_NC_PROJ_NAME}_static SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/vendor/mbedtls/include)

	message(STATUS "Linking to MbedTLS crypto library")

	#find the library
	find_library(MBEDTLS_LIB_CRYPTO
		NAMES mbedcrypto libmbedcrypto libmbedcrypto.a mbedcrypto.lib
			
		HINTS 
		${CRYPTO_LIB_DIR} 
		${CRYPTO_LIB_DIR}/debug 
		${CRYPTO_LIB_DIR}/release 
		${CRYPTO_LIB_DIR}/library
		${CRYPTO_LIB_DIR}/library/debug 
		${CRYPTO_LIB_DIR}/library/release
			
		REQUIRED
	)
		
	find_library(MBEDTLS_LIB_TLS
		NAMES mbedtls libmbedtls libmbedtls.a mbedtls.lib

		HINTS 
		${CRYPTO_LIB_DIR} 
		${CRYPTO_LIB_DIR}/debug 
		${CRYPTO_LIB_DIR}/release 
		${CRYPTO_LIB_DIR}/library
		${CRYPTO_LIB_DIR}/library/debug 
		${CRYPTO_LIB_DIR}/library/release

		REQUIRED
	)

	message(STATUS "Found mbedtls crypto library at ${MBEDTLS_LIB_CRYPTO}")
	message(STATUS "Found mbedtls tls library at ${MBEDTLS_LIB_TLS}")

	#link to the library
	target_link_libraries(${_NC_PROJ_NAME} PRIVATE ${MBEDTLS_LIB_CRYPTO} PRIVATE ${MBEDTLS_LIB_TLS})
	target_link_libraries(${_NC_PROJ_NAME}_static PRIVATE ${MBEDTLS_LIB_CRYPTO} PRIVATE ${MBEDTLS_LIB_TLS})
	
	#enable mbedtls crypto library bindings
	list(APPEND NC_PROJ_DEFINITIONS MBEDTLS_CRYPTO_LIB)

elseif(CRYPTO_LIB STREQUAL "openssl")

	set(OPENSSL_USE_STATIC_LIBS ON)
	find_package(OpenSSL REQUIRED)

	#link to openssl
	message(STATUS "Linking to OpenSSL crypto library")
	target_link_libraries(${_NC_PROJ_NAME} PRIVATE OpenSSL::Crypto)
	target_link_libraries(${_NC_PROJ_NAME}_static PRIVATE OpenSSL::Crypto)

	#enable openssl crypto library bindings
	list(APPEND NC_PROJ_DEFINITIONS OPENSSL_CRYPTO_LIB)

elseif(CRYPTO_LIB STREQUAL "bcrypt")

	if(MSVC)
		#link bcrypt for Windows platforms
		target_link_libraries(${_NC_PROJ_NAME} PRIVATE "bcrypt.lib")
		target_link_libraries(${_NC_PROJ_NAME}_static PRIVATE "bcrypt.lib")
	else()
		message(FATAL_ERROR "Bcrypt is only supported on Windows platforms")
	endif()

else()

	message(FATAL_ERROR "You must select a supported cryptography library: openssl, mbedtls, or bcrypt (Windows only)")

endif()

add_compile_definitions($<$<CONFIG:Debug>:DEBUG>)
add_compile_definitions(NOSCRYPT_EXPORTING)			#enable exporting symbols

if(NC_DISABLE_INPUT_VALIDATION)
	list(APPEND NC_PROJ_DEFINITIONS NC_INPUT_VALIDATION_OFF)
endif()

set(_NC_COMPILE_OPTS)

#setup flags for windows compilation
if(MSVC)

   list(APPEND _NC_COMPILE_OPTS
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
	list(APPEND NC_PROJ_DEFINITIONS
		$<$<CONFIG:DEBUG>:DEBUG>
		$<$<CONFIG:RELEASE>:RELEASE>
	)

#configure gcc flags
elseif(CMAKE_COMPILER_IS_GNUCC)

	list(APPEND _NC_COMPILE_OPTS 
		-Wextra 
		-fstack-protector
		-Werror				# warnings as errors
	)

	#if debug build enable additional debug flags
	if(build_type STREQUAL "debug")
		 list(APPEND _NC_COMPILE_OPTS
		
			-g				# enable debug info
			-Og				# disable all optimizations
			-Wall			# enable all warnings
			-pedantic		# enable pedantic warnings
			-Winit-self		# warn about self initialization
			-Wpointer-arith
			-Wstrict-prototypes
			-Wswitch-default
			-Wshadow		# warn when a local variable shadows another
			-Wformat=2		# warn about format strings
			-Wundef			# warn about undefined macros
			-Wcast-align	# warn about pointer casts that increase alignment requirements
			-Wmissing-prototypes	# warn if a global function is defined without a previous prototype declaration
			-Wmissing-declarations	# warn if a global function is defined without a previous declaration
		)
	endif()
endif()

target_compile_options(${_NC_PROJ_NAME} PRIVATE ${_NC_COMPILE_OPTS})
target_compile_options(${_NC_PROJ_NAME}_static PRIVATE ${_NC_COMPILE_OPTS})

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

	#add monocypher as a static dep to the project
	add_library(monocypher STATIC 
		"vendor/monocypher/monocypher.c"
		"vendor/monocypher/monocypher.h"
	)

	target_link_libraries(${_NC_PROJ_NAME} PRIVATE monocypher)
	target_link_libraries(${_NC_PROJ_NAME}_static PRIVATE monocypher)
	
	target_compile_features(monocypher PRIVATE c_std_99)			#targets c99

	if(MSVC)		
		target_compile_options(monocypher PRIVATE
			/sdl						#enable additional security checks
			/TC							#compile as c
			/GS							#buffer security check
		)

		#enable monocypher crypto library bindings
		list(APPEND NC_PROJ_DEFINITIONS NC_ENABLE_MONOCYPHER)

	elseif(CMAKE_COMPILER_IS_GNUCC)
		#from monocypher's Makefile
		target_compile_options(monocypher PRIVATE -pedantic -Wall -Wextra -O3 -march=native)

		#enable monocypher crypto library bindings
		list(APPEND NC_PROJ_DEFINITIONS NC_ENABLE_MONOCYPHER)
	else()
		message(WARNING "Monocypher is not supported on this platform")
	endif()
endif()

#Set NC variables to both projects
target_compile_definitions(${_NC_PROJ_NAME} PRIVATE ${NC_PROJ_DEFINITIONS})
target_compile_definitions(${_NC_PROJ_NAME}_static PRIVATE ${NC_PROJ_DEFINITIONS})

############################
#
#		TESTS
#
###########################
if(NC_BUILD_TESTS)

	#add test executable and link to shared library for more realistic usage
	add_executable(nctest tests/test.c)
	target_link_libraries(nctest ${_NC_PROJ_NAME})

	if(MSVC)
		#link bcrypt to test application for Windows platforms
		target_link_libraries(nctest "bcrypt.lib")
	endif()

	target_include_directories(nctest PRIVATE include)
	target_include_directories(nctest PRIVATE src)	#allow access to internal headers

	#enable c11 for testing
	target_compile_features(nctest PRIVATE c_std_11)
	target_compile_definitions(nctest PRIVATE ${NC_PROJ_DEFINITIONS})	

	enable_testing()

	add_test(
		NAME nctest 
		COMMAND nctest
		CONFIGURATIONS ${CMAKE_BUILD_TYPE}
	)

endif()

message("\n${_NC_PROJ_NAME} project summary")
message("=====================================")
message(" -- Version: ${CMAKE_PROJECT_VERSION} --")
message(" -- Configuration: ${build_type} --")
message("  Testing enabled: ....... ${NC_BUILD_TESTS}")
message("  Crypto library: ........ ${CRYPTO_LIB}")
message("  Input validation off: .. ${NC_DISABLE_INPUT_VALIDATION}")
message("  Monocypher: ............ ${NC_INCLUDE_MONOCYPHER}")
if(NOT secp256k1)
	message("  secp256k1 library: ..... (local)")
else()
	message("  secp256k1 library: ..... ${secp256k1}")
endif()
message("  Utilities enabled: ..... ${NC_ENABLE_UTILS}")
message(" Defintions: ${NC_PROJ_DEFINITIONS}")
message(" Compiler flags: ${_NC_COMPILE_OPTS}")
message("=====================================")


###########################
#
#		Installing
#
###########################

#export shared library for normal install
install(
	TARGETS ${_NC_PROJ_NAME} ${_NC_PROJ_NAME}_static
    LIBRARY DESTINATION lib COMPONENT devel
    ARCHIVE DESTINATION lib COMPONENT devel
    RUNTIME DESTINATION bin COMPONENT devel
)

install(
	TARGETS ${_NC_PROJ_NAME}
    LIBRARY DESTINATION lib COMPONENT release
    ARCHIVE DESTINATION lib COMPONENT release
    RUNTIME DESTINATION bin COMPONENT release
)


SET(NC_INSTALL_HEADERS
	include/noscrypt.h	#static install headers
	include/platform.h
)

if(NC_ENABLE_UTILS)
	LIST(APPEND 
		NC_INSTALL_HEADERS
		include/noscryptutil.h
	)
endif()

install(
	FILES ${NC_INSTALL_HEADERS} 
	DESTINATION include/noscrypt COMPONENT devel
)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

