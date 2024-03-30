# CMakeList.txt : CMake project for noscrypt, include source and define
# project specific logic here.
#

cmake_minimum_required (VERSION 3.10)

project(noscrypt C)

option(BUILD_TESTS "Build tests" TRUE)

set(NOSCRYPT_SRCS 
	"src/noscrypt.c"
)

set(NOSCRYPT_HEADERS
	"src/noscrypt.h"
)

include_directories(include)

#static/shared library
add_library(${CMAKE_PROJECT_NAME} SHARED ${NOSCRYPT_SRCS} ${NOSCRYPT_HEADERS})
add_library(${CMAKE_PROJECT_NAME}_static STATIC ${NOSCRYPT_SRCS} ${NOSCRYPT_HEADERS})

#Setup the compiler options for c90 shared library
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

#if debug
add_compile_definitions($<$<CONFIG:Debug>:DEBUG>)

#when building we are in libary mode, we need to export our symbols
add_compile_definitions(NOSCRYPT_EXPORTING)

#setup flags for windows compilation
if(MSVC)
	
    #global windows cl flags
	add_compile_options(
		/sdl	#enable additional security checks
		/TC		#compile as c
		/GS		#buffer security check
		
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
	add_compile_definitions( 
		$<$<CONFIG:DEBUG>:DEBUG>
		$<$<CONFIG:RELEASE>:RELEASE>
	)

#configure gcc flags
elseif(CMAKE_COMPILER_IS_GNUCC)

	add_compile_options(
		-Wextra
		-fstack-protector

		$<$<CONFIG:Debug>:-g>
		$<$<CONFIG:Debug>:-Og>
		$<$<CONFIG:Debug>:-Wall>
		$<$<CONFIG:Debug>:-Werror>
		$<$<CONFIG:Debug>:-Wall>
		$<$<CONFIG:Debug>:-pedantic>
	)

endif()

# Setup secp256k1 shared libary
unset(SECP256K1_LIB CACHE)

find_library(SECP256K1_LIB 
	NAMES secp256k1 libsecp256k1 lib_secp256k1
)

if(NOT SECP256K1_LIB)
	message(FATAL_ERROR "secp256k1 library not found on local system")
endif()

message(STATUS "secp256k1 library found at ${SECP256K1_LIB}")
target_link_libraries(${CMAKE_PROJECT_NAME} ${SECP256K1_LIB})


#link mbedtls and mbedcrypto shared libraries
unset(MBEDCRYPTO_LIB CACHE)
unset(MBEDTLS_LIB CACHE)

find_library(MBEDTLS_LIB NAMES mbedtls libmbedtls)
find_library(MBEDCRYPTO_LIB NAMES mbedcrypto libmbedcrypto)

if(NOT MBEDCRYPTO_LIB)
	message(FATAL_ERROR "mbedcrypto library not found on local system")
endif()
if(NOT MBEDTLS_LIB)
	message(FATAL_ERROR "mbedtls library not found on local system")
endif()

message(STATUS "mbedtls library found at ${MBEDTLS_LIB}")
message(STATUS "mbedcrypto library found at ${MBEDCRYPTO_LIB}")

target_link_libraries(${CMAKE_PROJECT_NAME} ${MBEDCRYPTO_LIB} ${MBEDTLS_LIB})


#TESTS
if(BUILD_TESTS)

	#add test executable and link to library
	add_executable(nctest tests/test.c)
	target_link_libraries(nctest ${CMAKE_PROJECT_NAME})
	#link mbedtls crypto sahred library
	target_link_libraries(nctest ${MBEDCRYPTO_LIB} ${MBEDTLS_LIB})
	target_include_directories(nctest PRIVATE "src")

endif()


# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()