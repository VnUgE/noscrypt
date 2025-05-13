# CPack configuration for package generation
# Copyright (c) 2025 Vaughn Nugent
# See the LICENSE in root directory

# Set CPack variables
set(CPACK_PACKAGE_NAME "${_NC_PROJ_NAME}")
set(CPACK_PACKAGE_VERSION "${CMAKE_PROJECT_VERSION}")
set(CPACK_PACKAGE_VENDOR "Vaughn Nugent")
set(CPACK_PACKAGE_CONTACT "Vaughn Nugent")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "A compact, C90 cross-platform, cryptography library built specifically for nostr")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://www.vaughnnugent.com/resources/software/modules/noscrypt")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")

# Component handling
set(CPACK_COMPONENTS_ALL release devel)
set(CPACK_COMPONENT_RELEASE_DISPLAY_NAME "Runtime Libraries")
set(CPACK_COMPONENT_DEVEL_DISPLAY_NAME "Development Files")
set(CPACK_COMPONENT_DEVEL_DEPENDS release)

# RPM-specific configuration
set(CPACK_RPM_PACKAGE_RELEASE fc1)
set(CPACK_RPM_PACKAGE_LICENSE "LGPL-2.1-or-later")
set(CPACK_RPM_PACKAGE_GROUP "Development/Libraries")
set(CPACK_RPM_PACKAGE_SUMMARY "${CPACK_PACKAGE_DESCRIPTION_SUMMARY}")
set(CPACK_RPM_CHANGELOG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/CHANGELOG.md")

# RPM dependencies
# No autoreq/autoprov, dependencies are defined above
set(CPACK_RPM_PACKAGE_AUTOREQ OFF)
set(CPACK_RPM_PACKAGE_AUTOPROV OFF)
set(CPACK_RPM_PACKAGE_REQUIRES "openssl, libsecp256k1")
set(CPACK_RPM_DEVEL_PACKAGE_REQUIRES "openssl-devel, libsecp256k1-devel")

# RPM post/pre actions
set(CPACK_RPM_POST_INSTALL_SCRIPT_CMD "/sbin/ldconfig || true")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_CMD "/sbin/ldconfig || true")

# Generate debuginfo package
#set(CPACK_RPM_DEBUGINFO_PACKAGE ON)

# Custom file attributes
set(CPACK_RPM_USER_FILELIST
        "%attr(0755, root, root) %{_bindir}/*"
        "%attr(0644, root, root) %{_libdir}/*.so.*"
        "%attr(0644, root, root) %{_libdir}/*.so"
        "%attr(0644, root, root) %{_libdir}/*.a"
        "%attr(0644, root, root) %{_includedir}/*/*"
)

# RPM component configuration
set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_RPM_MAIN_COMPONENT "release")
set(CPACK_COMPONENTS_GROUPING ONE_PER_GROUP)

# Include CPack module after setting all variables
include(CPack)
