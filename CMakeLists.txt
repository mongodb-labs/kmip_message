cmake_minimum_required (VERSION 3.1)
project (kmip_message
   LANGUAGES C
   VERSION 0.0.1
   DESCRIPTION "Library to parse and generate Key Management Interoperability Protocol (KMIP) messages"
)

set (CMAKE_C_STANDARD 90)

include (CheckCCompilerFlag)
# All targets obey visibility, not just library targets.
cmake_policy (SET CMP0063 NEW)
set (CMAKE_C_VISIBILITY_PRESET hidden)
add_library (
   kmip_message SHARED
   src/kmip_message/hexlify.h
   src/kmip_message/kmip_message.h
   src/kmip_message/kmip_parser.h
   src/kmip_message/kmip_private.h
   src/kmip_message/kmip_request.h
   src/hexlify.c
   src/kmip_message.c
   src/kmip_parser.c
   src/kmip_request.c
)

include (TestBigEndian)
test_big_endian (KMIP_MSG_BIG_ENDIAN)
if (KMIP_MSG_BIG_ENDIAN)
   target_compile_definitions (kmip_message -DKMIP_MSG_BIG_ENDIAN)
endif ()

target_include_directories (
   kmip_message PRIVATE
   ${PROJECT_SOURCE_DIR}/src
   ${CMAKE_CURRENT_BINARY_DIR}
)

set_target_properties (kmip_message PROPERTIES
   SOVERSION 0
   OUTPUT_NAME "kmip_message"
   PREFIX "lib"
   INTERFACE_kmip_message_MAJOR_VERSION 0
)

target_compile_definitions (kmip_message PRIVATE KMIP_MSG_COMPILATION)
set_property (TARGET kmip_message APPEND PROPERTY
   COMPATIBLE_INTERFACE_STRING kmip_message_MAJOR_VERSION
)

include (CMakePackageConfigHelpers)
install (TARGETS kmip_message
   EXPORT kmip_message_targets
   LIBRARY DESTINATION lib
   ARCHIVE DESTINATION lib
   RUNTIME DESTINATION bin
   INCLUDES DESTINATION include
)

install (
   FILES
   src/kmip_message/kmip_message.h
   src/kmip_message/kmip_parser.h
   src/kmip_message/kmip_request.h
   DESTINATION include/kmip_message
   COMPONENT Devel
)

include (CMakePackageConfigHelpers)
write_basic_package_version_file (
   "${CMAKE_CURRENT_BINARY_DIR}/kmip_message/kmip_message-config-version.cmake"
   VERSION 0.0.1
   COMPATIBILITY AnyNewerVersion
)

export (EXPORT kmip_message_targets
   FILE "${CMAKE_CURRENT_BINARY_DIR}/kmip_message/kmip_message_targets.cmake"
)

configure_file (cmake/kmip_message-config.cmake
   "${CMAKE_CURRENT_BINARY_DIR}/kmip_message/kmip_message-config.cmake"
   COPYONLY
)

set (ConfigPackageLocation lib/cmake/kmip_message)
install (EXPORT kmip_message_targets
   FILE kmip_message_targets.cmake
   DESTINATION ${ConfigPackageLocation}
)

install (
   FILES
   cmake/kmip_message-config.cmake
   "${CMAKE_CURRENT_BINARY_DIR}/kmip_message/kmip_message-config-version.cmake"
   DESTINATION ${ConfigPackageLocation}
   COMPONENT Devel
)

# pkg-config.
set (PKG_CONFIG_LIBDIR "\${prefix}/lib")
set (PKG_CONFIG_INCLUDEDIR "\${prefix}/include")
set (PKG_CONFIG_LIBS "-L\${libdir} -lkmip_message")
set (PKG_CONFIG_CFLAGS "-I\${includedir}")
configure_file (
   "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libkmip_message.pc.in"
   "${CMAKE_CURRENT_BINARY_DIR}/libkmip_message.pc"
)

install (
   FILES "${CMAKE_BINARY_DIR}/libkmip_message.pc"
   DESTINATION lib/pkgconfig
)

add_executable (
   test_kmip_parser
   src/hexlify.c
   src/kmip_message/hexlify.h
   test/test_kmip.h
   test/test_kmip_parser.c
)

target_link_libraries (test_kmip_parser kmip_message)
target_include_directories (
   test_kmip_parser PRIVATE
   ${CMAKE_CURRENT_SOURCE_DIR}/src
   ${CMAKE_CURRENT_BINARY_DIR}
)

add_executable (
   test_kmip_request
   src/hexlify.c
   src/kmip_message/hexlify.h
   test/test_kmip.h
   test/test_kmip_request.c
)

target_link_libraries (test_kmip_request kmip_message)
target_include_directories (
   test_kmip_request PRIVATE
   ${CMAKE_CURRENT_SOURCE_DIR}/src
   ${CMAKE_CURRENT_BINARY_DIR}
)
