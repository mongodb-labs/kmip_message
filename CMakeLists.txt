cmake_minimum_required (VERSION 3.1)
project (kmip_message C)

set (CMAKE_C_STANDARD 90)

add_library (
   kmip_message SHARED
   src/kmip_message.h
   src/kmip_parser.c
   src/kmip_parser.h
   src/kmip_request.c
   src/kmip_request.h
)

include (TestBigEndian)
test_big_endian (KMIP_MSG_BIG_ENDIAN)
if (KMIP_MSG_BIG_ENDIAN)
   target_compile_definitions (kmip_message -DKMIP_MSG_BIG_ENDIAN)
endif ()

add_executable (
   test_kmip_parser
   test/test_kmip.c
   test/test_kmip.h
   test/test_kmip_parser.c
)

target_link_libraries (test_kmip_parser kmip_message)
target_include_directories (test_kmip_parser PRIVATE ${PROJECT_SOURCE_DIR})

add_executable (
   test_kmip_request
   test/test_kmip.c
   test/test_kmip.h
   test/test_kmip_request.c
)

target_link_libraries (test_kmip_request kmip_message)
target_include_directories (test_kmip_request PRIVATE ${PROJECT_SOURCE_DIR})
