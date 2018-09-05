cmake_minimum_required (VERSION 3.1)
project (kmip_message C)

set (CMAKE_C_STANDARD 90)

add_library (
   kmip_message SHARED
   src/kmip_message.h
   src/kmip_request.c
   src/kmip_request.h
)

include (TestBigEndian)
test_big_endian (KMIP_MSG_BIG_ENDIAN)
if (KMIP_MSG_BIG_ENDIAN)
   target_compile_definitions (kmip_message -DKMIP_MSG_BIG_ENDIAN)
endif ()

add_executable (
   kmip_message_test
   test/kmip_test.c
)

target_link_libraries (kmip_message_test kmip_message)
target_include_directories (kmip_message_test PRIVATE ${PROJECT_SOURCE_DIR})
