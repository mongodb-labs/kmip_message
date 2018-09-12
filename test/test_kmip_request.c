/*
 * Copyright 2018-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "src/kmip_message.h"
#include "test_kmip.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


static void
msg_test (uint8_t *expected, size_t expected_len, kmip_request_t *msg)
{
   uint8_t *buf;
   uint32_t len;
   char *hex_expected;
   char *hex_buf;
   if (kmip_request_get_error (msg)) {
      fprintf (stderr, "Error: [%s]\n", kmip_request_get_error (msg));
      abort ();
   }

   buf = kmip_request_get_data (msg, &len);
   assert (buf);
   hex_buf = hexlify (buf, (size_t) len);
   hex_expected = hexlify (expected, expected_len);
   if (len != expected_len || 0 != memcmp (expected, buf, (size_t) len)) {
      fprintf (stderr, "Expected: %s\n  Actual: %s\n", hex_expected, hex_buf);
      abort ();
   }

   free (hex_buf);
   free (hex_expected);
}

/* tests from kmip spec version 1.4, section 9.1.2 "examples" */

/* An Integer containing the decimal value 8 */
static void
spec_test_0 (void)
{
   size_t len;
   uint8_t *expected = unhexlify ("420020"    /* tag */
                                  "02"        /* type */
                                  "00000004"  /* length */
                                  "00000008"  /* value */
                                  "00000000", /* padding */
                                  &len);
   kmip_request_t *msg = kmip_request_new ();
   assert (kmip_request_add_int (msg, 0x420020, 8));
   msg_test (expected, len, msg);
   kmip_request_destroy (msg);
   free (expected);
}

/* A Long Integer containing the decimal value 123456789000000000 */
static void
spec_test_1 (void)
{
   size_t len;
   uint8_t *expected = unhexlify ("420020"            /* tag */
                                  "03"                /* type */
                                  "00000008"          /* length */
                                  "01B69B4BA5749200", /* value */
                                  &len);
   kmip_request_t *msg = kmip_request_new ();
   assert (kmip_request_add_long (msg, 0x420020, 123456789000000000L));
   msg_test (expected, len, msg);
   kmip_request_destroy (msg);
   free (expected);
}

/* A Big Integer containing the decimal value 1234567890000000000000000000 */
/* see also test_negative_big_int */
static void
spec_test_2 (void)
{
   size_t len;
   uint8_t *expected =
      unhexlify ("420020"                            /* tag */
                 "04"                                /* type */
                 "00000010"                          /* length */
                 "0000000003FD35EB6BC2DF4618080000", /* value */
                 &len);
   kmip_request_t *msg = kmip_request_new ();
   size_t big_int_len;
   uint8_t *big_int = unhexlify ("03FD35EB6BC2DF4618080000", &big_int_len);
   assert (kmip_request_add_big_int (
      msg, 0x420020, big_int, (uint32_t) big_int_len));
   msg_test (expected, len, msg);
   kmip_request_destroy (msg);
   free (big_int);
   free (expected);
}

/* An Enumeration with value 255 */
static void
spec_test_3 (void)
{
   size_t len;
   uint8_t *expected = unhexlify ("420020"    /* tag */
                                  "05"        /* type */
                                  "00000004"  /* length */
                                  "000000FF"  /* value */
                                  "00000000", /* padding */
                                  &len);
   kmip_request_t *msg = kmip_request_new ();
   assert (kmip_request_add_enum (msg, 0x420020, 255));
   msg_test (expected, len, msg);
   kmip_request_destroy (msg);
   free (expected);
}

/* A Boolean with the value True */
static void
spec_test_4 (void)
{
   size_t len;
   uint8_t *expected = unhexlify ("420020"            /* tag */
                                  "06"                /* type */
                                  "00000008"          /* length */
                                  "0000000000000001", /* value */
                                  &len);
   kmip_request_t *msg = kmip_request_new ();
   assert (kmip_request_add_bool (msg, 0x420020, true));
   msg_test (expected, len, msg);
   kmip_request_destroy (msg);
   free (expected);
}

/* A Text String with the value "Hello World" */
static void
spec_test_5 (void)
{
   size_t len;
   uint8_t *expected = unhexlify ("420020"                 /* tag */
                                  "07"                     /* type */
                                  "0000000B"               /* length */
                                  "48656C6C6F20576F726C64" /* value */
                                  "0000000000",            /* padding */
                                  &len);
   kmip_request_t *msg = kmip_request_new ();
   assert (kmip_request_add_text (
      msg, 0x420020, (uint8_t *) "Hello World", 11 /* omit nil */));
   msg_test (expected, len, msg);
   kmip_request_destroy (msg);
   free (expected);
}

/* A Byte String with the value { 0x01, 0x02, 0x03 } */
static void
spec_test_6 (void)
{
   size_t len;
   uint8_t *expected = unhexlify ("420020"      /* tag */
                                  "08"          /* type */
                                  "00000003"    /* length */
                                  "010203"      /* value */
                                  "0000000000", /* padding */
                                  &len);
   kmip_request_t *msg = kmip_request_new ();
   assert (kmip_request_add_bytes (
      msg, 0x420020, (uint8_t *) "\x01\x02\x03", 3 /* omit nil */));
   msg_test (expected, len, msg);
   kmip_request_destroy (msg);
   free (expected);
}

/* A Date-Time, containing the value for Friday, March 14, 2008, 11:56:40 GMT */
static void
spec_test_7 (void)
{
   struct tm tm = {0};
   time_t epoch;
   size_t len;
   uint8_t *expected = unhexlify ("420020"            /* tag */
                                  "09"                /* type */
                                  "00000008"          /* length */
                                  "0000000047DA67F8", /* value */
                                  &len);

   assert (strptime ("2008-03-14 11:56:40 GMT", "%Y-%m-%d %H:%M:%S %Z", &tm));
   epoch = mktime (&tm);
   kmip_request_t *msg = kmip_request_new ();
   assert (
      kmip_request_add_date_time (msg, 0x420020, (kmip_msg_date_time_t) epoch));
   msg_test (expected, len, msg);
   kmip_request_destroy (msg);
   free (expected);
}

/* An Interval, containing the value for 10 days */
static void
spec_test_8 (void)
{
   size_t len;
   uint8_t *expected = unhexlify ("420020"    /* tag */
                                  "0A"        /* type */
                                  "00000004"  /* length */
                                  "000D2F00"  /* value */
                                  "00000000", /* padding */
                                  &len);
   kmip_request_t *msg = kmip_request_new ();
   assert (
      kmip_request_add_interval (msg, 0x420020, 10 * 24 * 3600 /* seconds */));
   msg_test (expected, len, msg);
   kmip_request_destroy (msg);
   free (expected);
}

/* A Structure containing an Enumeration, value 254, followed by an Integer,
 * value 255, having tags 420004 and 420005 respectively */
static void
spec_test_9 (void)
{
   size_t len;
   uint8_t *expected = unhexlify ("420020"    /* struct tag */
                                  "01"        /* struct type */
                                  "00000020"  /* struct length */
                                  "420004"    /* enum tag */
                                  "05"        /* enum type */
                                  "00000004"  /* enum length */
                                  "000000FE"  /* enum value */
                                  "00000000"  /* enum padding  */
                                  "420005"    /* int tag */
                                  "02"        /* int type */
                                  "00000004"  /* int length */
                                  "000000FF"  /* int value */
                                  "00000000", /* int padding */
                                  &len);
   kmip_request_t *msg = kmip_request_new ();
   assert (kmip_request_begin_struct (msg, 0x420020));
   assert (kmip_request_add_enum (msg, 0x420004, 254));
   assert (kmip_request_add_int (msg, 0x420005, 255));
   assert (kmip_request_end_struct (msg));
   msg_test (expected, len, msg);
   kmip_request_destroy (msg);
   free (expected);
}

/* A Big Integer containing the decimal value -123 */
static void
test_negative_big_int (void)
{
   size_t len;
   uint8_t *expected =
      unhexlify ("420020"            /* tag */
                 "04"                /* type */
                 "00000008"          /* length */
                 "FFFFFFFFFFFFFF85", /* left-padded with 1's + value */
                 &len);
   kmip_request_t *msg = kmip_request_new ();
   size_t big_int_len;
   uint8_t *big_int = unhexlify ("FFFFFF85", &big_int_len);
   assert (kmip_request_add_big_int (
      msg, 0x420020, big_int, (uint32_t) big_int_len));
   msg_test (expected, len, msg);
   free (big_int);
   kmip_request_destroy (msg);
   free (expected);
}

static void
test_unclosed_struct (void)
{
   uint32_t len;
   kmip_request_t *msg;
   msg = kmip_request_new ();
   assert (kmip_request_begin_struct (msg, kmip_tag_request_message));
   assert (!kmip_request_get_data (msg, &len));
   assert (strstr (kmip_request_get_error (msg),
                   "Cannot call kmip_request_get_data"));
   kmip_request_destroy (msg);
}

static void
test_struct_end_error (void)
{
   kmip_request_t *msg;
   msg = kmip_request_new ();
   assert (kmip_request_begin_struct (msg, kmip_tag_request_message));
   assert (kmip_request_end_struct (msg));
   assert (!kmip_request_end_struct (msg));
   assert (strstr (kmip_request_get_error (msg),
                   "Too many calls to kmip_request_end_struct"));
   kmip_request_destroy (msg);
}

/* a "get" request for object with unique id "1" */
static void
test_request_get (void)
{
   size_t len;
   /* see kmip spec v1.4 section 6 "message contents", and 7.2 "operations" */
   uint8_t *expected = unhexlify (
      "420078"           /* request message tag */
      "01"               /* struct type */
      "000000a8"         /* length */
      "420077"           /* request header tag */
      "01"               /* struct type */
      "00000070"         /* length */
      "420069"           /* protocol version tag */
      "01"               /* struct type */
      "00000020"         /* length */
      "42006a"           /* protocol version major tag */
      "02"               /* int type */
      "00000004"         /* length */
      "0000000100000000" /* value + padding */
      "42006b02"         /* protocol version minor tag */
      "00000004"         /* length */
      "0000000200000000" /* value + padding */
      /* END protocol version struct */
      "42000c"           /* authentication tag */
      "01"               /* struct type */
      "00000030"         /* length */
      "420023"           /* credential tag */
      "01"               /* struct type */
      "00000028"         /* length */
      "420024"           /* credential type tag */
      "05"               /* enum type */
      "00000004"         /* length */
      "0000000100000000" /* "username_and_password" value + padding */
      "420025"           /* credential value tag */
      "01"               /* struct type */
      "00000010"         /* length */
      "420099"           /* username tag */
      "07"               /* text type */
      "00000000"         /* length, no value */
      "4200a1"           /* password tag */
      "07"               /* text type */
      "00000000"         /* length, no value */
      /* END credential value, credential, auth structs */
      "42000d"            /* batch count tag */
      "02"                /* int type */
      "00000004"          /* length */
      "0000000100000000"  /* value + padding */
      "42000f"            /* batch item tag */
      "01"                /* struct type */
      "00000028"          /* length */
      "42005c"            /* operation tag */
      "05"                /* enum type */
      "00000004"          /* length */
      "0000000a00000000"  /* "get" value + padding */
      "420079"            /* request payload tag */
      "01"                /* struct type */
      "00000010"          /* length */
      "420094"            /* unique identifier tag */
      "07"                /* text type */
      "00000001"          /* length */
      "3100000000000000", /* ASCII "1" value + padding */
      /* END request payload, batch item, request message structs */
      &len);

   kmip_request_t *msg = kmip_request_new ();
   assert (kmip_request_begin_struct (msg, kmip_tag_request_message));
   assert (kmip_request_begin_struct (msg, kmip_tag_request_header));
   assert (kmip_request_begin_struct (msg, kmip_tag_protocol_version));
   assert (kmip_request_add_int (msg, kmip_tag_protocol_version_major, 1));
   assert (kmip_request_add_int (msg, kmip_tag_protocol_version_minor, 2));
   assert (kmip_request_end_struct (msg)); /* protocol_version */
   assert (kmip_request_begin_struct (msg, kmip_tag_authentication));
   assert (kmip_request_begin_struct (msg, kmip_tag_credential));
   assert (kmip_request_add_enum (msg,
                                  kmip_tag_credential_type,
                                  kmip_credential_type_username_and_password));
   assert (kmip_request_begin_struct (msg, kmip_tag_credential_value));
   assert (kmip_request_add_text (msg, kmip_tag_username, (uint8_t *) "", 0));
   assert (kmip_request_add_text (msg, kmip_tag_password, (uint8_t *) "", 0));
   assert (kmip_request_end_struct (msg)); /* credential_value */
   assert (kmip_request_end_struct (msg)); /* credential */
   assert (kmip_request_end_struct (msg)); /* authentication */
   assert (kmip_request_add_int (msg, kmip_tag_batch_count, 1));
   assert (kmip_request_end_struct (msg)); /* request_header */
   assert (kmip_request_begin_struct (msg, kmip_tag_batch_item));
   assert (kmip_request_add_enum (msg, kmip_tag_operation, kmip_operation_get));
   assert (kmip_request_begin_struct (msg, kmip_tag_request_payload));
   assert (kmip_request_add_text (
      msg, kmip_tag_unique_identifier, (uint8_t *) "1", 1));
   assert (kmip_request_end_struct (msg)); /* request_payload */
   assert (kmip_request_end_struct (msg)); /* batch_item */
   assert (kmip_request_end_struct (msg)); /* request_message */
   msg_test (expected, len, msg);
   kmip_request_destroy (msg);
   free (expected);
}

int
main (void)
{
   RUN_TEST (spec_test_0);
   RUN_TEST (spec_test_1);
   RUN_TEST (spec_test_2);
   RUN_TEST (spec_test_3);
   RUN_TEST (spec_test_4);
   RUN_TEST (spec_test_5);
   RUN_TEST (spec_test_6);
   RUN_TEST (spec_test_7);
   RUN_TEST (spec_test_8);
   RUN_TEST (spec_test_9);
   RUN_TEST (test_negative_big_int);
   RUN_TEST (test_unclosed_struct);
   RUN_TEST (test_struct_end_error);
   RUN_TEST (test_request_get);
}
