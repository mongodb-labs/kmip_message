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
#include "hexlify.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* tests from kmip spec version 1.4, section 9.1.2 "examples" */

/* An Integer containing the decimal value 8 */
static void
spec_test_0 (void)
{
   size_t len;
   kmip_msg_int_t v;
   uint8_t *reply = unhexlify ("420020"    /* tag */
                               "02"        /* type */
                               "00000004"  /* length */
                               "00000008"  /* value */
                               "00000000", /* padding */
                               &len);
   kmip_parser_t *parser = kmip_parser_new (reply, (uint32_t) len);
   assert (kmip_parser_next (parser));
   assert (kmip_parser_type (parser) == kmip_obj_type_integer);
   assert (kmip_parser_tag (parser) == 0x420020);
   assert (kmip_parser_read_int (parser, &v));
   assert (v == 8);
   assert (!kmip_parser_next (parser));
   kmip_parser_destroy (parser);
   free (reply);
}

/* A Long Integer containing the decimal value 123456789000000000 */
static void
spec_test_1 (void)
{
   size_t len;
   kmip_msg_long_t v;
   uint8_t *reply = unhexlify ("420020"            /* tag */
                               "03"                /* type */
                               "00000008"          /* length */
                               "01B69B4BA5749200", /* value */
                               &len);
   kmip_parser_t *parser = kmip_parser_new (reply, (uint32_t) len);
   assert (kmip_parser_next (parser));
   assert (kmip_parser_type (parser) == kmip_obj_type_long_integer);
   assert (kmip_parser_tag (parser) == 0x420020);
   assert (kmip_parser_read_long (parser, &v));
   assert (v == 0x01B69B4BA5749200);
   assert (!kmip_parser_next (parser));
   kmip_parser_destroy (parser);
   free (reply);
}

/* A Big Integer containing the decimal value 1234567890000000000000000000 */
/* see also test_negative_big_int */
static void
spec_test_2 (void)
{
   uint32_t v_len;
   const uint8_t *v;
   size_t expected_len;
   uint8_t *expected_v =
      unhexlify ("0000000003FD35EB6BC2DF4618080000", &expected_len);
   size_t len;
   uint8_t *reply = unhexlify ("420020"                            /* tag */
                               "04"                                /* type */
                               "00000010"                          /* length */
                               "0000000003FD35EB6BC2DF4618080000", /* value */
                               &len);
   kmip_parser_t *parser = kmip_parser_new (reply, (uint32_t) len);
   assert (kmip_parser_next (parser));
   assert (kmip_parser_type (parser) == kmip_obj_type_big_integer);
   assert (kmip_parser_tag (parser) == 0x420020);
   assert (kmip_parser_read_big_int (parser, &v, &v_len));
   assert ((uint32_t) expected_len == v_len);
   assert (0 == memcmp (expected_v, v, expected_len));
   assert (!kmip_parser_next (parser));
   kmip_parser_destroy (parser);
   free (reply);
   free (expected_v);
}

/* An Enumeration with value 255 */
static void
spec_test_3 (void)
{
   kmip_msg_enum_t v;
   size_t len;
   uint8_t *reply = unhexlify ("420020"    /* tag */
                               "05"        /* type */
                               "00000004"  /* length */
                               "000000FF"  /* value */
                               "00000000", /* padding */
                               &len);
   kmip_parser_t *parser = kmip_parser_new (reply, (uint32_t) len);
   assert (kmip_parser_next (parser));
   assert (kmip_parser_type (parser) == kmip_obj_type_enumeration);
   assert (kmip_parser_tag (parser) == 0x420020);
   assert (kmip_parser_read_enum (parser, &v));
   assert (v == 255);
   assert (!kmip_parser_next (parser));
   kmip_parser_destroy (parser);
   free (reply);
}

/* A Boolean with the value True */
static void
spec_test_4 (void)
{
   kmip_msg_bool_t v;
   size_t len;
   uint8_t *reply = unhexlify ("420020"            /* tag */
                               "06"                /* type */
                               "00000008"          /* length */
                               "0000000000000001", /* value */
                               &len);
   kmip_parser_t *parser = kmip_parser_new (reply, (uint32_t) len);
   assert (kmip_parser_next (parser));
   assert (kmip_parser_type (parser) == kmip_obj_type_boolean);
   assert (kmip_parser_tag (parser) == 0x420020);
   assert (kmip_parser_read_bool (parser, &v));
   assert (v);
   assert (!kmip_parser_next (parser));
   kmip_parser_destroy (parser);
   free (reply);
}

/* A Text String with the value "Hello World" */
static void
spec_test_5 (void)
{
   uint32_t v_len;
   const uint8_t *v;
   size_t len;
   uint8_t *reply = unhexlify ("420020"                 /* tag */
                               "07"                     /* type */
                               "0000000B"               /* length */
                               "48656C6C6F20576F726C64" /* value */
                               "0000000000",            /* padding */
                               &len);
   kmip_parser_t *parser = kmip_parser_new (reply, (uint32_t) len);
   assert (kmip_parser_next (parser));
   assert (kmip_parser_type (parser) == kmip_obj_type_text_string);
   assert (kmip_parser_tag (parser) == 0x420020);
   assert (kmip_parser_read_text (parser, &v, &v_len));
   assert (strlen ("Hello World") == v_len);
   assert (0 == strncmp ("Hello World", (const char *) v, v_len));
   assert (!kmip_parser_next (parser));
   kmip_parser_destroy (parser);
   free (reply);
}

/* A Byte String with the value { 0x01, 0x02, 0x03 } */
static void
spec_test_6 (void)
{
   uint32_t v_len;
   const uint8_t *v;
   size_t len;
   uint8_t *reply = unhexlify ("420020"      /* tag */
                               "08"          /* type */
                               "00000003"    /* length */
                               "010203"      /* value */
                               "0000000000", /* padding */
                               &len);
   kmip_parser_t *parser = kmip_parser_new (reply, (uint32_t) len);
   assert (kmip_parser_next (parser));
   assert (kmip_parser_type (parser) == kmip_obj_type_byte_string);
   assert (kmip_parser_tag (parser) == 0x420020);
   assert (kmip_parser_read_bytes (parser, &v, &v_len));
   assert (3 == v_len);
   assert (0 == memcmp ("\x01\x02\x03", v, 3));
   assert (!kmip_parser_next (parser));
   kmip_parser_destroy (parser);
   free (reply);
}

/* A Date-Time, containing the value for Friday, March 14, 2008, 11:56:40 GMT */
static void
spec_test_7 (void)
{
   kmip_msg_date_time_t v;
   struct tm tm;
   time_t epoch;
   size_t len;
   uint8_t *reply = unhexlify ("420020"            /* tag */
                               "09"                /* type */
                               "00000008"          /* length */
                               "0000000047DA67F8", /* value */
                               &len);

   assert (strptime ("2008-03-14 11:56:40 GMT", "%Y-%m-%d %H:%M:%S %Z", &tm));
   epoch = mktime (&tm);
   kmip_parser_t *parser = kmip_parser_new (reply, (uint32_t) len);
   assert (kmip_parser_next (parser));
   assert (kmip_parser_type (parser) == kmip_obj_type_date_time);
   assert (kmip_parser_tag (parser) == 0x420020);
   assert (kmip_parser_read_date_time (parser, &v));
   assert (v == (kmip_msg_date_time_t) epoch);
   assert (!kmip_parser_next (parser));
   kmip_parser_destroy (parser);
   free (reply);
}

/* An Interval, containing the value for 10 days */
static void
spec_test_8 (void)
{
   kmip_msg_interval_t v;
   size_t len;
   uint8_t *reply = unhexlify ("420020"    /* tag */
                               "0A"        /* type */
                               "00000004"  /* length */
                               "000D2F00"  /* value */
                               "00000000", /* padding */
                               &len);
   kmip_parser_t *parser = kmip_parser_new (reply, (uint32_t) len);
   assert (kmip_parser_next (parser));
   assert (kmip_parser_type (parser) == kmip_obj_type_interval);
   assert (kmip_parser_tag (parser) == 0x420020);
   assert (kmip_parser_read_interval (parser, &v));
   assert (v == 10 * 24 * 3600 /* seconds */);
   assert (!kmip_parser_next (parser));
   kmip_parser_destroy (parser);
   free (reply);
}

/* A Structure containing an Enumeration, value 254, followed by an Integer,
 * value 255, having tags 420004 and 420005 respectively */
static void
spec_test_9 (void)
{
   size_t len;
   kmip_parser_t *child;
   kmip_msg_enum_t v_enum;
   kmip_msg_int_t v_int;
   uint8_t *reply = unhexlify ("420020"    /* struct tag */
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
   kmip_parser_t *parser = kmip_parser_new (reply, (uint32_t) len);
   assert (kmip_parser_next (parser));
   assert (kmip_parser_type (parser) == kmip_obj_type_structure);
   assert (kmip_parser_tag (parser) == 0x420020);
   child = kmip_parser_read_struct (parser);
   assert (child);
   assert (kmip_parser_next (child));
   assert (kmip_parser_type (child) == kmip_obj_type_enumeration);
   assert (kmip_parser_tag (child) == 0x420004);
   assert (kmip_parser_read_enum (child, &v_enum));
   assert (v_enum == 254);
   assert (kmip_parser_next (child));
   assert (kmip_parser_type (child) == kmip_obj_type_integer);
   assert (kmip_parser_tag (child) == 0x420005);
   assert (kmip_parser_read_int (child, &v_int));
   assert (v_int == 255);
   assert (!kmip_parser_next (child));
   assert (!kmip_parser_next (parser));
   kmip_parser_destroy (child);
   assert (!kmip_parser_next (parser));
   kmip_parser_destroy (parser);
   free (reply);
}

/* A Big Integer containing the decimal value -123 */
static void
test_negative_big_int (void)
{
   uint32_t v_len;
   const uint8_t *v;
   size_t expected_len;
   uint8_t *expected_v = unhexlify ("FFFFFFFFFFFFFF85", &expected_len);
   size_t len;
   uint8_t *reply =
      unhexlify ("420020"            /* tag */
                 "04"                /* type */
                 "00000008"          /* length */
                 "FFFFFFFFFFFFFF85", /* left-padded with 1's + value */
                 &len);
   kmip_parser_t *parser = kmip_parser_new (reply, (uint32_t) len);
   assert (kmip_parser_next (parser));
   assert (kmip_parser_type (parser) == kmip_obj_type_big_integer);
   assert (kmip_parser_tag (parser) == 0x420020);
   assert (kmip_parser_read_big_int (parser, &v, &v_len));
   assert ((uint32_t) expected_len == v_len);
   assert (0 == memcmp (expected_v, v, expected_len));
   assert (!kmip_parser_next (parser));
   kmip_parser_destroy (parser);
   free (reply);
   free (expected_v);
}

/* a "get" request for object with unique id "1" */
static void
test_request_get (void)
{
   size_t len;
   kmip_parser_t *request_message, *request_header, *protocol_version,
      *authentication, *credential, *credential_value, *batch_item,
      *request_payload;
   kmip_msg_int_t v_int;
   kmip_msg_enum_t v_enum;
   const uint8_t *v_bytes;
   uint32_t v_len;
   /* see kmip spec v1.4 section 6 "message contents", and 7.2 "operations" */
   uint8_t *reply = unhexlify (
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

   kmip_parser_t *parser = kmip_parser_new (reply, (uint32_t) len);
   assert (kmip_parser_next (parser));
   assert (kmip_parser_tag (parser) == kmip_tag_request_message);
   /*
    *  REQUEST_MESSAGE
    */
   request_message = kmip_parser_read_struct (parser);
   assert (request_message);
   assert (kmip_parser_next (request_message));
   assert (kmip_parser_tag (request_message) == kmip_tag_request_header);
   /*
    *        REQUEST_HEADER
    */
   request_header = kmip_parser_read_struct (request_message);
   assert (request_header);
   assert (kmip_parser_next (request_header));
   /*
    *              PROTOCOL_VERSION
    */
   protocol_version = kmip_parser_read_struct (request_header);
   assert (protocol_version);
   assert (kmip_parser_next (protocol_version));
   assert (kmip_parser_tag (protocol_version) == kmip_tag_protocol_version_major);
   assert (kmip_parser_read_int (protocol_version, &v_int));
   assert (v_int == 1);
   assert (kmip_parser_next (protocol_version));
   assert (kmip_parser_tag (protocol_version) == kmip_tag_protocol_version_minor);
   assert (kmip_parser_read_int (protocol_version, &v_int));
   assert (v_int == 2);
   assert (!kmip_parser_next (protocol_version));
   kmip_parser_destroy (protocol_version);
   /*
    *             /PROTOCOL_VERSION
    */
   assert (kmip_parser_next (request_header));
   /*
    *              AUTHENTICATION
    */
   authentication = kmip_parser_read_struct (request_header);
   assert (authentication);
   assert (kmip_parser_next (authentication));
   /*
    *                    CREDENTIAL
    */
   credential = kmip_parser_read_struct (authentication);
   assert (credential);
   assert (kmip_parser_next (credential));
   assert (kmip_parser_type (credential) == kmip_obj_type_enumeration);
   assert (kmip_parser_read_enum (credential, &v_enum));
   assert (v_enum == kmip_credential_type_username_and_password);
   assert (kmip_parser_next (credential));
   /*
    *                          CREDENTIAL_VALUE
    */
   credential_value = kmip_parser_read_struct (credential);
   assert (credential_value);
   assert (kmip_parser_next (credential_value));
   assert (kmip_parser_tag (credential_value) == kmip_tag_username);
   assert (kmip_parser_read_text (credential_value, &v_bytes, &v_len));
   assert (v_len == 0);
   assert (0 == strncmp ((const char *)v_bytes, "", v_len));
   assert (kmip_parser_next (credential_value));
   assert (kmip_parser_tag (credential_value) == kmip_tag_password);
   assert (kmip_parser_read_text (credential_value, &v_bytes, &v_len));
   assert (v_len == 0);
   assert (0 == strncmp ((const char *)v_bytes, "", v_len));
   assert (!kmip_parser_next (credential_value));
   kmip_parser_destroy (credential_value);
   assert (!kmip_parser_next (credential));
   kmip_parser_destroy (credential);
   assert (!kmip_parser_next(authentication));
   /*
    *                         /CREDENTIAL_VALUE
    *                   /CREDENTIAL
    *             /AUTHENTICATION
    *       /REQUEST_HEADER
    */
   assert (kmip_parser_next (request_header));
   assert (kmip_parser_tag (request_header) == kmip_tag_batch_count);
   assert (kmip_parser_read_int (request_header, &v_int));
   assert (v_int == 1);
   assert (!kmip_parser_next (request_header));
   kmip_parser_destroy (request_header);
   /*
    *       BATCH_ITEM
    */
   assert (kmip_parser_next (request_message));
   batch_item = kmip_parser_read_struct (request_message);
   assert (batch_item);
   assert (kmip_parser_next (batch_item));
   assert (kmip_parser_type (batch_item) == kmip_obj_type_enumeration);
   assert (kmip_parser_read_enum (batch_item, &v_enum));
   assert (v_enum == kmip_operation_get);
   assert (kmip_parser_next (batch_item));
   /*
    *              REQUEST_PAYLOAD
    */
   request_payload = kmip_parser_read_struct (batch_item);
   assert (request_payload);
   assert (kmip_parser_next (request_payload));
   assert (kmip_parser_tag (request_payload) == kmip_tag_unique_identifier);
   assert (kmip_parser_read_text (request_payload, &v_bytes, &v_len));
   assert (v_len == 1);
   assert (0 == strncmp ((const char *)v_bytes, "1", v_len));
   assert (!kmip_parser_next (request_payload));
   kmip_parser_destroy (request_payload);
   assert (!kmip_parser_next (batch_item));
   kmip_parser_destroy (batch_item);
   assert (!kmip_parser_next (request_message));
   kmip_parser_destroy (request_message);
   assert (!kmip_parser_next (parser));
   kmip_parser_destroy (parser);
   /*
    *             /REQUEST_PAYLOAD
    *       /BATCH_ITEM
    * /REQUEST_MESSAGE
    */
   free (reply);
}

int
main (void)
{
   spec_test_0 ();
   spec_test_1 ();
   spec_test_2 ();
   spec_test_3 ();
   spec_test_4 ();
   spec_test_5 ();
   spec_test_6 ();
   spec_test_7 ();
   spec_test_8 ();
   spec_test_9 ();
   test_negative_big_int ();
   test_request_get ();
}

/* TODO: test all errs */
/* TODO: memcheck */
