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

#include "kmip_message.h"
#include "kmip_private.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct _parse_stack_t {
   struct _parse_stack_t *parent;
   const uint8_t *buf;
   uint32_t buf_len;
   const uint8_t *pos;
   kmip_tag_t tag;
   kmip_obj_type_t type;
   uint32_t value_len;
   const uint8_t *value;
} parse_stack_t;


struct _kmip_parser_t {
   bool failed;
   char error[512];
   /* the current child object */
   parse_stack_t *stack;
};

static inline void
set_error (kmip_parser_t *parser, const char *fmt, ...)
{
   va_list va;

   parser->failed = true;

   va_start (va, fmt);
   (void) vsnprintf (parser->error, sizeof (parser->error), fmt, va);
   va_end (va);
}

#define CHECK_FAILED        \
   do {                     \
      if (parser->failed) { \
         return false;      \
      }                     \
   } while (0)

/* KMIP objects are TTLV encoded: tag, type, length, value. read the first 3. */
static bool
read_ttl (kmip_parser_t *parser)
{
   size_t remaining;
   uint32_t tag_be;
   uint32_t value_len_be;
   parse_stack_t *stack;

   CHECK_FAILED;

   stack = parser->stack;
   assert (stack);
   remaining = (stack->buf + stack->buf_len) - stack->pos;
   if (remaining == 0) {
      /* done */
      return false;
   }

   if (remaining < 8) {
      set_error (parser,
                 "incomplete reply data: not enough bytes for type,"
                 " tag, and length");
      return false;
   }

   /* tag is 3 bytes */
   tag_be = 0;
#ifdef KMIP_MSG_BIG_ENDIAN
   memcpy (&parser->tag, parser->pos, 3);
#else
   memcpy (((uint8_t *) &tag_be) + 1, stack->pos, 3);
   stack->tag = (kmip_tag_t) uint32_from_be (tag_be);
#endif
   stack->pos += 3;

   /* type is 1 byte */
   memcpy (&stack->type, stack->pos, 1);
   stack->pos += 1;

   /* length is 4 bytes */
   memcpy (&value_len_be, stack->pos, 4);
   stack->value_len = uint32_from_be (value_len_be);
   stack->pos += 4;

   if (stack->value_len > remaining - 8) {
      set_error (parser, "incomplete reply data: not enough bytes for value");
      return false;
   }

   return true;
}

/* read the "V" portion of the TTLV-encoded object */
static bool
read_value (kmip_parser_t *parser)
{
   uint32_t pad_len;
   parse_stack_t *stack;

   CHECK_FAILED;

   stack = parser->stack;
   assert (stack);

   stack->value = stack->pos;
   stack->pos += stack->value_len;
   if (stack->value_len % 8 != 0) {
      pad_len = 8 - stack->value_len % 8;
      stack->pos += pad_len;
   }

   if (stack->pos > stack->buf + stack->buf_len) {
      set_error (parser, "incomplete reply data: not enough bytes for value");
      return false;
   }

   return true;
}

static void
parse_stack_push (kmip_parser_t *parser, const uint8_t *data, uint32_t len)
{
   parse_stack_t *stack = malloc (sizeof (parse_stack_t));

   stack->parent = parser->stack;
   parser->stack = stack;

   stack->buf = stack->pos = data;
   stack->buf_len = len;
   stack->tag = (kmip_tag_t) 0;
   stack->type = (kmip_obj_type_t) 0;
   stack->value_len = 0;
   stack->value = NULL;
}

kmip_parser_t *
kmip_parser_new (const uint8_t *data, uint32_t len)
{
   kmip_parser_t *p = malloc (sizeof (kmip_parser_t));

   p->failed = false;
   p->stack = NULL;
   parse_stack_push (p, data, len);

   return p;
}

void
kmip_parser_destroy (kmip_parser_t *parser)
{
   parse_stack_t *parent, *stack = parser->stack;

   while (stack) {
      parent = stack->parent;
      free (stack);
      stack = parent;
   }

   free (parser);
}

const char *
kmip_parser_get_error (kmip_parser_t *parser)
{
   return parser->failed ? parser->error : NULL;
}

bool
kmip_parser_next (kmip_parser_t *parser)
{
   CHECK_FAILED;

   return read_ttl (parser) && read_value (parser);
}

kmip_tag_t
kmip_parser_tag (kmip_parser_t *parser)
{
   return parser->stack->tag;
}

kmip_obj_type_t
kmip_parser_type (kmip_parser_t *parser)
{
   return parser->stack->type;
}

#define CHECK_TYPE(_type)                                              \
   do {                                                                \
      CHECK_FAILED;                                                    \
      if (parser->stack->type != (_type)) {                            \
         set_error (parser, "called %s for wrong type", __FUNCTION__); \
         return false;                                                 \
      }                                                                \
   } while (0)

bool
kmip_parser_descend (kmip_parser_t *parser)
{
   parse_stack_t *stack;

   CHECK_FAILED;

   stack = parser->stack;
   assert (stack);

   if (stack->type != kmip_obj_type_structure) {
      set_error (parser,
                 "cannot call kmip_parser_descend unless type is struct");
      return false;
   }

   parse_stack_push (parser, stack->value, stack->value_len);

   return true;
}

bool
kmip_parser_ascend (kmip_parser_t *parser)
{
   parse_stack_t *stack;

   CHECK_FAILED;

   stack = parser->stack;
   assert (stack);
   if (!stack->parent) {
      set_error (parser, "too many calls to kmip_parser_ascend");
      return false;
   }

   /* pop the child from the stack */
   parser->stack = stack->parent;
   free (stack);
   return true;
}

bool
kmip_parser_read_int (kmip_parser_t *parser, kmip_msg_int_t *v)
{
   kmip_msg_int_t v_be;

   CHECK_TYPE (kmip_obj_type_integer);

   /* kmip spec v1.4 section 9.1.1.4 "item value": */
   /* Integers are encoded as four-byte long (32 bit) binary signed numbers in
    * 2's complement notation, transmitted big-endian. */
   memcpy (&v_be, parser->stack->value, 4);
   *v = uint32_from_be ((uint32_t) v_be);
   return true;
}

bool
kmip_parser_read_long (kmip_parser_t *parser, kmip_msg_long_t *v)
{
   kmip_msg_long_t v_be;

   CHECK_TYPE (kmip_obj_type_long_integer);

   /* kmip spec v1.4 section 9.1.1.4 "item value": */
   /* Long Integers are encoded as eight-byte long (64 bit) binary signed
    * numbers in 2's complement notation, transmitted big-endian. */
   memcpy (&v_be, parser->stack->value, 8);
   *v = uint64_from_be ((uint64_t) v_be);
   return true;
}

bool
kmip_parser_read_big_int (kmip_parser_t *parser,
                          const uint8_t **v,
                          uint32_t *len)
{
   CHECK_TYPE (kmip_obj_type_big_integer);

   /* kmip spec v1.4 section 9.1.1.4 "item value": */
   /* Big Integers are encoded as a sequence of eight-bit bytes, in two's
    * complement notation, transmitted big-endian. If the length of the
    * sequence is not a multiple of eight bytes, then Big Integers SHALL be
    * padded with the minimal number of leading sign-extended bytes to make the
    * length a multiple of eight bytes. These padding bytes are part of the Item
    * Value and SHALL be counted in the Item Length. */
   *v = parser->stack->value;
   *len = parser->stack->value_len;
   return true;
}

bool
kmip_parser_read_enum (kmip_parser_t *parser, kmip_msg_enum_t *v)
{
   kmip_msg_enum_t v_be;

   CHECK_TYPE (kmip_obj_type_enumeration);

   /* kmip spec v1.4 section 9.1.1.4 "item value": */
   /* Enumerations are encoded as four-byte long (32 bit) binary unsigned
    * numbers transmitted big-endian. Extensions, which are permitted, but are
    * not defined in this specification, contain the value 8 hex in the first
    * nibble of the first byte. */
   memcpy (&v_be, parser->stack->value, 4);
   *v = uint32_from_be ((uint32_t) v_be);
   return true;
}

bool
kmip_parser_read_bool (kmip_parser_t *parser, kmip_msg_bool_t *v)
{
   int64_t v_be;

   CHECK_TYPE (kmip_obj_type_boolean);

   /* kmip spec v1.4 section 9.1.1.4 "item value": */
   /* Booleans are encoded as an eight-byte value that SHALL either contain the
    * hex value 0000000000000000, indicating the Boolean value False, or the
    * hex value 0000000000000001, transmitted big-endian, indicating the
    * Boolean value True. */
   memcpy (&v_be, parser->stack->value, 8);
   *v = (v_be != 0);
   return true;
}

bool
kmip_parser_read_text (kmip_parser_t *parser, const uint8_t **v, uint32_t *len)
{
   CHECK_TYPE (kmip_obj_type_text_string);

   /* kmip spec v1.4 section 9.1.1.4 "item value": */
   /* Text Strings are sequences of bytes that encode character values
    * according to the UTF-8 encoding standard. There SHALL NOT be
    * null-termination at the end of such strings. */
   *v = parser->stack->value;
   *len = parser->stack->value_len;
   return true;
}

bool
kmip_parser_read_bytes (kmip_parser_t *parser, const uint8_t **v, uint32_t *len)
{
   CHECK_TYPE (kmip_obj_type_byte_string);

   /* kmip spec v1.4 section 9.1.1.4 "item value": */
   /* Byte Strings are sequences of bytes containing individual unspecified
    * eight-bit binary values, and are interpreted in the same sequence
    * order. */
   *v = parser->stack->value;
   *len = parser->stack->value_len;
   return true;
}

bool
kmip_parser_read_date_time (kmip_parser_t *parser, kmip_msg_date_time_t *v)
{
   kmip_msg_date_time_t v_be;

   CHECK_TYPE (kmip_obj_type_date_time);

   /* kmip spec v1.4 section 9.1.1.4 "item value": */
   /* Date-Time values are POSIX Time values encoded as Long Integers. POSIX
    * Time, as described in IEEE Standard 1003.1, is the number of seconds since
    * the Epoch (1970 Jan 1, 00:00:00 UTC), not counting leap seconds. */
   memcpy (&v_be, parser->stack->value, 8);
   *v = uint64_from_be ((uint64_t) v_be);
   return true;
}

bool
kmip_parser_read_interval (kmip_parser_t *parser, kmip_msg_interval_t *v)
{
   kmip_msg_interval_t v_be;

   CHECK_TYPE (kmip_obj_type_interval);

   /* kmip spec v1.4 section 9.1.1.4 "item value": */
   /* Intervals are encoded as four-byte long (32 bit) binary unsigned numbers,
    * transmitted big-endian. They have a resolution of one second. */
   memcpy (&v_be, parser->stack->value, 4);
   *v = uint32_from_be ((uint32_t) v_be);
   return true;
}
