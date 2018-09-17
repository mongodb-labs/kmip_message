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

#include "kmip_message/kmip_message.h"
#include "kmip_message/kmip_private.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct _obj_stack_t {
   struct _obj_stack_t *parent;
   uint8_t *obj_len;
} obj_stack_t;

struct _kmip_request_t {
   uint8_t *buf;
   uint32_t buf_len;
   uint8_t *pos;
   /* the current child object */
   obj_stack_t *obj_stack;
   bool failed;
   char error[512];
};

static inline void
set_error (kmip_request_t *msg, const char *fmt, ...)
{
   va_list va;

   msg->failed = true;

   va_start (va, fmt);
   (void) vsnprintf (msg->error, sizeof (msg->error), fmt, va);
   va_end (va);
}

#define CHECK_FAILED     \
   do {                  \
      if (msg->failed) { \
         return false;   \
      }                  \
   } while (0)

static bool
reserve_buf (kmip_request_t *msg, uint32_t length)
{
   uint32_t next_length = length;
   if (msg->buf_len < next_length) {
      /* next power of 2 */
      next_length--;
      next_length |= next_length >> 1U;
      next_length |= next_length >> 2U;
      next_length |= next_length >> 4U;
      next_length |= next_length >> 8U;
      next_length |= next_length >> 16U;
      next_length++;

      msg->buf_len = next_length;
      msg->buf = realloc (msg->buf, (size_t) next_length);
      if (!msg->buf) {
         set_error (
            msg, "Could not grow message to %" PRIu32 " bytes", next_length);
         return false;
      }
   }

   return true;
}

/* KMIP objects are TTLV encoded: tag, type, length, value. write the first 3,
 * and return a pointer to the length bytes in the request buffer. */
static bool
add_ttl (kmip_request_t *msg,
         kmip_request_tag_t tag,
         kmip_obj_type_t obj_type,
         uint32_t obj_len,
         uint8_t **obj_len_ptr /* OUT */)
{
   uint32_t total = (uint32_t) sizeof (tag) + 3 /* tag */ + obj_len;
   uint32_t tag_be;
   uint32_t obj_len_be;

   CHECK_FAILED;

   if (!reserve_buf (msg, total)) {
      return false;
   }

   tag_be = uint32_to_be (tag);

   /* tag is 3 bytes */
   memcpy (msg->pos, (uint8_t *) &tag_be + 1, 3);
   msg->pos += 3;

   /* type is 1 byte */
   *(msg->pos) = (uint8_t) obj_type;
   msg->pos += 1;

   /* length is 4 bytes */
   obj_len_be = uint32_to_be (obj_len);
   memcpy (msg->pos, &obj_len_be, 4);
   if (obj_len_ptr) {
      *obj_len_ptr = msg->pos;
   }

   msg->pos += 4;

   return true;
}

/* write the "V" portion of the TTLV-encoded object */
static bool
add_value (kmip_request_t *msg, uint32_t obj_len, const uint8_t *value)
{
   uint32_t pad_len;

   memcpy (msg->pos, value, (size_t) obj_len);
   msg->pos += obj_len;

   /* pad all objects to 8 bytes, kmip_message spec v1.4 section 9.1.1.3: item length */
   if (obj_len % 8 != 0) {
      pad_len = 8 - obj_len % 8;
      memset (msg->pos, 0, pad_len);
      msg->pos += pad_len;
   }

   return true;
}

static bool
add_object (kmip_request_t *msg,
            kmip_request_tag_t tag,
            kmip_obj_type_t obj_type,
            uint32_t obj_len,
            const uint8_t *value)
{
   CHECK_FAILED;

   return add_ttl (msg, tag, obj_type, obj_len, NULL) &&
          add_value (msg, obj_len, value);
}

kmip_request_t *
kmip_request_new (void)
{
   kmip_request_t *r = malloc (sizeof (kmip_request_t));
   r->buf_len = 256;
   r->buf = malloc (r->buf_len);
   r->pos = r->buf;
   r->obj_stack = NULL;
   r->failed = false;
   return r;
}

void
kmip_request_destroy (kmip_request_t *msg)
{
   obj_stack_t *parent, *child = msg->obj_stack;

   while (child) {
      parent = child->parent;
      free (child);
      child = parent;
   }

   free (msg->buf);
   free (msg);
}

uint8_t *
kmip_request_get_data (kmip_request_t *msg, uint32_t *len)
{
   if (msg->obj_stack) {
      set_error (msg,
                 "%s",
                 "Cannot call kmip_request_get_data until all "
                 "kmip_request_begin_struct calls are matched by "
                 "kmip_request_end_struct calls");
      return NULL;
   }

   *len = (uint32_t) (msg->pos - msg->buf);
   return msg->buf;
}

const char *
kmip_request_get_error (kmip_request_t *msg)
{
   return msg->failed ? msg->error : NULL;
}

bool
kmip_request_begin_struct (kmip_request_t *msg, kmip_request_tag_t tag)
{
   obj_stack_t *child = malloc (sizeof (obj_stack_t));
   child->parent = msg->obj_stack;
   msg->obj_stack = child;

   /* call add_object and set child->obj_len to the right pointer */
   return add_ttl (
      msg, tag, kmip_obj_type_structure, 0 /* obj_len */, &child->obj_len);
}

bool
kmip_request_end_struct (kmip_request_t *msg)
{
   obj_stack_t *child;
   uint8_t *struct_start;
   uint32_t len_be;

   CHECK_FAILED;

   child = msg->obj_stack;
   if (!child) {
      set_error (msg, "Too many calls to kmip_request_end_struct");
      return false;
   }

   /* the struct begins after the buffer position where its length prefix is
    * stored, and ends at the byte before the current buffer position. */
   struct_start = msg->obj_stack->obj_len + 4;
   len_be = uint32_to_be ((uint32_t) (msg->pos - struct_start));
   memcpy (child->obj_len, &len_be, 4);

   /* pop the child from the stack */
   msg->obj_stack = child->parent;
   free (child);
   return true;
}

bool
kmip_request_add_int (kmip_request_t *msg,
                      kmip_request_tag_t tag,
                      kmip_msg_int_t v)
{
   /* kmip_message spec v1.4 section 9.1.1.4 "item value": */
   /* Integers are encoded as four-byte long (32 bit) binary signed numbers in
    * 2's complement notation, transmitted big-endian. */
   kmip_msg_int_t v_be = (kmip_msg_int_t) uint32_to_be ((uint32_t) v);
   return add_object (
      msg, tag, kmip_obj_type_integer, 4, (const uint8_t *) &v_be);
}

bool
kmip_request_add_long (kmip_request_t *msg,
                       kmip_request_tag_t tag,
                       kmip_msg_long_t v)
{
   /* kmip_message spec v1.4 section 9.1.1.4 "item value": */
   /* Long Integers are encoded as eight-byte long (64 bit) binary signed
    * numbers in 2's complement notation, transmitted big-endian. */
   kmip_msg_long_t v_be = (kmip_msg_long_t) uint64_to_be ((uint64_t) v);
   return add_object (
      msg, tag, kmip_obj_type_long_integer, 8, (const uint8_t *) &v_be);
}

bool
kmip_request_add_big_int (kmip_request_t *msg,
                          kmip_request_tag_t tag,
                          const uint8_t *v,
                          uint32_t len)
{
   /* kmip_message spec v1.4 section 9.1.1.4 "item value": */
   /* Big Integers are encoded as a sequence of eight-bit bytes, in two's
    * complement notation, transmitted big-endian. If the length of the
    * sequence is not a multiple of eight bytes, then Big Integers SHALL be
    * padded with the minimal number of leading sign-extended bytes to make the
    * length a multiple of eight bytes. These padding bytes are part of the Item
    * Value and SHALL be counted in the Item Length. */
   if (len % 8) {
      uint32_t pad_len = 8 - len % 8;
      uint8_t *padded = malloc (len + pad_len);
      bool r;

      if (v[0] & 0x80U) {
         /* first bit is 1, v is negative */
         memset (padded, 0xff, pad_len);
      } else {
         memset (padded, 0, pad_len);
      }

      memcpy (padded + pad_len, v, len);
      r = add_object (
         msg, tag, kmip_obj_type_big_integer, len + pad_len, padded);

      free (padded);
      return r;
   } else {
      /* len is already a multiple of 8 bytes */
      return add_object (msg, tag, kmip_obj_type_big_integer, len, v);
   }
}

bool
kmip_request_add_enum (kmip_request_t *msg,
                       kmip_request_tag_t tag,
                       kmip_msg_enum_t v)
{
   /* kmip_message spec v1.4 section 9.1.1.4 "item value": */
   /* Enumerations are encoded as four-byte long (32 bit) binary unsigned
    * numbers transmitted big-endian. Extensions, which are permitted, but are
    * not defined in this specification, contain the value 8 hex in the first
    * nibble of the first byte. */
   kmip_msg_enum_t v_be = (kmip_msg_enum_t) uint32_to_be ((uint32_t) v);
   return add_object (
      msg, tag, kmip_obj_type_enumeration, 4, (const uint8_t *) &v_be);
}

bool
kmip_request_add_bool (kmip_request_t *msg,
                       kmip_request_tag_t tag,
                       kmip_msg_bool_t v)
{
   /* kmip_message spec v1.4 section 9.1.1.4 "item value": */
   /* Booleans are encoded as an eight-byte value that SHALL either contain the
    * hex value 0000000000000000, indicating the Boolean value False, or the
    * hex value 0000000000000001, transmitted big-endian, indicating the
    * Boolean value True. */
   uint64_t v_be = uint64_to_be (v ? 1 : 0);
   return add_object (
      msg, tag, kmip_obj_type_boolean, 8, (const uint8_t *) &v_be);
}

bool
kmip_request_add_text (kmip_request_t *msg,
                       kmip_request_tag_t tag,
                       const uint8_t *v,
                       uint32_t len)
{
   /* kmip_message spec v1.4 section 9.1.1.4 "item value": */
   /* Text Strings are sequences of bytes that encode character values
    * according to the UTF-8 encoding standard. There SHALL NOT be
    * null-termination at the end of such strings. */
   return add_object (msg, tag, kmip_obj_type_text_string, len, v);
}

bool
kmip_request_add_bytes (kmip_request_t *msg,
                        kmip_request_tag_t tag,
                        const uint8_t *v,
                        uint32_t len)
{
   /* kmip_message spec v1.4 section 9.1.1.4 "item value": */
   /* Byte Strings are sequences of bytes containing individual unspecified
    * eight-bit binary values, and are interpreted in the same sequence
    * order. */
   return add_object (msg, tag, kmip_obj_type_byte_string, len, v);
}

bool
kmip_request_add_date_time (kmip_request_t *msg,
                            kmip_request_tag_t tag,
                            kmip_msg_date_time_t v)
{
   /* kmip_message spec v1.4 section 9.1.1.4 "item value": */
   /* Date-Time values are POSIX Time values encoded as Long Integers. POSIX
    * Time, as described in IEEE Standard 1003.1, is the number of seconds since
    * the Epoch (1970 Jan 1, 00:00:00 UTC), not counting leap seconds. */
   kmip_msg_long_t v_be = (kmip_msg_long_t) uint64_to_be ((uint64_t) v);
   return add_object (
      msg, tag, kmip_obj_type_date_time, 8, (const uint8_t *) &v_be);
}

bool
kmip_request_add_interval (kmip_request_t *msg,
                           kmip_request_tag_t tag,
                           kmip_msg_interval_t v)
{
   /* kmip_message spec v1.4 section 9.1.1.4 "item value": */
   /* Intervals are encoded as four-byte long (32 bit) binary unsigned numbers,
    * transmitted big-endian. They have a resolution of one second. */
   kmip_msg_int_t v_be = (kmip_msg_int_t) uint32_to_be ((uint32_t) v);
   return add_object (
      msg, tag, kmip_obj_type_interval, 4, (const uint8_t *) &v_be);
}
