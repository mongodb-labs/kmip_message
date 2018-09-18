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

#ifndef KMIP_PARSER_H
#define KMIP_PARSER_H

#include <stdlib.h>

typedef struct _kmip_parser_t kmip_parser_t;

KMIP_MSG_EXPORT (kmip_parser_t *)
kmip_parser_new (void);
KMIP_MSG_EXPORT (kmip_parser_t *)
kmip_parser_new_from_data (const uint8_t *data, uint32_t len);
KMIP_MSG_EXPORT (void)
kmip_parser_destroy (kmip_parser_t *parser);
KMIP_MSG_EXPORT (const char *)
kmip_parser_get_error (kmip_parser_t *parser);
KMIP_MSG_EXPORT (bool)
kmip_parser_feed (kmip_parser_t *parser, const uint8_t *data, size_t len);
KMIP_MSG_EXPORT (bool)
kmip_parser_next (kmip_parser_t *parser);
KMIP_MSG_EXPORT (kmip_tag_t)
kmip_parser_tag (kmip_parser_t *parser);
KMIP_MSG_EXPORT (kmip_obj_type_t)
kmip_parser_type (kmip_parser_t *parser);
KMIP_MSG_EXPORT (bool)
kmip_parser_descend (kmip_parser_t *parser);
KMIP_MSG_EXPORT (bool)
kmip_parser_ascend (kmip_parser_t *parser);
KMIP_MSG_EXPORT (bool)
kmip_parser_read_int (kmip_parser_t *parser, kmip_msg_int_t *v);
KMIP_MSG_EXPORT (bool)
kmip_parser_read_long (kmip_parser_t *parser, kmip_msg_long_t *v);
KMIP_MSG_EXPORT (bool)
kmip_parser_read_big_int (kmip_parser_t *parser,
                          const uint8_t **v,
                          uint32_t *len);
KMIP_MSG_EXPORT (bool)
kmip_parser_read_enum (kmip_parser_t *parser, kmip_msg_enum_t *v);
KMIP_MSG_EXPORT (bool)
kmip_parser_read_bool (kmip_parser_t *parser, kmip_msg_bool_t *v);
KMIP_MSG_EXPORT (bool)
kmip_parser_read_text (kmip_parser_t *parser, const uint8_t **v, uint32_t *len);
KMIP_MSG_EXPORT (bool)
kmip_parser_read_bytes (kmip_parser_t *parser,
                        const uint8_t **v,
                        uint32_t *len);
KMIP_MSG_EXPORT (bool)
kmip_parser_read_date_time (kmip_parser_t *parser, kmip_msg_date_time_t *v);
KMIP_MSG_EXPORT (bool)
kmip_parser_read_interval (kmip_parser_t *parser, kmip_msg_interval_t *v);
KMIP_MSG_EXPORT (char *)
kmip_parser_dump (kmip_parser_t *parser);

#endif /* KMIP_PARSER_H */
