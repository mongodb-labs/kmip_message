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

#ifndef KMIP_REQUEST_H
#define KMIP_REQUEST_H

kmip_request_t *
kmip_request_new (void);
void
kmip_request_destroy (kmip_request_t *msg);
uint8_t *
kmip_request_get_data (kmip_request_t *msg, uint32_t *len);
const char *
kmip_request_get_error (kmip_request_t *msg);
bool
kmip_request_begin_struct (kmip_request_t *msg, kmip_request_tag_t tag);
bool
kmip_request_end_struct (kmip_request_t *msg);
bool
kmip_request_add_int (kmip_request_t *msg,
                      kmip_request_tag_t tag,
                      kmip_msg_int_t v);
bool
kmip_request_add_long (kmip_request_t *msg,
                       kmip_request_tag_t tag,
                       kmip_msg_long_t v);
bool
kmip_request_add_big_int (kmip_request_t *msg,
                          kmip_request_tag_t tag,
                          const uint8_t *v,
                          uint32_t len);
bool
kmip_request_add_enum (kmip_request_t *msg,
                       kmip_request_tag_t tag,
                       kmip_msg_enum_t v);
bool
kmip_request_add_bool (kmip_request_t *msg,
                       kmip_request_tag_t tag,
                       kmip_msg_bool_t v);
bool
kmip_request_add_text (kmip_request_t *msg,
                       kmip_request_tag_t tag,
                       const uint8_t *v,
                       uint32_t len);
bool
kmip_request_add_bytes (kmip_request_t *msg,
                        kmip_request_tag_t tag,
                        const uint8_t *v,
                        uint32_t len);
bool
kmip_request_add_date_time (kmip_request_t *msg,
                            kmip_request_tag_t tag,
                            kmip_msg_date_time_t v);
bool
kmip_request_add_interval (kmip_request_t *msg,
                           kmip_request_tag_t tag,
                           kmip_msg_interval_t v);

#endif /* KMIP_REQUEST_H */