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

#ifndef KMIP_PRIVATE_H
#define KMIP_PRIVATE_H

#ifdef KMIP_MSG_BIG_ENDIAN
inline uint32_t
uint32_to_be (uint32_t v)
{
   return v;
}

inline uint64_t
uint64_to_be (uint64_t v)
{
   return v;
}
#else
inline uint32_t
uint32_to_be (uint32_t v)
{
   return ((v & 0x000000FFU) << 24) | ((v & 0x0000FF00U) << 8) |
          ((v & 0x00FF0000U) >> 8) | ((v & 0xFF000000U) >> 24);
}

inline uint64_t
uint64_to_be (uint64_t v)
{
   return ((v & 0x00000000000000FFULL) << 56) |
          ((v & 0x000000000000FF00ULL) << 40) |
          ((v & 0x0000000000FF0000ULL) << 24) |
          ((v & 0x00000000FF000000ULL) << 8) |
          ((v & 0x000000FF00000000ULL) >> 8) |
          ((v & 0x0000FF0000000000ULL) >> 24) |
          ((v & 0x00FF000000000000ULL) >> 40) |
          ((v & 0xFF00000000000000ULL) >> 56);
}
#endif /* KMIP_MSG_BIG_ENDIAN */
#endif /* KMIP_PRIVATE_H */
