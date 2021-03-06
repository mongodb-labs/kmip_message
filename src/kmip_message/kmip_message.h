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

#ifndef KMIP_MESSAGE_H
#define KMIP_MESSAGE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef _MSC_VER
#ifdef KMIP_MSG_STATIC
#define KMIP_MSG_API
#elif defined(KMIP_MSG_COMPILATION)
#define KMIP_MSG_API __declspec(dllexport)
#else
#define KMIP_MSG_API __declspec(dllimport)
#endif
#define KMIP_MSG_CALL __cdecl
#elif defined(__GNUC__)
#ifdef KMIP_MSG_STATIC
#define KMIP_MSG_API
#elif defined(KMIP_MSG_COMPILATION)
#define KMIP_MSG_API __attribute__ ((visibility ("default")))
#else
#define KMIP_MSG_API
#endif
#define KMIP_MSG_CALL
#endif

#define KMIP_MSG_EXPORT(type) KMIP_MSG_API type KMIP_MSG_CALL

typedef uint32_t kmip_request_tag_t;

typedef int32_t kmip_msg_int_t;
typedef int64_t kmip_msg_long_t;
typedef int32_t kmip_msg_enum_t;
typedef bool kmip_msg_bool_t;
typedef int64_t kmip_msg_date_time_t;
typedef int32_t kmip_msg_interval_t;

typedef enum {
   kmip_obj_type_structure = 0x01,
   kmip_obj_type_integer = 0x02,
   kmip_obj_type_long_integer = 0x03,
   kmip_obj_type_big_integer = 0x04,
   kmip_obj_type_enumeration = 0x05,
   kmip_obj_type_boolean = 0x06,
   kmip_obj_type_text_string = 0x07,
   kmip_obj_type_byte_string = 0x08,
   kmip_obj_type_date_time = 0x09,
   kmip_obj_type_interval = 0x0A,
} kmip_obj_type_t;

typedef enum {
   kmip_tag_activation_date = 0x420001,
   kmip_tag_application_data = 0x420002,
   kmip_tag_application_namespace = 0x420003,
   kmip_tag_application_specific_information = 0x420004,
   kmip_tag_archive_date = 0x420005,
   kmip_tag_asynchronous_correlation_value = 0x420006,
   kmip_tag_asynchronous_indicator = 0x420007,
   kmip_tag_attribute = 0x420008,
   kmip_tag_attribute_index = 0x420009,
   kmip_tag_attribute_name = 0x42000A,
   kmip_tag_attribute_value = 0x42000B,
   kmip_tag_authentication = 0x42000C,
   kmip_tag_batch_count = 0x42000D,
   kmip_tag_batch_error_continuation_option = 0x42000E,
   kmip_tag_batch_item = 0x42000F,
   kmip_tag_batch_order_option = 0x420010,
   kmip_tag_block_cipher_mode = 0x420011,
   kmip_tag_cancellation_result = 0x420012,
   kmip_tag_certificate = 0x420013,
   kmip_tag_certificate_identifier = 0x420014,                /* deprecated */
   kmip_tag_certificate_issuer = 0x420015,                    /* deprecated */
   kmip_tag_certificate_issuer_alternative_name = 0x420016,   /* deprecated */
   kmip_tag_certificate_issuer_distinguished_name = 0x420017, /* deprecated */
   kmip_tag_certificate_request = 0x420018,
   kmip_tag_certificate_request_type = 0x420019,
   kmip_tag_certificate_subject = 0x42001A,                    /* deprecated */
   kmip_tag_certificate_subject_alternative_name = 0x42001B,   /* deprecated */
   kmip_tag_certificate_subject_distinguished_name = 0x42001C, /* deprecated */
   kmip_tag_certificate_type = 0x42001D,
   kmip_tag_certificate_value = 0x42001E,
   kmip_tag_common_template_attribute = 0x42001F,
   kmip_tag_compromise_date = 0x420020,
   kmip_tag_compromise_occurrence_date = 0x420021,
   kmip_tag_contact_information = 0x420022,
   kmip_tag_credential = 0x420023,
   kmip_tag_credential_type = 0x420024,
   kmip_tag_credential_value = 0x420025,
   kmip_tag_criticality_indicator = 0x420026,
   kmip_tag_crt_coefficient = 0x420027,
   kmip_tag_cryptographic_algorithm = 0x420028,
   kmip_tag_cryptographic_domain_parameters = 0x420029,
   kmip_tag_cryptographic_length = 0x42002A,
   kmip_tag_cryptographic_parameters = 0x42002B,
   kmip_tag_cryptographic_usage_mask = 0x42002C,
   kmip_tag_custom_attribute = 0x42002D,
   kmip_tag_d = 0x42002E,
   kmip_tag_deactivation_date = 0x42002F,
   kmip_tag_derivation_data = 0x420030,
   kmip_tag_derivation_method = 0x420031,
   kmip_tag_derivation_parameters = 0x420032,
   kmip_tag_destroy_date = 0x420033,
   kmip_tag_digest = 0x420034,
   kmip_tag_digest_value = 0x420035,
   kmip_tag_encryption_key_information = 0x420036,
   kmip_tag_g = 0x420037,
   kmip_tag_hashing_algorithm = 0x420038,
   kmip_tag_initial_date = 0x420039,
   kmip_tag_initialization_vector = 0x42003A,
   kmip_tag_issuer = 0x42003B, /* deprecated */
   kmip_tag_iteration_count = 0x42003C,
   kmip_tag_iv_counter_nonce = 0x42003D,
   kmip_tag_j = 0x42003E,
   kmip_tag_key = 0x42003F,
   kmip_tag_key_block = 0x420040,
   kmip_tag_key_compression_type = 0x420041,
   kmip_tag_key_format_type = 0x420042,
   kmip_tag_key_material = 0x420043,
   kmip_tag_key_part_identifier = 0x420044,
   kmip_tag_key_value = 0x420045,
   kmip_tag_key_wrapping_data = 0x420046,
   kmip_tag_key_wrapping_specification = 0x420047,
   kmip_tag_last_change_date = 0x420048,
   kmip_tag_lease_time = 0x420049,
   kmip_tag_link = 0x42004A,
   kmip_tag_link_type = 0x42004B,
   kmip_tag_linked_object_identifier = 0x42004C,
   kmip_tag_mac_signature = 0x42004D,
   kmip_tag_mac_signature_key_information = 0x42004E,
   kmip_tag_maximum_items = 0x42004F,
   kmip_tag_maximum_response_size = 0x420050,
   kmip_tag_message_extension = 0x420051,
   kmip_tag_modulus = 0x420052,
   kmip_tag_name = 0x420053,
   kmip_tag_name_type = 0x420054,
   kmip_tag_name_value = 0x420055,
   kmip_tag_object_group = 0x420056,
   kmip_tag_object_type = 0x420057,
   kmip_tag_offset = 0x420058,
   kmip_tag_opaque_data_type = 0x420059,
   kmip_tag_opaque_data_value = 0x42005A,
   kmip_tag_opaque_object = 0x42005B,
   kmip_tag_operation = 0x42005C,
   kmip_tag_operation_policy_name = 0x42005D, /* deprecated */
   kmip_tag_p = 0x42005E,
   kmip_tag_padding_method = 0x42005F,
   kmip_tag_prime_exponent_p = 0x420060,
   kmip_tag_prime_exponent_q = 0x420061,
   kmip_tag_prime_field_size = 0x420062,
   kmip_tag_private_exponent = 0x420063,
   kmip_tag_private_key = 0x420064,
   kmip_tag_private_key_template_attribute = 0x420065,
   kmip_tag_private_key_unique_identifier = 0x420066,
   kmip_tag_process_start_date = 0x420067,
   kmip_tag_protect_stop_date = 0x420068,
   kmip_tag_protocol_version = 0x420069,
   kmip_tag_protocol_version_major = 0x42006A,
   kmip_tag_protocol_version_minor = 0x42006B,
   kmip_tag_public_exponent = 0x42006C,
   kmip_tag_public_key = 0x42006D,
   kmip_tag_public_key_template_attribute = 0x42006E,
   kmip_tag_public_key_unique_identifier = 0x42006F,
   kmip_tag_put_function = 0x420070,
   kmip_tag_q = 0x420071,
   kmip_tag_q_string = 0x420072,
   kmip_tag_qlength = 0x420073,
   kmip_tag_query_function = 0x420074,
   kmip_tag_recommended_curve = 0x420075,
   kmip_tag_replaced_unique_identifier = 0x420076,
   kmip_tag_request_header = 0x420077,
   kmip_tag_request_message = 0x420078,
   kmip_tag_request_payload = 0x420079,
   kmip_tag_response_header = 0x42007A,
   kmip_tag_response_message = 0x42007B,
   kmip_tag_response_payload = 0x42007C,
   kmip_tag_result_message = 0x42007D,
   kmip_tag_result_reason = 0x42007E,
   kmip_tag_result_status = 0x42007F,
   kmip_tag_revocation_message = 0x420080,
   kmip_tag_revocation_reason = 0x420081,
   kmip_tag_revocation_reason_code = 0x420082,
   kmip_tag_key_role_type = 0x420083,
   kmip_tag_salt = 0x420084,
   kmip_tag_secret_data = 0x420085,
   kmip_tag_secret_data_type = 0x420086,
   kmip_tag_serial_number = 0x420087, /* deprecated */
   kmip_tag_server_information = 0x420088,
   kmip_tag_split_key = 0x420089,
   kmip_tag_split_key_method = 0x42008A,
   kmip_tag_split_key_parts = 0x42008B,
   kmip_tag_split_key_threshold = 0x42008C,
   kmip_tag_state = 0x42008D,
   kmip_tag_storage_status_mask = 0x42008E,
   kmip_tag_symmetric_key = 0x42008F,
   kmip_tag_template = 0x420090,
   kmip_tag_template_attribute = 0x420091,
   kmip_tag_time_stamp = 0x420092,
   kmip_tag_unique_batch_item_id = 0x420093,
   kmip_tag_unique_identifier = 0x420094,
   kmip_tag_usage_limits = 0x420095,
   kmip_tag_usage_limits_count = 0x420096,
   kmip_tag_usage_limits_total = 0x420097,
   kmip_tag_usage_limits_unit = 0x420098,
   kmip_tag_username = 0x420099,
   kmip_tag_validity_date = 0x42009A,
   kmip_tag_validity_indicator = 0x42009B,
   kmip_tag_vendor_extension = 0x42009C,
   kmip_tag_vendor_identification = 0x42009D,
   kmip_tag_wrapping_method = 0x42009E,
   kmip_tag_x = 0x42009F,
   kmip_tag_y = 0x4200A0,
   kmip_tag_password = 0x4200A1,
   kmip_tag_device_identifier = 0x4200A2,
   kmip_tag_encoding_option = 0x4200A3,
   kmip_tag_extension_information = 0x4200A4,
   kmip_tag_extension_name = 0x4200A5,
   kmip_tag_extension_tag = 0x4200A6,
   kmip_tag_extension_type = 0x4200A7,
   kmip_tag_fresh = 0x4200A8,
   kmip_tag_machine_identifier = 0x4200A9,
   kmip_tag_media_identifier = 0x4200AA,
   kmip_tag_network_identifier = 0x4200AB,
   kmip_tag_object_group_member = 0x4200AC,
   kmip_tag_certificate_length = 0x4200AD,
   kmip_tag_digital_signature_algorithm = 0x4200AE,
   kmip_tag_certificate_serial_number = 0x4200AF,
   kmip_tag_device_serial_number = 0x4200B0,
   kmip_tag_issuer_alternative_name = 0x4200B1,
   kmip_tag_issuer_distinguished_name = 0x4200B2,
   kmip_tag_subject_alternative_name = 0x4200B3,
   kmip_tag_subject_distinguished_name = 0x4200B4,
   kmip_tag_x_509_certificate_identifier = 0x4200B5,
   kmip_tag_x_509_certificate_issuer = 0x4200B6,
   kmip_tag_x_509_certificate_subject = 0x4200B7,
   kmip_tag_key_value_location = 0x4200B8,
   kmip_tag_key_value_location_value = 0x4200B9,
   kmip_tag_key_value_location_type = 0x4200BA,
   kmip_tag_key_value_present = 0x4200BB,
   kmip_tag_original_creation_date = 0x4200BC,
   kmip_tag_pgp_key = 0x4200BD,
   kmip_tag_pgp_key_version = 0x4200BE,
   kmip_tag_alternative_name = 0x4200BF,
   kmip_tag_alternative_name_value = 0x4200C0,
   kmip_tag_alternative_name_type = 0x4200C1,
   kmip_tag_data = 0x4200C2,
   kmip_tag_signature_data = 0x4200C3,
   kmip_tag_data_length = 0x4200C4,
   kmip_tag_random_iv = 0x4200C5,
   kmip_tag_mac_data = 0x4200C6,
   kmip_tag_attestation_type = 0x4200C7,
   kmip_tag_nonce = 0x4200C8,
   kmip_tag_nonce_id = 0x4200C9,
   kmip_tag_nonce_value = 0x4200CA,
   kmip_tag_attestation_measurement = 0x4200CB,
   kmip_tag_attestation_assertion = 0x4200CC,
   kmip_tag_iv_length = 0x4200CD,
   kmip_tag_tag_length = 0x4200CE,
   kmip_tag_fixed_field_length = 0x4200CF,
   kmip_tag_counter_length = 0x4200D0,
   kmip_tag_initial_counter_value = 0x4200D1,
   kmip_tag_invocation_field_length = 0x4200D2,
   kmip_tag_attestation_capable_indicator = 0x4200D3,
   kmip_tag_offset_items = 0x4200D4,
   kmip_tag_located_items = 0x4200D5,
   kmip_tag_correlation_value = 0x4200D6,
   kmip_tag_init_indicator = 0x4200D7,
   kmip_tag_final_indicator = 0x4200D8,
   kmip_tag_rng_parameters = 0x4200D9,
   kmip_tag_rng_algorithm = 0x4200DA,
   kmip_tag_drbg_algorithm = 0x4200DB,
   kmip_tag_fips186_variation = 0x4200DC,
   kmip_tag_prediction_resistance = 0x4200DD,
   kmip_tag_random_number_generator = 0x4200DE,
   kmip_tag_validation_information = 0x4200DF,
   kmip_tag_validation_authority_type = 0x4200E0,
   kmip_tag_validation_authority_country = 0x4200E1,
   kmip_tag_validation_authority_uri = 0x4200E2,
   kmip_tag_validation_version_major = 0x4200E3,
   kmip_tag_validation_version_minor = 0x4200E4,
   kmip_tag_validation_type = 0x4200E5,
   kmip_tag_validation_level = 0x4200E6,
   kmip_tag_validation_certificate_identifier = 0x4200E7,
   kmip_tag_validation_certificate_uri = 0x4200E8,
   kmip_tag_validation_vendor_uri = 0x4200E9,
   kmip_tag_validation_profile = 0x4200EA,
   kmip_tag_profile_information = 0x4200EB,
   kmip_tag_profile_name = 0x4200EC,
   kmip_tag_server_uri = 0x4200ED,
   kmip_tag_server_port = 0x4200EE,
   kmip_tag_streaming_capability = 0x4200EF,
   kmip_tag_asynchronous_capability = 0x4200F0,
   kmip_tag_attestation_capability = 0x4200F1,
   kmip_tag_unwrap_mode = 0x4200F2,
   kmip_tag_destroy_action = 0x4200F3,
   kmip_tag_shredding_algorithm = 0x4200F4,
   kmip_tag_rng_mode = 0x4200F5,
   kmip_tag_client_registration_method = 0x4200F6,
   kmip_tag_capability_information = 0x4200F7,
   kmip_tag_key_wrap_type = 0x4200F8,
   kmip_tag_batch_undo_capability = 0x4200F9,
   kmip_tag_batch_continue_capability = 0x4200FA,
   kmip_tag_pkcs12_friendly_name = 0x4200FB,
   kmip_tag_description = 0x4200FC,
   kmip_tag_comment = 0x4200FD,
   kmip_tag_authenticated_encryption_additional_data = 0x4200FE,
   kmip_tag_authenticated_encryption_tag = 0x4200FF,
   kmip_tag_salt_length = 0x420100,
   kmip_tag_mask_generator = 0x420101,
   kmip_tag_mask_generator_hashing_algorithm = 0x420102,
   kmip_tag_p_source = 0x420103,
   kmip_tag_trailer_field = 0x420104,
   kmip_tag_client_correlation_value = 0x420105,
   kmip_tag_server_correlation_value = 0x420106,
   kmip_tag_digested_data = 0x420107,
   kmip_tag_certificate_subject_cn = 0x420108,
   kmip_tag_certificate_subject_o = 0x420109,
   kmip_tag_certificate_subject_ou = 0x42010A,
   kmip_tag_certificate_subject_email = 0x42010B,
   kmip_tag_certificate_subject_c = 0x42010C,
   kmip_tag_certificate_subject_st = 0x42010D,
   kmip_tag_certificate_subject_l = 0x42010E,
   kmip_tag_certificate_subject_uid = 0x42010F,
   kmip_tag_certificate_subject_serial_number = 0x420110,
   kmip_tag_certificate_subject_title = 0x420111,
   kmip_tag_certificate_subject_dc = 0x420112,
   kmip_tag_certificate_subject_dn_qualifier = 0x420113,
   kmip_tag_certificate_issuer_cn = 0x420114,
   kmip_tag_certificate_issuer_o = 0x420115,
   kmip_tag_certificate_issuer_ou = 0x420116,
   kmip_tag_certificate_issuer_email = 0x420117,
   kmip_tag_certificate_issuer_c = 0x420118,
   kmip_tag_certificate_issuer_st = 0x420119,
   kmip_tag_certificate_issuer_l = 0x42011A,
   kmip_tag_certificate_issuer_uid = 0x42011B,
   kmip_tag_certificate_issuer_serial_number = 0x42011C,
   kmip_tag_certificate_issuer_title = 0x42011D,
   kmip_tag_certificate_issuer_dc = 0x42011E,
   kmip_tag_certificate_issuer_dn_qualifier = 0x42011F,
   kmip_tag_sensitive = 0x420120,
   kmip_tag_always_sensitive = 0x420121,
   kmip_tag_extractable = 0x420122,
   kmip_tag_never_extractable = 0x420123,
   kmip_tag_replace_existing = 0x420124,
} kmip_tag_t;

typedef enum {
   kmip_operation_create = 0x01,
   kmip_operation_create_key_pair = 0x02,
   kmip_operation_register = 0x03,
   kmip_operation_re_key = 0x04,
   kmip_operation_derive_key = 0x05,
   kmip_operation_certify = 0x06,
   kmip_operation_re_certify = 0x07,
   kmip_operation_locate = 0x08,
   kmip_operation_check = 0x09,
   kmip_operation_get = 0x0A,
   kmip_operation_get_attributes = 0x0B,
   kmip_operation_get_attribute_list = 0x0C,
   kmip_operation_add_attribute = 0x0D,
   kmip_operation_modify_attribute = 0x0E,
   kmip_operation_delete_attribute = 0x0F,
   kmip_operation_obtain_lease = 0x10,
   kmip_operation_get_usage_allocation = 0x11,
   kmip_operation_activate = 0x12,
   kmip_operation_revoke = 0x13,
   kmip_operation_destroy = 0x14,
   kmip_operation_archive = 0x15,
   kmip_operation_recover = 0x16,
   kmip_operation_validate = 0x17,
   kmip_operation_query = 0x18,
   kmip_operation_cancel = 0x19,
   kmip_operation_poll = 0x1A,
   kmip_operation_notify = 0x1B,
   kmip_operation_put = 0x1C,
   kmip_operation_re_key_key_pair = 0x1D,
   kmip_operation_discover_versions = 0x1E,
   kmip_operation_encrypt = 0x1F,
   kmip_operation_decrypt = 0x20,
   kmip_operation_sign = 0x21,
   kmip_operation_signature_verify = 0x22,
   kmip_operation_mac = 0x23,
   kmip_operation_mac_verify = 0x24,
   kmip_operation_rng_retrieve = 0x25,
   kmip_operation_rng_seed = 0x26,
   kmip_operation_hash = 0x27,
   kmip_operation_create_split_key = 0x28,
   kmip_operation_join_split_key = 0x29,
   kmip_operation_import = 0x2A,
   kmip_operation_export = 0x2B,
} kmip_operation_t;

typedef enum {
   kmip_credential_type_username_and_password = 0x1,
   kmip_credential_type_device = 0x2,
   kmip_credential_type_attestation = 0x3
} kmip_credential_type_t;

char *
kmip_get_type_name (kmip_obj_type_t type);

char *
kmip_get_tag_name (kmip_tag_t tag);

uint32_t
next_power_of_2 (uint32_t i);

#include "kmip_parser.h"
#include "kmip_request.h"

#endif /* KMIP_MESSAGE_H */
