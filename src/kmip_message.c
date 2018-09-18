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

#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

char *
kmip_get_type_name (kmip_obj_type_t type)
{
   char *name = NULL;
   switch (type) {
   case kmip_obj_type_structure:
      name = "structure";
      break;
   case kmip_obj_type_integer:
      name = "integer";
      break;
   case kmip_obj_type_long_integer:
      name = "long_integer";
      break;
   case kmip_obj_type_big_integer:
      name = "big_integer";
      break;
   case kmip_obj_type_enumeration:
      name = "enumeration";
      break;
   case kmip_obj_type_boolean:
      name = "boolean";
      break;
   case kmip_obj_type_text_string:
      name = "text_string";
      break;
   case kmip_obj_type_byte_string:
      name = "byte_string";
      break;
   case kmip_obj_type_date_time:
      name = "date_time";
      break;
   case kmip_obj_type_interval:
      name = "interval";
      break;
   default:
      break;
   }

   if (!name) {
      name = malloc (512);
      snprintf (name, 512, "Unknown type: %X", type);
      return name;
   }

   return strdup (name);
}

char *
kmip_get_tag_name (kmip_tag_t tag)
{
   char *name = NULL;
   switch (tag) {
   case kmip_tag_activation_date:
      name = "activation_date";
      break;
   case kmip_tag_application_data:
      name = "application_data";
      break;
   case kmip_tag_application_namespace:
      name = "application_namespace";
      break;
   case kmip_tag_application_specific_information:
      name = "application_specific_information";
      break;
   case kmip_tag_archive_date:
      name = "archive_date";
      break;
   case kmip_tag_asynchronous_correlation_value:
      name = "asynchronous_correlation_value";
      break;
   case kmip_tag_asynchronous_indicator:
      name = "asynchronous_indicator";
      break;
   case kmip_tag_attribute:
      name = "attribute";
      break;
   case kmip_tag_attribute_index:
      name = "attribute_index";
      break;
   case kmip_tag_attribute_name:
      name = "attribute_name";
      break;
   case kmip_tag_attribute_value:
      name = "attribute_value";
      break;
   case kmip_tag_authentication:
      name = "authentication";
      break;
   case kmip_tag_batch_count:
      name = "batch_count";
      break;
   case kmip_tag_batch_error_continuation_option:
      name = "batch_error_continuation_option";
      break;
   case kmip_tag_batch_item:
      name = "batch_item";
      break;
   case kmip_tag_batch_order_option:
      name = "batch_order_option";
      break;
   case kmip_tag_block_cipher_mode:
      name = "block_cipher_mode";
      break;
   case kmip_tag_cancellation_result:
      name = "cancellation_result";
      break;
   case kmip_tag_certificate:
      name = "certificate";
      break;
   case kmip_tag_certificate_identifier:
      name = "certificate_identifier";
      break;
   case kmip_tag_certificate_issuer:
      name = "certificate_issuer";
      break;
   case kmip_tag_certificate_issuer_alternative_name:
      name = "certificate_issuer_alternative_name";
      break;
   case kmip_tag_certificate_issuer_distinguished_name:
      name = "certificate_issuer_distinguished_name";
      break;
   case kmip_tag_certificate_request:
      name = "certificate_request";
      break;
   case kmip_tag_certificate_request_type:
      name = "certificate_request_type";
      break;
   case kmip_tag_certificate_subject:
      name = "certificate_subject";
      break;
   case kmip_tag_certificate_subject_alternative_name:
      name = "certificate_subject_alternative_name";
      break;
   case kmip_tag_certificate_subject_distinguished_name:
      name = "certificate_subject_distinguished_name";
      break;
   case kmip_tag_certificate_type:
      name = "certificate_type";
      break;
   case kmip_tag_certificate_value:
      name = "certificate_value";
      break;
   case kmip_tag_common_template_attribute:
      name = "common_template_attribute";
      break;
   case kmip_tag_compromise_date:
      name = "compromise_date";
      break;
   case kmip_tag_compromise_occurrence_date:
      name = "compromise_occurrence_date";
      break;
   case kmip_tag_contact_information:
      name = "contact_information";
      break;
   case kmip_tag_credential:
      name = "credential";
      break;
   case kmip_tag_credential_type:
      name = "credential_type";
      break;
   case kmip_tag_credential_value:
      name = "credential_value";
      break;
   case kmip_tag_criticality_indicator:
      name = "criticality_indicator";
      break;
   case kmip_tag_crt_coefficient:
      name = "crt_coefficient";
      break;
   case kmip_tag_cryptographic_algorithm:
      name = "cryptographic_algorithm";
      break;
   case kmip_tag_cryptographic_domain_parameters:
      name = "cryptographic_domain_parameters";
      break;
   case kmip_tag_cryptographic_length:
      name = "cryptographic_length";
      break;
   case kmip_tag_cryptographic_parameters:
      name = "cryptographic_parameters";
      break;
   case kmip_tag_cryptographic_usage_mask:
      name = "cryptographic_usage_mask";
      break;
   case kmip_tag_custom_attribute:
      name = "custom_attribute";
      break;
   case kmip_tag_d:
      name = "d";
      break;
   case kmip_tag_deactivation_date:
      name = "deactivation_date";
      break;
   case kmip_tag_derivation_data:
      name = "derivation_data";
      break;
   case kmip_tag_derivation_method:
      name = "derivation_method";
      break;
   case kmip_tag_derivation_parameters:
      name = "derivation_parameters";
      break;
   case kmip_tag_destroy_date:
      name = "destroy_date";
      break;
   case kmip_tag_digest:
      name = "digest";
      break;
   case kmip_tag_digest_value:
      name = "digest_value";
      break;
   case kmip_tag_encryption_key_information:
      name = "encryption_key_information";
      break;
   case kmip_tag_g:
      name = "g";
      break;
   case kmip_tag_hashing_algorithm:
      name = "hashing_algorithm";
      break;
   case kmip_tag_initial_date:
      name = "initial_date";
      break;
   case kmip_tag_initialization_vector:
      name = "initialization_vector";
      break;
   case kmip_tag_issuer:
      name = "issuer";
      break;
   case kmip_tag_iteration_count:
      name = "iteration_count";
      break;
   case kmip_tag_iv_counter_nonce:
      name = "iv_counter_nonce";
      break;
   case kmip_tag_j:
      name = "j";
      break;
   case kmip_tag_key:
      name = "key";
      break;
   case kmip_tag_key_block:
      name = "key_block";
      break;
   case kmip_tag_key_compression_type:
      name = "key_compression_type";
      break;
   case kmip_tag_key_format_type:
      name = "key_format_type";
      break;
   case kmip_tag_key_material:
      name = "key_material";
      break;
   case kmip_tag_key_part_identifier:
      name = "key_part_identifier";
      break;
   case kmip_tag_key_value:
      name = "key_value";
      break;
   case kmip_tag_key_wrapping_data:
      name = "key_wrapping_data";
      break;
   case kmip_tag_key_wrapping_specification:
      name = "key_wrapping_specification";
      break;
   case kmip_tag_last_change_date:
      name = "last_change_date";
      break;
   case kmip_tag_lease_time:
      name = "lease_time";
      break;
   case kmip_tag_link:
      name = "link";
      break;
   case kmip_tag_link_type:
      name = "link_type";
      break;
   case kmip_tag_linked_object_identifier:
      name = "linked_object_identifier";
      break;
   case kmip_tag_mac_signature:
      name = "mac_signature";
      break;
   case kmip_tag_mac_signature_key_information:
      name = "mac_signature_key_information";
      break;
   case kmip_tag_maximum_items:
      name = "maximum_items";
      break;
   case kmip_tag_maximum_response_size:
      name = "maximum_response_size";
      break;
   case kmip_tag_message_extension:
      name = "message_extension";
      break;
   case kmip_tag_modulus:
      name = "modulus";
      break;
   case kmip_tag_name:
      name = "name";
      break;
   case kmip_tag_name_type:
      name = "name_type";
      break;
   case kmip_tag_name_value:
      name = "name_value";
      break;
   case kmip_tag_object_group:
      name = "object_group";
      break;
   case kmip_tag_object_type:
      name = "object_type";
      break;
   case kmip_tag_offset:
      name = "offset";
      break;
   case kmip_tag_opaque_data_type:
      name = "opaque_data_type";
      break;
   case kmip_tag_opaque_data_value:
      name = "opaque_data_value";
      break;
   case kmip_tag_opaque_object:
      name = "opaque_object";
      break;
   case kmip_tag_operation:
      name = "operation";
      break;
   case kmip_tag_operation_policy_name:
      name = "operation_policy_name";
      break;
   case kmip_tag_p:
      name = "p";
      break;
   case kmip_tag_padding_method:
      name = "padding_method";
      break;
   case kmip_tag_prime_exponent_p:
      name = "prime_exponent_p";
      break;
   case kmip_tag_prime_exponent_q:
      name = "prime_exponent_q";
      break;
   case kmip_tag_prime_field_size:
      name = "prime_field_size";
      break;
   case kmip_tag_private_exponent:
      name = "private_exponent";
      break;
   case kmip_tag_private_key:
      name = "private_key";
      break;
   case kmip_tag_private_key_template_attribute:
      name = "private_key_template_attribute";
      break;
   case kmip_tag_private_key_unique_identifier:
      name = "private_key_unique_identifier";
      break;
   case kmip_tag_process_start_date:
      name = "process_start_date";
      break;
   case kmip_tag_protect_stop_date:
      name = "protect_stop_date";
      break;
   case kmip_tag_protocol_version:
      name = "protocol_version";
      break;
   case kmip_tag_protocol_version_major:
      name = "protocol_version_major";
      break;
   case kmip_tag_protocol_version_minor:
      name = "protocol_version_minor";
      break;
   case kmip_tag_public_exponent:
      name = "public_exponent";
      break;
   case kmip_tag_public_key:
      name = "public_key";
      break;
   case kmip_tag_public_key_template_attribute:
      name = "public_key_template_attribute";
      break;
   case kmip_tag_public_key_unique_identifier:
      name = "public_key_unique_identifier";
      break;
   case kmip_tag_put_function:
      name = "put_function";
      break;
   case kmip_tag_q:
      name = "q";
      break;
   case kmip_tag_q_string:
      name = "q_string";
      break;
   case kmip_tag_qlength:
      name = "qlength";
      break;
   case kmip_tag_query_function:
      name = "query_function";
      break;
   case kmip_tag_recommended_curve:
      name = "recommended_curve";
      break;
   case kmip_tag_replaced_unique_identifier:
      name = "replaced_unique_identifier";
      break;
   case kmip_tag_request_header:
      name = "request_header";
      break;
   case kmip_tag_request_message:
      name = "request_message";
      break;
   case kmip_tag_request_payload:
      name = "request_payload";
      break;
   case kmip_tag_response_header:
      name = "response_header";
      break;
   case kmip_tag_response_message:
      name = "response_message";
      break;
   case kmip_tag_response_payload:
      name = "response_payload";
      break;
   case kmip_tag_result_message:
      name = "result_message";
      break;
   case kmip_tag_result_reason:
      name = "result_reason";
      break;
   case kmip_tag_result_status:
      name = "result_status";
      break;
   case kmip_tag_revocation_message:
      name = "revocation_message";
      break;
   case kmip_tag_revocation_reason:
      name = "revocation_reason";
      break;
   case kmip_tag_revocation_reason_code:
      name = "revocation_reason_code";
      break;
   case kmip_tag_key_role_type:
      name = "key_role_type";
      break;
   case kmip_tag_salt:
      name = "salt";
      break;
   case kmip_tag_secret_data:
      name = "secret_data";
      break;
   case kmip_tag_secret_data_type:
      name = "secret_data_type";
      break;
   case kmip_tag_serial_number:
      name = "serial_number";
      break;
   case kmip_tag_server_information:
      name = "server_information";
      break;
   case kmip_tag_split_key:
      name = "split_key";
      break;
   case kmip_tag_split_key_method:
      name = "split_key_method";
      break;
   case kmip_tag_split_key_parts:
      name = "split_key_parts";
      break;
   case kmip_tag_split_key_threshold:
      name = "split_key_threshold";
      break;
   case kmip_tag_state:
      name = "state";
      break;
   case kmip_tag_storage_status_mask:
      name = "storage_status_mask";
      break;
   case kmip_tag_symmetric_key:
      name = "symmetric_key";
      break;
   case kmip_tag_template:
      name = "template";
      break;
   case kmip_tag_template_attribute:
      name = "template_attribute";
      break;
   case kmip_tag_time_stamp:
      name = "time_stamp";
      break;
   case kmip_tag_unique_batch_item_id:
      name = "unique_batch_item_id";
      break;
   case kmip_tag_unique_identifier:
      name = "unique_identifier";
      break;
   case kmip_tag_usage_limits:
      name = "usage_limits";
      break;
   case kmip_tag_usage_limits_count:
      name = "usage_limits_count";
      break;
   case kmip_tag_usage_limits_total:
      name = "usage_limits_total";
      break;
   case kmip_tag_usage_limits_unit:
      name = "usage_limits_unit";
      break;
   case kmip_tag_username:
      name = "username";
      break;
   case kmip_tag_validity_date:
      name = "validity_date";
      break;
   case kmip_tag_validity_indicator:
      name = "validity_indicator";
      break;
   case kmip_tag_vendor_extension:
      name = "vendor_extension";
      break;
   case kmip_tag_vendor_identification:
      name = "vendor_identification";
      break;
   case kmip_tag_wrapping_method:
      name = "wrapping_method";
      break;
   case kmip_tag_x:
      name = "x";
      break;
   case kmip_tag_y:
      name = "y";
      break;
   case kmip_tag_password:
      name = "password";
      break;
   case kmip_tag_device_identifier:
      name = "device_identifier";
      break;
   case kmip_tag_encoding_option:
      name = "encoding_option";
      break;
   case kmip_tag_extension_information:
      name = "extension_information";
      break;
   case kmip_tag_extension_name:
      name = "extension_name";
      break;
   case kmip_tag_extension_tag:
      name = "extension_tag";
      break;
   case kmip_tag_extension_type:
      name = "extension_type";
      break;
   case kmip_tag_fresh:
      name = "fresh";
      break;
   case kmip_tag_machine_identifier:
      name = "machine_identifier";
      break;
   case kmip_tag_media_identifier:
      name = "media_identifier";
      break;
   case kmip_tag_network_identifier:
      name = "network_identifier";
      break;
   case kmip_tag_object_group_member:
      name = "object_group_member";
      break;
   case kmip_tag_certificate_length:
      name = "certificate_length";
      break;
   case kmip_tag_digital_signature_algorithm:
      name = "digital_signature_algorithm";
      break;
   case kmip_tag_certificate_serial_number:
      name = "certificate_serial_number";
      break;
   case kmip_tag_device_serial_number:
      name = "device_serial_number";
      break;
   case kmip_tag_issuer_alternative_name:
      name = "issuer_alternative_name";
      break;
   case kmip_tag_issuer_distinguished_name:
      name = "issuer_distinguished_name";
      break;
   case kmip_tag_subject_alternative_name:
      name = "subject_alternative_name";
      break;
   case kmip_tag_subject_distinguished_name:
      name = "subject_distinguished_name";
      break;
   case kmip_tag_x_509_certificate_identifier:
      name = "x_509_certificate_identifier";
      break;
   case kmip_tag_x_509_certificate_issuer:
      name = "x_509_certificate_issuer";
      break;
   case kmip_tag_x_509_certificate_subject:
      name = "x_509_certificate_subject";
      break;
   case kmip_tag_key_value_location:
      name = "key_value_location";
      break;
   case kmip_tag_key_value_location_value:
      name = "key_value_location_value";
      break;
   case kmip_tag_key_value_location_type:
      name = "key_value_location_type";
      break;
   case kmip_tag_key_value_present:
      name = "key_value_present";
      break;
   case kmip_tag_original_creation_date:
      name = "original_creation_date";
      break;
   case kmip_tag_pgp_key:
      name = "pgp_key";
      break;
   case kmip_tag_pgp_key_version:
      name = "pgp_key_version";
      break;
   case kmip_tag_alternative_name:
      name = "alternative_name";
      break;
   case kmip_tag_alternative_name_value:
      name = "alternative_name_value";
      break;
   case kmip_tag_alternative_name_type:
      name = "alternative_name_type";
      break;
   case kmip_tag_data:
      name = "data";
      break;
   case kmip_tag_signature_data:
      name = "signature_data";
      break;
   case kmip_tag_data_length:
      name = "data_length";
      break;
   case kmip_tag_random_iv:
      name = "random_iv";
      break;
   case kmip_tag_mac_data:
      name = "mac_data";
      break;
   case kmip_tag_attestation_type:
      name = "attestation_type";
      break;
   case kmip_tag_nonce:
      name = "nonce";
      break;
   case kmip_tag_nonce_id:
      name = "nonce_id";
      break;
   case kmip_tag_nonce_value:
      name = "nonce_value";
      break;
   case kmip_tag_attestation_measurement:
      name = "attestation_measurement";
      break;
   case kmip_tag_attestation_assertion:
      name = "attestation_assertion";
      break;
   case kmip_tag_iv_length:
      name = "iv_length";
      break;
   case kmip_tag_tag_length:
      name = "tag_length";
      break;
   case kmip_tag_fixed_field_length:
      name = "fixed_field_length";
      break;
   case kmip_tag_counter_length:
      name = "counter_length";
      break;
   case kmip_tag_initial_counter_value:
      name = "initial_counter_value";
      break;
   case kmip_tag_invocation_field_length:
      name = "invocation_field_length";
      break;
   case kmip_tag_attestation_capable_indicator:
      name = "attestation_capable_indicator";
      break;
   case kmip_tag_offset_items:
      name = "offset_items";
      break;
   case kmip_tag_located_items:
      name = "located_items";
      break;
   case kmip_tag_correlation_value:
      name = "correlation_value";
      break;
   case kmip_tag_init_indicator:
      name = "init_indicator";
      break;
   case kmip_tag_final_indicator:
      name = "final_indicator";
      break;
   case kmip_tag_rng_parameters:
      name = "rng_parameters";
      break;
   case kmip_tag_rng_algorithm:
      name = "rng_algorithm";
      break;
   case kmip_tag_drbg_algorithm:
      name = "drbg_algorithm";
      break;
   case kmip_tag_fips186_variation:
      name = "fips186_variation";
      break;
   case kmip_tag_prediction_resistance:
      name = "prediction_resistance";
      break;
   case kmip_tag_random_number_generator:
      name = "random_number_generator";
      break;
   case kmip_tag_validation_information:
      name = "validation_information";
      break;
   case kmip_tag_validation_authority_type:
      name = "validation_authority_type";
      break;
   case kmip_tag_validation_authority_country:
      name = "validation_authority_country";
      break;
   case kmip_tag_validation_authority_uri:
      name = "validation_authority_uri";
      break;
   case kmip_tag_validation_version_major:
      name = "validation_version_major";
      break;
   case kmip_tag_validation_version_minor:
      name = "validation_version_minor";
      break;
   case kmip_tag_validation_type:
      name = "validation_type";
      break;
   case kmip_tag_validation_level:
      name = "validation_level";
      break;
   case kmip_tag_validation_certificate_identifier:
      name = "validation_certificate_identifier";
      break;
   case kmip_tag_validation_certificate_uri:
      name = "validation_certificate_uri";
      break;
   case kmip_tag_validation_vendor_uri:
      name = "validation_vendor_uri";
      break;
   case kmip_tag_validation_profile:
      name = "validation_profile";
      break;
   case kmip_tag_profile_information:
      name = "profile_information";
      break;
   case kmip_tag_profile_name:
      name = "profile_name";
      break;
   case kmip_tag_server_uri:
      name = "server_uri";
      break;
   case kmip_tag_server_port:
      name = "server_port";
      break;
   case kmip_tag_streaming_capability:
      name = "streaming_capability";
      break;
   case kmip_tag_asynchronous_capability:
      name = "asynchronous_capability";
      break;
   case kmip_tag_attestation_capability:
      name = "attestation_capability";
      break;
   case kmip_tag_unwrap_mode:
      name = "unwrap_mode";
      break;
   case kmip_tag_destroy_action:
      name = "destroy_action";
      break;
   case kmip_tag_shredding_algorithm:
      name = "shredding_algorithm";
      break;
   case kmip_tag_rng_mode:
      name = "rng_mode";
      break;
   case kmip_tag_client_registration_method:
      name = "client_registration_method";
      break;
   case kmip_tag_capability_information:
      name = "capability_information";
      break;
   case kmip_tag_key_wrap_type:
      name = "key_wrap_type";
      break;
   case kmip_tag_batch_undo_capability:
      name = "batch_undo_capability";
      break;
   case kmip_tag_batch_continue_capability:
      name = "batch_continue_capability";
      break;
   case kmip_tag_pkcs12_friendly_name:
      name = "pkcs12_friendly_name";
      break;
   case kmip_tag_description:
      name = "description";
      break;
   case kmip_tag_comment:
      name = "comment";
      break;
   case kmip_tag_authenticated_encryption_additional_data:
      name = "authenticated_encryption_additional_data";
      break;
   case kmip_tag_authenticated_encryption_tag:
      name = "authenticated_encryption_tag";
      break;
   case kmip_tag_salt_length:
      name = "salt_length";
      break;
   case kmip_tag_mask_generator:
      name = "mask_generator";
      break;
   case kmip_tag_mask_generator_hashing_algorithm:
      name = "mask_generator_hashing_algorithm";
      break;
   case kmip_tag_p_source:
      name = "p_source";
      break;
   case kmip_tag_trailer_field:
      name = "trailer_field";
      break;
   case kmip_tag_client_correlation_value:
      name = "client_correlation_value";
      break;
   case kmip_tag_server_correlation_value:
      name = "server_correlation_value";
      break;
   case kmip_tag_digested_data:
      name = "digested_data";
      break;
   case kmip_tag_certificate_subject_cn:
      name = "certificate_subject_cn";
      break;
   case kmip_tag_certificate_subject_o:
      name = "certificate_subject_o";
      break;
   case kmip_tag_certificate_subject_ou:
      name = "certificate_subject_ou";
      break;
   case kmip_tag_certificate_subject_email:
      name = "certificate_subject_email";
      break;
   case kmip_tag_certificate_subject_c:
      name = "certificate_subject_c";
      break;
   case kmip_tag_certificate_subject_st:
      name = "certificate_subject_st";
      break;
   case kmip_tag_certificate_subject_l:
      name = "certificate_subject_l";
      break;
   case kmip_tag_certificate_subject_uid:
      name = "certificate_subject_uid";
      break;
   case kmip_tag_certificate_subject_serial_number:
      name = "certificate_subject_serial_number";
      break;
   case kmip_tag_certificate_subject_title:
      name = "certificate_subject_title";
      break;
   case kmip_tag_certificate_subject_dc:
      name = "certificate_subject_dc";
      break;
   case kmip_tag_certificate_subject_dn_qualifier:
      name = "certificate_subject_dn_qualifier";
      break;
   case kmip_tag_certificate_issuer_cn:
      name = "certificate_issuer_cn";
      break;
   case kmip_tag_certificate_issuer_o:
      name = "certificate_issuer_o";
      break;
   case kmip_tag_certificate_issuer_ou:
      name = "certificate_issuer_ou";
      break;
   case kmip_tag_certificate_issuer_email:
      name = "certificate_issuer_email";
      break;
   case kmip_tag_certificate_issuer_c:
      name = "certificate_issuer_c";
      break;
   case kmip_tag_certificate_issuer_st:
      name = "certificate_issuer_st";
      break;
   case kmip_tag_certificate_issuer_l:
      name = "certificate_issuer_l";
      break;
   case kmip_tag_certificate_issuer_uid:
      name = "certificate_issuer_uid";
      break;
   case kmip_tag_certificate_issuer_serial_number:
      name = "certificate_issuer_serial_number";
      break;
   case kmip_tag_certificate_issuer_title:
      name = "certificate_issuer_title";
      break;
   case kmip_tag_certificate_issuer_dc:
      name = "certificate_issuer_dc";
      break;
   case kmip_tag_certificate_issuer_dn_qualifier:
      name = "certificate_issuer_dn_qualifier";
      break;
   case kmip_tag_sensitive:
      name = "sensitive";
      break;
   case kmip_tag_always_sensitive:
      name = "always_sensitive";
      break;
   case kmip_tag_extractable:
      name = "extractable";
      break;
   case kmip_tag_never_extractable:
      name = "never_extractable";
      break;
   case kmip_tag_replace_existing:
      name = "replace_existing";
      break;
   default:
      break;
   }

   if (!name) {
      name = malloc (512);
      snprintf (name, 512, "Unknown tag: %X", tag);
      return name;
   }

   return strdup (name);
}
