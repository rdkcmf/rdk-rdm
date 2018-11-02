/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
/**
 * Obfuscated error return values.
 * Inital status returns to splunk will consist of the string:
 * "performance status bla bla: " followed by the hex ascii of one of
 * the following values.
 */
#define retcode_param_error     0x5165C860              /* -1 */
#define retcode_success         0x15245EAD              /* 0 */
#define retcode_datafile_err    0x3560800C              /* 1 */
#define retcode_sigfile_err     0x59A67B29              /* 2 */
#define retcode_ssl_err                 0x716A311F              /* 3 */
#define retcode_verify_fail             0x151358C6              /* 4 */
#define retcode_keyfile_err             0x389CD6A0
/**
 * debug stuff
 */
#ifdef DEBUG_ENABLED
#define debug_print(fmt,args...) printf(fmt,##args)
#else
#define debug_print(fmt,args...) 
#endif

/**
 * Minimum bufferlength for reply strings
 */
#define REPLY_MSG_LEN   40

/**
 * buffer sizes
 */
#define SHA256_DIGEST_LENGTH 32
#define SHA256_ASCII_DIGEST_LENGTH (SHA256_DIGEST_LENGTH * 2)
#define RSA2048_SIGNATURE_LEN 256
#define RSA2048_ASCII_SIGNATURE_LEN ( RSA2048_SIGNATURE_LEN * 2 )

 /**
  * cpe_local_verify_file_signature
  *
  * Input:
  *   char *data_file           - the file that has been signed
  *   size_t file_len           - the length of the file.  PASS (size_t)-1 for "don't know, use eof"
  *   char *sig_file            - contains the KMS ASCII hex signature ALL UPPER CASE as created by signing process
  *   char *vkey_file           - PEM format public key exported from KMS
  *   char *reply_msg           - buffer to receive message to send to logging system
  *       int  *reply_msg_len   - pointer to int containing size of buffer.  Must be at least 65 bytes.
  * Returns (see above for logical to actual :
  *   -1                                        - reply_msg NULL or *reply_msg_len too small, no check done, required size in *reply_msg_len
  *    0                                        - signature verifies, reply_msg buffer size ok, reply_msg has response
  *    1                                - failed reading data_file, no sig check done, reply_msg has response
  *        2                                    - failed reading sig_file, no sig check done, reply_msg has response
  *    3                                        - openssl operational error, no sig check done, reply_msg has response
  *    4                                        - signature does not match! reply_msg has response
  *
  *   -1 can also be returned for internal invalid lengths in buffer size variables. the logic is not fully implemented
  *      to check for buffer length updates and retry.  Left as an exercise.
  */
 int cpe_local_verify_file_signature(const char *data_file, size_t file_len, const char *sig_file, const char *vkey_file, char *reply_msg, int *reply_msg_len);

