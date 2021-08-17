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
 * @defgroup RDM RDM(RDK Download Manager)
 *
 * - RDM is used for the management of downloadable modules.
 * - RDK download manager enforces https connections for downloading modules (does not allow non-https connections).
 *
 * @defgroup RDM_API  RDM Public APIs
 * @ingroup  RDM
 *
 * @defgroup RDM_TYPES RDM Data Types
 * @ingroup  RDM
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#define RDM_DOWNLOADS_DIR       "/rdm/downloads/"
#define RDM_MANIFEST_DIR        "/etc/rdm/"
#define RDM_TMP_SIGFILE         "/tmp/sig.truncated"
#define RDM_KMS_PUB_KEY         "/tmp/vstuvwx.file"
#define RDM_KMS_PADDING_FILE    "pkg_padding"
#define RDM_SIGFILE_SUFFIX      "-pkg.sig"
#define RDM_MANIFEST_SUFFIX     "_cpemanifest"
#define ENABLE_DEBUG_FLAG       "/tmp/debug_rdmopenssl"

/**
 * @addtogroup RDM_TYPES
 * @{
 */


/**
 * Obfuscated error return values.
 * Inital status returns to splunk will consist of the string:
 * "performance status bla bla: " followed by the hex ascii of one of
 * the following values.
 */
#define retcode_param_error     0x5165C860              /*!< -1 */
#define retcode_success         0x15245EAD              /*!< 0 */
#define retcode_datafile_err    0x3560800C              /*!< 1 */
#define retcode_sigfile_err     0x59A67B29              /*!< 2 */
#define retcode_ssl_err                 0x716A311F              /*!< 3 */
#define retcode_verify_fail             0x151358C6              /*!< 4 */
#define retcode_keyfile_err             0x389CD6A0
/**
 * debug stuff
 */
#ifdef DEBUG_ENABLED
#define debug_print(fmt,args...) printf(fmt,##args)
#else
#define debug_print(fmt,args...) if(access(ENABLE_DEBUG_FLAG, F_OK) != -1) printf(fmt,##args);
#endif

/**< Minimum bufferlength for reply strings */
#define REPLY_MSG_LEN   40

/**< buffer sizes */
#define SHA256_DIGEST_LENGTH 32
#define SHA256_ASCII_DIGEST_LENGTH (SHA256_DIGEST_LENGTH * 2)
#define RSA2048_SIGNATURE_LEN 256
#define RSA2048_ASCII_SIGNATURE_LEN ( RSA2048_SIGNATURE_LEN * 2 )

/** @} */  //END OF GROUP RDM_TYPES

/**
 * @addtogroup RDM_API
 * @{
 */

 /**
  *
  * @brief This function is used to verify the signature of rdm package
  *
  *  @param[in] *cache_dir          - Mount point where rdm packages are extracted (Eg - /media/apps, /tmp)
  *  @param[in] *app_name           - Name of the app
  *  @param[in] *prepare_files      - 1 - prepare files and then verify signature. 0 - just verify signature
  *
  *  @return The status of the operation.
  *
  *  @reval    0                     - Signature verification success
  *  @retval   1                     - Signature verification failed
  */
 int rdm_signature_verify(char *cache_dir, char *app_name, int prepare_files);

 /**
  * @brief This function is used to verify the signature file locally.
  *
  *  @param[in] *data_file           - The file that has been signed
  *  @param[in] file_len             - The length of the file.  PASS (size_t)-1 for "don't know, use eof"
  *  @param[in] *sig_file            - Contains the KMS ASCII hex signature ALL UPPER CASE as created by signing process
  *  @param[in] *vkey_file           - PEM format public key exported from KMS
  *  @param[out] *reply_msg          - Buffer to receive message to send to logging system
  *  @param[out] *reply_msg_len      - Pointer to int containing size of buffer.  Must be at least 65 bytes.
  *
  * @return The status of the operation.
  *
  * @reval    -1                     - reply_msg NULL or *reply_msg_len too small, no check done, required size in *reply_msg_len.
  * @retval   0                      - Signature verifies, reply_msg buffer size ok, reply_msg has response.
  * @retval   1                      - Failed reading data_file, no sig check done, reply_msg has response.
  * @retval   2                      - Failed reading sig_file, no sig check done, reply_msg has response.
  * @retval   3                      - Openssl operational error, no sig check done, reply_msg has response.
  * @retval   4                      - Signature does not match! reply_msg has response.
  *
  * @note  -1 can also be returned for internal invalid lengths in buffer size variables. the logic is not fully implemented
  *      to check for buffer length updates and retry.  Left as an exercise.
  */
 int cpe_local_verify_file_signature(const char *data_file, size_t file_len, const char *sig_file, const char *vkey_file, char *reply_msg, int *reply_msg_len);

/** @} */  //END OF GROUP RDM_API
