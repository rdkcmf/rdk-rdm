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



#include "rdm_rsa_signature_verify.h"

#if defined(DEBUG_ENABLED)
static time_t timebuffer;
#endif

/**
 * @addtogroup RDM_API
 * @{
 */

/**
 * @brief This function outputs all the run's data to stdout and also to a binary file.
 *
 * @param[in] buffer          Data buffer
 * @param[in] buffer_size     Length of buffer
 * @param[in] name            Binary file name
 *
 */
void dump_buffer(void *buffer, int buffer_size, char *name)
{
#if defined(DEBUG_ENABLED)
        int i;

        /** this is for outputting all the run's data in binary files */
        struct tm *tm = localtime(&timebuffer);
        char s[128];
        static int filecount=0;

        memset(s,0,sizeof(s));
        strftime(s, sizeof(s), "%T-", tm);
        /* should be sndebug_print */
        sdebug_print(s+strlen(s),"%d-",filecount);

        strncat(s,name,sizeof(s)-strlen(name)-1);
        strncat(s,".bin",sizeof(s)-strlen(".bin")-1);

        filecount++;

        for(i = 0;i < buffer_size;++i) {
              debug_print("buffer[%d]=(%c) [%2.2x]\n",i, ((char *)buffer)[i],((unsigned char *)buffer)[i]);
        }

        FILE *binout = fopen(s,"wb");
        if ( binout == NULL ) return;
        fwrite(buffer,buffer_size,1,binout);
        fclose(binout);
#endif
}

 /**
  * @brief This function is used to convert asciihex data into binary format.
  *
  * @param[in]  asciihex           - Pointer to ascii hex string (not necessarily 0-term)
  * @param[in]  asciihex_length    - Length of ascii input string
  * @param[out] bin                - Pointer to output buffer
  * @param[out] bin_length         - Pointer length of output buffer
  *
  * @return Returns the status of the operation.
  * @retval -1 Bad input args: null pointers or insufficient length, length returned if too small.
  * @retval  0 All inputs OK, conversion performed.
  *
  * @note ASCII '0' = 0x30,'A' = 0x41. Case conversion/enforcement is based on same assumption.
  */
static
int asciihex_to_bin( const char *asciihex, size_t asciihex_length, unsigned char *bin, size_t *bin_length )
{
        if ( asciihex == NULL || bin == NULL || bin_length == NULL || (asciihex_length & 1) ) {
                return -1;
        }
        if ( *bin_length < asciihex_length/2 ) {
                *bin_length = asciihex_length/2;
                return -1;
        }

        while ( asciihex_length > 0 ) {
                unsigned char uc = (*asciihex++);
                if ( uc > '9' ) { uc &= ~0x20; uc -= ('A'-10); } else { uc -= '0'; }
                *bin = uc << 4;
                uc = (*asciihex++);
                if ( uc > '9' ) { uc &= ~0x20; uc -= ('A'-10); } else { uc -= '0'; }
                *bin++ |= uc;
                asciihex_length -= 2;
        }

        return 0;
}

/**
 * @brief This function is used to convert binary data into asciihex format.
 *
 * @param[in]  bin                   Pointer to binary input
 * @param[in]  bin_length            Length of binary input (bytes)
 * @param[out] asciihex              Pointer to ascii hex destination
 * @param[out] asciihex_length       Pointer to length of output buffer (must be at least 2x bin_length!)
 * 
 * @note THE SIGNATURE VALIDATION PACKAGES REQUIRES THE FILE IS HASHED AND THEN CONVERTED
 * TO ASCII HEX USING "xxd -ps -c 2048 binary_hash_file" FOR SIGNING.  THE SIGNED MESSAGE IS  LOWER-CASE
 * HEX ASCII.  SO WHEN THE HASH OVER THE DATA TO BE VERIFIED IS CONVERTED BACK TO BINARY FOR VERIFICATION,
 * THE CONVERSION MUST BE TO LOWER-CASE HEX ASCII.
 *
 * @return Returns the status of the operation.
 * @retval -1  Bad input args, length returned if too small.
 * @retval  0  All inputs OK, conversion returned.
 */
static
int bin_to_asciihex( const unsigned char *bin, size_t bin_length, char *asciihex, size_t *asciihex_length )
{
        if ( bin == NULL || asciihex == NULL || asciihex_length == NULL ) {
                return -1;
        }
        if ( *asciihex_length < bin_length * 2 ) {
                *asciihex_length = bin_length * 2;
                return -1;
        }
        size_t i;
        for( i=0; i < bin_length; i++, bin++ ) {
                unsigned char c = (*bin >> 4) + '0';
                if ( c > '9' ) {
                        c = c-('9'+1)+'a';
                }
                *asciihex++ = c;
                c = (*bin & 0x0f) + '0';
                if ( c > '9' ) {
                        c = c-('9'+1)+'a';
                }
                *asciihex++ = c;
        }
        return 0;
}

static int prepare_sig_file(char *sig_file) {
        char buffer[512] = {0};
        int read = 0, skip = 0, len = 0;
        char *mv_command = NULL;

        FILE *file_in = fopen(sig_file, "r");
        FILE *file_out = fopen(RDM_TMP_SIGFILE, "w+");

        if (NULL == file_in || NULL == file_out)
            return 1;

        while((read = fread(buffer, sizeof(char), sizeof(buffer), file_in)) > 0)
        {
                if(0 == skip && read > 6) {
                        //skip first 6 bytes
                        fwrite(&buffer[6], sizeof(char), read-6, file_out);
                        skip = 1;
                } else {
                        fwrite(buffer, sizeof(char), read, file_out);
                }
        }

        fclose(file_out);
        fclose(file_in);

        len = strlen("/bin/mv") + strlen(RDM_TMP_SIGFILE) + strlen(sig_file) + 3;
        mv_command = (char*) calloc(len, sizeof(char));
        sprintf(mv_command, "/bin/mv %s %s", RDM_TMP_SIGFILE, sig_file);

        system(mv_command);
        free(mv_command);

        return 0;
}

static int prepare_app_manifest(char *etc_manifest_file, char *cache_manifest_file, char* padding_file, char *prefix) {
        char *line = NULL;
        size_t len = 0;
        char *new_line = NULL;

        FILE *file_in = fopen(etc_manifest_file, "r");
        FILE *file_out = fopen(cache_manifest_file, "w+");

        if(file_in == NULL || file_out == NULL) {
                return 1;
        }

        while(getline(&line, &len, file_in) != -1) {
                if (NULL == new_line)
                    new_line = (char *) malloc(sizeof(char) * (strlen(line) + strlen(prefix) + 1));
                else
                    new_line = (char *) realloc(new_line, sizeof(char) * (strlen(line) + strlen(prefix) + 1));
                sprintf(new_line, "%s%s", prefix, line);
                fwrite(new_line, sizeof(char), strlen(new_line), file_out);
        }

        //add path to padding file
        fprintf(file_out, "%s\n", padding_file);

        if (new_line)
                free(new_line);
        if (line)
                free(line);

        fclose(file_in);
        fclose(file_out);

        return 0;
}

static int prepare_kms_pubkey() {
        int ret;
        ret = system("/usr/bin/configparamgen jx /etc/rdm/vjyrepbsb.ijv /tmp/vstuvwx.file");
        return WEXITSTATUS(ret);
}

/**
 *
 * @brief This function prepares the rdm files for signature verification
 * Does the following -
 * 1. Remove header added by KMS
 * 2. Prepare cpe manifest file with correct path to extracted files
 * 3. Decrypt kms public key
 */
static int prepare_rdm_files_for_sign_verification(char *cache_dir, char *app_name)
{
        char *app_cache_dir = NULL;
        char *app_home_dir = NULL;
        char *path_to_sig_file = NULL;
        char *cache_app_manifest = NULL;
        char *etc_app_manifest = NULL;
        char *path_to_padding_file = NULL;
        int  len, ret;

        len = strlen(cache_dir) + strlen(RDM_DOWNLOADS_DIR) + strlen(app_name) + 2;
        app_cache_dir = (char*) calloc(len, sizeof(char));
        sprintf(app_cache_dir, "%s%s%s/", cache_dir, RDM_DOWNLOADS_DIR, app_name);

        len = strlen(cache_dir) + strlen(app_name) + 3;
        app_home_dir = (char*) calloc(len, sizeof(char));
        sprintf(app_home_dir, "%s/%s/", cache_dir, app_name);

        len = strlen(app_cache_dir) + strlen(app_name) + strlen(RDM_SIGFILE_SUFFIX) + 1;
        path_to_sig_file = (char*) calloc(len, sizeof(char));
        sprintf(path_to_sig_file, "%s%s%s", app_cache_dir, app_name, RDM_SIGFILE_SUFFIX);
    
        ret = prepare_sig_file(path_to_sig_file);

        free(path_to_sig_file);

        if (ret) {
            free(app_cache_dir);
            free(app_home_dir);
            return ret;
        }

        len  = strlen(RDM_MANIFEST_DIR) + strlen(app_name) + strlen(RDM_MANIFEST_SUFFIX) + 1;
        etc_app_manifest = (char*) calloc(len, sizeof(char));
        sprintf(etc_app_manifest, "%s%s%s", RDM_MANIFEST_DIR, app_name, RDM_MANIFEST_SUFFIX);

        len  = strlen(app_home_dir) + strlen(app_name) + strlen(RDM_MANIFEST_SUFFIX) + 1;
        cache_app_manifest = (char*) calloc(len, sizeof(char));
        sprintf(cache_app_manifest, "%s%s%s", app_home_dir, app_name, RDM_MANIFEST_SUFFIX);

        len  = strlen(app_cache_dir) + strlen(RDM_KMS_PADDING_FILE) + 1;
        path_to_padding_file = (char*) calloc(len, sizeof(char));
        sprintf(path_to_padding_file, "%s%s", app_cache_dir, RDM_KMS_PADDING_FILE);

        ret = prepare_app_manifest(etc_app_manifest, cache_app_manifest, path_to_padding_file, app_home_dir);

        free(path_to_padding_file);
        free(app_cache_dir);
        free(app_home_dir);
        free(cache_app_manifest);
        free(etc_app_manifest);

        if (ret) {
            return ret;
        }

        ret = prepare_kms_pubkey();

        return ret;
}

/**
 *
 * @brief This function prepares the rdm files for signature verification and invokes
 * the kms openssl verification api
 */
int rdm_signature_verify(char *cache_dir, char *app_name, int prepare_files)
{
        int status = 1, len = 0;
        int outputMsgLen=REPLY_MSG_LEN;
        char outputMsg[REPLY_MSG_LEN] = "no response received";
        char *dataFile=NULL, *sigFile=NULL;

        if (NULL == cache_dir || NULL == app_name)
            return status;

        if (1 == prepare_files) {
            if (0 != prepare_rdm_files_for_sign_verification(cache_dir, app_name)) {
                printf("prepare_rdm_files_for_sign_verification failed\n");
                return status;
            }
        } else {
            if (0 != prepare_kms_pubkey()) {
                printf("prepare_kms_pubkey failed\n");
                return status;
            }
        }

        /* Initialize the openSSL crypto library and configurations */
        init_ssl_lib();

        len  = strlen(cache_dir) + 2 * strlen(app_name) + strlen(RDM_MANIFEST_SUFFIX) + 3;
        dataFile = (char*) calloc(len, sizeof(char));
        sprintf(dataFile, "%s/%s/%s%s", cache_dir, app_name, app_name, RDM_MANIFEST_SUFFIX);

        len = strlen(cache_dir) + strlen(RDM_DOWNLOADS_DIR) + 2 * strlen(app_name) + strlen(RDM_SIGFILE_SUFFIX) + 2;
        sigFile = (char*) calloc(len, sizeof(char));
        sprintf(sigFile, "%s%s%s/%s%s", cache_dir, RDM_DOWNLOADS_DIR, app_name, app_name, RDM_SIGFILE_SUFFIX);

        status = rdm_openssl_rsa_file_signature_verify( dataFile, -1, sigFile, RDM_KMS_PUB_KEY, outputMsg, &outputMsgLen );
        if ( status == retcode_success ) {
            printf("RSA Signature Validation Success\n");
            status = 0;
        } else {
            printf("RSA Signature Verification Failed\n");
        }

        free(dataFile);
        free(sigFile);

        unlink(RDM_KMS_PUB_KEY);
        return status;
}

/**
 *
 * @brief This function initializes the openSSL crypto library and configurations
 *
 */
void init_ssl_lib(void)
{
        static int      ssl_init=0;

        if ( ssl_init ) {return;}
        /* Load the human readable error strings for libcrypto */
        ERR_load_crypto_strings();

        /* Load all digest and cipher algorithms */
        OpenSSL_add_all_algorithms();

        /* Load config file, and other important initialisation */
        OPENSSL_config(NULL);
        ssl_init++;
#if defined(DEBUG_ENABLED)
        timebuffer = time(NULL);
#endif
}

/**
 *
 * @brief This function decodes the signature file.
 *
 * @param[in] sig_file                      Pointer to signature file
 * @param[in] sig_buffer                    Output signature buffer
 * @param[in] sig_size                      Pointer to signature file size
 *
 * @ret returns  -1                         Bad parameters, including bad length.  *buffer_len contains required len.
 * @ret returns   2                         Failed reading sig_file, no sig check done, reply_msg has response
 */
static
int read_signature_file( const char *sig_file, unsigned char **sig_buffer, int *sig_size )
{
        FILE *sig_fh;

        /* file buffer */
        char buf[RSA2048_ASCII_SIGNATURE_LEN];

        /* Keep internal buffer, return to caller */
        static unsigned char sig[RSA2048_SIGNATURE_LEN];

        if ( sig_file == NULL || sig_buffer == NULL || sig_size == NULL ) {
                debug_print("read_signature_file parm error\n");
                return retcode_param_error;
        }

        /**
         * read and convert file here
         */

        sig_fh = fopen( sig_file, "r" );        /* its ascii.  not binary.  this keeps us honest*/
        if ( sig_fh == NULL ) {
                debug_print("read_signature_file file open error\n");
                return retcode_sigfile_err;
        }

        size_t nread = fread( buf, 1, RSA2048_ASCII_SIGNATURE_LEN, sig_fh );
        if ( nread != (RSA2048_ASCII_SIGNATURE_LEN) || ferror( sig_fh ) ) {
                fclose( sig_fh );
                debug_print("read_signature_file file read error\n");
                return retcode_sigfile_err;
        }
        fclose( sig_fh );

#if defined(DEBUG_ENABLED)
        char buf2[RSA2048_ASCII_SIGNATURE_LEN + 1];
        memcpy(buf2, buf ,RSA2048_ASCII_SIGNATURE_LEN);
        buf2[RSA2048_ASCII_SIGNATURE_LEN] = 0;
        debug_print("Sig file contents:\n%s\n",buf2);
#endif
        size_t sig_len = sizeof( sig );
        if ( asciihex_to_bin( buf, RSA2048_ASCII_SIGNATURE_LEN, sig, &sig_len ) != 0 ) {
                return -1;
        }
        *sig_buffer = sig;
        *sig_size = RSA2048_SIGNATURE_LEN;
        return 0;
}
/** @} */  //END OF GROUP RDM_API

/**
 * @addtogroup RDM_TYPES
 * @{
 */

static
int manifest_file_size(const char *data_file, int *buffer_size)
{
      FILE *data_fh=NULL;
      int retval=0;
      data_fh = fopen( data_file, "r" );
      if ( data_fh == NULL )
      {
      		debug_print("manifest_file_size(): datafile open error\n");
                retval = retcode_datafile_err;
          	goto error;
      }
      fseek(data_fh, 0, SEEK_END);
      // calculating the size of the cpemanifest file
      *buffer_size = ftell(data_fh) + 1;

      if ( fseek( data_fh, 0, SEEK_END ) != 0 ) {
                retval = retcode_datafile_err;
                goto error;
      }

      if ( ferror( data_fh ) ) {
                retval = retcode_datafile_err;
                goto error;
      }

error:
        if ( data_fh != NULL ) fclose( data_fh );
        return retval;
}

/** @} */  //END OF GROUP RDM_TYPES


/**
 * @addtogroup RDM_API
 * @{
 */

/**
 * @brief This function is used to read and digest the data file.
 *
 * @param[in] data_file           The file to calculate a hash over
 * @param[in] hash_buffer         Pointer to memory to receive hash
 * @param[in] buffer_len          Pointer to int length of callers buffer
 * 
 * @ret returns 0                 Hash is complete and in caller's buffer.
 * @ret returns 1                 Data file error.
 * @ret returns -1                Bad parameters, including bad length.
 * @ret returns 3                 Openssl returned some sort of error.
 */
static
int rdm_openssl_file_hash_sha256( const char *data_file, size_t file_len, unsigned char *hash_buffer, int *buffer_len )
{
        int BUFSIZE;
        if ( manifest_file_size(data_file, &BUFSIZE) != 0 )
              return retcode_datafile_err;
        EVP_MD_CTX *mdctx=NULL;
        FILE *data_fh=NULL;
        unsigned char* buffer= (unsigned char*)calloc(sizeof(unsigned char), BUFSIZE );
        int retval;

        debug_print("rdm_openssl_file_hash_sha256() Entry\n");

        if ( data_file == NULL || hash_buffer == NULL || buffer_len == NULL ) {
                debug_print("rdm_openssl_file_hash_sha256(): Invalid param error\n");
                retval=retcode_param_error;
                goto error;
        }
        if ( *buffer_len < SHA256_DIGEST_LENGTH ) {
                *buffer_len = SHA256_DIGEST_LENGTH;
                debug_print("rdm_openssl_file_hash_sha256(): Wrong param error\n");
                retval=retcode_param_error;
                goto error;
        }
        /**
         * read and digest the data file
         */
        data_fh = fopen( data_file, "r" );
        if ( data_fh == NULL ) {
                debug_print("rdm_openssl_file_hash_sha256(): datafile open error\n");
                retval=retcode_datafile_err;
                goto error;
        }

        /* init ret code to ssl error */
        retval = retcode_ssl_err;

        if((mdctx = EVP_MD_CTX_create()) == NULL) {
                debug_print("rdm_openssl_file_hash_sha256(): Digest Context Initialize Failed\n");
                goto error;
        }

        if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
                debug_print("rdm_openssl_file_hash_sha256(): Digest Context Type Setup Failed\n");
                goto error;
        }

        retval = retcode_datafile_err;
        if ( file_len == (size_t)-1 ) {
                if ( fseek( data_fh, 0, SEEK_END ) != 0 ) {
                        goto error;
                }
                file_len = (size_t)ftell( data_fh );
                if ( fseek( data_fh, 0, SEEK_SET ) != 0 ) {
                        goto error;
                }
        }
        size_t bytesread=0;
        
        do {
                size_t bytes_to_read = ( file_len < sizeof(buffer) ? file_len : sizeof(buffer) );
                bytesread = fread(buffer, 1, bytes_to_read, data_fh );
                if ( bytesread > 0 ) {
                        if(1 != EVP_DigestUpdate(mdctx, buffer, bytesread)) {
                                goto error;
                        }
                }
                file_len -= bytes_to_read;
        } while ( file_len > 0 );
        
        if ( ferror( data_fh ) ) {
                retval = retcode_datafile_err;
                goto error;
        }

        int hashval_len;
        if( 1 != EVP_DigestFinal_ex(mdctx, hash_buffer, &hashval_len) ) {
                goto error;
        }
        if ( hashval_len != SHA256_DIGEST_LENGTH ) {
                goto error;
        }
        retval = 0;

error:

        if ( data_fh != NULL ) fclose( data_fh );
        if ( mdctx != NULL ) EVP_MD_CTX_destroy( mdctx );
        if ( buffer != NULL ) free( buffer );
        return retval;
}

/**
 * @brief This function is used to initiating signature validation of individual package components.
 *
 * @param[in]  data_file          Manifest file having path for all package components
 * @param[out] hash_buffer        Pointer to memory to receive hash
 * @param[out] buffer_len         Pointer to int length of callers buffer
 * 
 * @return Reurns the status of operation.
 *
 * @retval 0                      Hash is complete and in caller's buffer.
 * @retval 1                      Data file error.
 * @retval -1                     Bad parameters, including bad length.
 * @retval 3                      Openssl returned some sort of error.
 */
static
int rdm_openssl_file_hash_sha256_pkg_components( const char *data_file, size_t file_len, unsigned char *hash_buffer, int *buffer_len )
{
        int BUFSIZE;
        if ( manifest_file_size(data_file, &BUFSIZE) != 0 )
              return retcode_datafile_err;
        EVP_MD_CTX *mdctx=NULL;
        FILE *manifest_fh=NULL;
        FILE *data_fh=NULL;
        unsigned char* buffer= (unsigned char*)calloc(sizeof(unsigned char), BUFSIZE );
        char *manifest=NULL;
        char *path_buff=NULL;
        int retval;
        size_t bytesread=0;

        debug_print("rdm_openssl_file_hash_sha256_pkg_components() Entry\n");

        if ( data_file == NULL || hash_buffer == NULL || buffer_len == NULL ) {
                debug_print("rdm_openssl_file_hash_sha256_pkg_components(): Invalid param error\n");
                retval=retcode_param_error;
                goto error;
        }
        if ( *buffer_len < SHA256_DIGEST_LENGTH ) {
                *buffer_len = SHA256_DIGEST_LENGTH;
                debug_print("rdm_openssl_file_hash_sha256_pkg_components(): Wrong param error\n");
                retval=retcode_param_error;
                goto error;
        }
        /**
         * Read and digest the manifest file
         */
        manifest_fh = fopen( data_file, "r" );
        if ( manifest_fh == NULL ) {
                debug_print("rdm_openssl_file_hash_sha256_pkg_components(): manifest file open error\n");
                retval=retcode_datafile_err;
                goto error;
        }

        /* init ret code to ssl error */
        retval = retcode_ssl_err;

        if((mdctx = EVP_MD_CTX_create()) == NULL) {
                debug_print("rdm_openssl_file_hash_sha256_pkg_components(): Digest Context Initialize Failed\n");
                goto error;
        }

        if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
                debug_print("rdm_openssl_file_hash_sha256_pkg_components(): Digest Context Type Setup Failed\n");
                goto error;
        }

        retval = retcode_datafile_err;
        manifest = calloc(sizeof(char), BUFSIZE);
        if ( NULL == manifest ) {
            debug_print("rdm_openssl_file_hash_sha256_pkg_components(): memory allocation failed\n");
            goto error;
        }
        fread(manifest, BUFSIZE, 1, manifest_fh);
        fclose(manifest_fh);
        path_buff = strtok(manifest, "\t\r\n");
        while ( path_buff != NULL )
        {
            data_fh = fopen( path_buff, "r" );
            if(  strstr(path_buff, "tmp") || strstr(path_buff, "media") || strstr(path_buff, "padding") ||  strstr(path_buff, "json") ) {
                if ( data_fh == NULL ) {
                    printf("rdm_openssl_file_hash_sha256_pkg_components: datafile open error\n");
                    goto error;
                }
                bytesread=0;
                while (1) {
                    bytesread = fread(buffer, 1, BUFSIZE, data_fh );
                    if ( bytesread > 0 ) {
                        if( 1 != EVP_DigestUpdate(mdctx, buffer, bytesread) ) {
                            goto error;
                        }
                    }
                    if ( bytesread != BUFSIZE)
                        break; // EoF found
                }
                if ( ferror( data_fh ) ) {
                    goto error;
                }
            }
            path_buff = strtok(NULL, "\t\r\n");
            if ( data_fh != NULL ) fclose( data_fh );
            data_fh=NULL;
        }
        
        int hashval_len;
        if( 1 != EVP_DigestFinal_ex(mdctx, hash_buffer, &hashval_len) ) {
                goto error;
        }
        if ( hashval_len != SHA256_DIGEST_LENGTH ) {
                goto error;
        }
        retval = 0;

error:

        if ( data_fh != NULL ) fclose( data_fh );
        if ( mdctx != NULL ) EVP_MD_CTX_destroy( mdctx );
        if ( manifest != NULL) free( manifest );
        if ( buffer != NULL ) free( buffer );
        return retval;
}

/**
 * @brief This function performs signature verification process.
 *
 * @param[in] hashval                 Hash generated over the data
 * @param[in] hashval_len             Length of hash though we know this all coded to SHA256
 * @param[in] sig_file                Contains the KMS ASCII hex signature ALL UPPER CASE as created by signing process
 * @param[in] vkey_file               PEM format public key exported from KMS
 * @param[in] reply_msg               Buffer to receive message to send to logging system
 * @param[in] reply_msg_len           Pointer to int containing size of buffer.  Must be at least 65 bytes.
 *
 * @ret returns -1                    Bad parameters, including bad length.  *buffer_len contains required len.
 */

static
int openssl_verify_signature(const unsigned char *hashval, int hashval_len, const char *sig_file, const char *vkey_file, char *reply_msg, int *reply_msg_len)
{

        EVP_MD_CTX *mdctx=NULL;
        FILE *sig_fh=NULL;
        EVP_PKEY *pkey=NULL;
        char hash_ascii[SHA256_ASCII_DIGEST_LENGTH + 1];
        unsigned char *sig;
        int sig_len;
        int retval;


        /* Only one parameter hasn't been checked by the calling code */
        if ( hashval == NULL ) {
                return retcode_param_error;
        }

        /**
         * For no particular reason, decode the signature file first
         */
        retval = read_signature_file( sig_file, &sig, &sig_len );
        if ( retval != 0 ) {
                debug_print("read_signature_file returns err\n");
                goto error;
        }
#if defined(DEBUG_ENABLED)
        dump_buffer( sig, sig_len, "decoded-sig" );
#endif
        size_t hashval_ascii_len = SHA256_ASCII_DIGEST_LENGTH;
        if ( bin_to_asciihex( hashval, hashval_len, hash_ascii, &hashval_ascii_len ) != 0 ) {
                debug_print("bin_to_asciihex fail\n");
                retval = -1;  
                goto error;
        }

        /* CAREFUL here - add a 0-terminator.  Don't use that trailing 0! */
        hash_ascii[sizeof(hash_ascii)-1] = 0;
        debug_print("HASH ASCII (signed message):\n%s\n",hash_ascii);

        /**
         * Perform verify operations
         */

        /* initialize `key` with a public key */
        debug_print("reading key file: %s\n",vkey_file);
        FILE *pub_fh = fopen( vkey_file, "rb" );
        if ( pub_fh == NULL ) {
                debug_print( "pubkey open fail\n" );
                retval = retcode_keyfile_err;
                goto error;
        }

        pkey = PEM_read_PUBKEY( pub_fh, NULL, NULL, NULL );
        if ( pkey == NULL ) {
                debug_print( "pubkey read fail\n" );
                goto error;
        }

        /* reinit a digest context */
        EVP_MD_CTX_destroy( mdctx );
        if((mdctx = EVP_MD_CTX_create()) == NULL) {
                debug_print( "verify context create fail\n" );
                goto error;
        }

        /* Initialize verify */
        if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey)) {
                debug_print( "digest verify init fail\n" );
                goto err;
        }

        /* perform verify */
        if( 1 != EVP_DigestVerifyUpdate( mdctx, hash_ascii, SHA256_ASCII_DIGEST_LENGTH ) ) {
                debug_print( "digest verify update fail\n" );
                goto err;
        }

        /* check verify */
        if(1 == EVP_DigestVerifyFinal( mdctx, sig, sig_len) )
        {
                retval = retcode_success;
        }
        else
        {
                retval = retcode_verify_fail;
        }
err:
error:

        if ( sig_fh != NULL ) fclose( sig_fh );
        if ( pub_fh != NULL ) fclose( pub_fh );
        if ( mdctx != NULL ) EVP_MD_CTX_destroy( mdctx );
        if ( pkey != NULL ) EVP_PKEY_free( pkey );

        /* other clean here */

        snprintf( reply_msg, (size_t)REPLY_MSG_LEN, "c_l_s_v performance status: %x", retval );
        return retval;
 }



/**
 * @brief This function is used for a signature validation of the package.
 *
 * @param[in] data_file              Input data file.
 * @param[in] file_len               Input data file length.
 * @param[in] sig_file               Signature file.
 * @param[in] vkey_file              Public key file.
 * @param[in] reply_msg              Return Value.
 * @param[in] reply_msg_len          Length of return value message.
 *
 * @return Returns the status of the operation.
 * @retval -1                         On error.
 * @retval 5                          When failed to open public key.
 * @retval 0                          Success on signature verification.
 * @retval 2                          Failure on signature verification.
 */
 int rdm_openssl_rsa_file_signature_verify(const char *data_file, size_t file_len, const char *sig_file, const char *vkey_file, char *reply_msg, int *reply_msg_len)
 {
         int retval;

         unsigned char hashval[SHA256_DIGEST_LENGTH];
         int hashval_len=SHA256_DIGEST_LENGTH;

         debug_print("Entry: rdm_openssl_rsa_file_signature_verify\n");
         if ( data_file == NULL ||
                         sig_file == NULL ||
                         reply_msg == NULL ||
                         vkey_file == NULL ||
                         reply_msg_len == NULL ) {
                 debug_print("rdm_openssl_rsa_file_signature_verify(): Input Args parameter error\n");
                 return retcode_param_error;
         }

         if ( *reply_msg_len < REPLY_MSG_LEN ) {
                 *reply_msg_len = REPLY_MSG_LEN;
                 debug_print("rdm_openssl_rsa_file_signature_verify(): Output Buffer Len parameter error\n");
                 return retcode_param_error;
         }

         if ( NULL == strstr(data_file, "cpemanifest") ) {
             retval = rdm_openssl_file_hash_sha256( data_file, file_len, hashval, &hashval_len );
         }
         else {
             // Input data file is manifest file having path for all package components
             printf("rdm_openssl_rsa_file_signature_verify():Initiating signature validation of individual package components\n");
             retval = rdm_openssl_file_hash_sha256_pkg_components( data_file, file_len, hashval, &hashval_len );
         }
         if ( retval != 0 ) {
                debug_print("rdm_openssl_rsa_file_signature_verify(): rdm_openssl_file_hash_sha256 returns err %x\n",retval);
                return retval;
         }

         retval = openssl_verify_signature(hashval, hashval_len, sig_file, vkey_file, reply_msg, reply_msg_len);
         return retval;

 }

/** @} */  //END OF GROUP RDM_API
