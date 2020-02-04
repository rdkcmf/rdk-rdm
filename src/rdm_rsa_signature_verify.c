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




#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
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

/**
 *
 * @brief This function initializes the openSSL crypto library and configurations
 *
 */
static
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

#define BUFSIZE 16384
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
        EVP_MD_CTX *mdctx=NULL;
        FILE *data_fh=NULL;
        unsigned char buffer[BUFSIZE];
        int retval;

        debug_print("rdm_openssl_file_hash_sha256() Entry\n");

        if ( data_file == NULL || hash_buffer == NULL || buffer_len == NULL ) {
                debug_print("rdm_openssl_file_hash_sha256(): Invalid param error\n");
                return retcode_param_error;
        }
        if ( *buffer_len < SHA256_DIGEST_LENGTH ) {
                *buffer_len = SHA256_DIGEST_LENGTH;
                debug_print("rdm_openssl_file_hash_sha256(): Wrong param error\n");
                return retcode_param_error;
        }
        /**
         * read and digest the data file
         */
        data_fh = fopen( data_file, "r" );
        if ( data_fh == NULL ) {
                debug_print("rdm_openssl_file_hash_sha256(): datafile open error\n");
                return retcode_datafile_err;
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
        EVP_MD_CTX *mdctx=NULL;
        FILE *manifest_fh=NULL;
        FILE *data_fh=NULL;
        unsigned char buffer[BUFSIZE];
        char *manifest=NULL;
        char *path_buff=NULL;
        int retval;
        size_t bytesread=0;

        debug_print("rdm_openssl_file_hash_sha256_pkg_components() Entry\n");

        if ( data_file == NULL || hash_buffer == NULL || buffer_len == NULL ) {
                debug_print("rdm_openssl_file_hash_sha256_pkg_components(): Invalid param error\n");
                return retcode_param_error;
        }
        if ( *buffer_len < SHA256_DIGEST_LENGTH ) {
                *buffer_len = SHA256_DIGEST_LENGTH;
                debug_print("rdm_openssl_file_hash_sha256_pkg_components(): Wrong param error\n");
                return retcode_param_error;
        }
        /**
         * Read and digest the manifest file
         */
        manifest_fh = fopen( data_file, "r" );
        if ( manifest_fh == NULL ) {
                debug_print("rdm_openssl_file_hash_sha256_pkg_components(): manifest file open error\n");
                return retcode_datafile_err;
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
        manifest = malloc(BUFSIZE);
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
            if(  strstr(path_buff, "tmp") || strstr(path_buff, "media") || strstr(path_buff, "padding") ) {
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

void usage(void)
{
        printf("Usage:\n");
        printf(" f <filename>\n");
        printf(" s <signature file> [PEM format]\n");
        printf(" k <public key file>\n");
        exit (1);
}

 int main(int argc, char *argv[])
 {
        int status = 0, opt = 0;
        int outputMsgLen=REPLY_MSG_LEN;
        char outputMsg[REPLY_MSG_LEN] = "no response received";
        char *dataFile=NULL, *sigFile=NULL, *keyFile=NULL;

        debug_print("Program name: %s\n", argv[0]);

        /* Initialize the openSSL crypto library and configurations */
        init_ssl_lib();
#if defined(DEBUG_ENABLED)
        timebuffer = time(NULL);
#endif
        while ((opt = getopt(argc, argv, "f:s:k:")) != -1) {
            switch(opt) {
  		case 'f':
                        dataFile = optarg;
    			printf("Input option value=%s\n", dataFile);
    			break;
    		case 's':
    			sigFile = optarg;
    			printf("Output option value=%s\n", sigFile);
    			break;
    		case 'k':
    			keyFile = optarg;
    			printf("Output option value=%s\n", keyFile);
    			break;
    		case '?':
    			if (optopt == 'f') {
    				printf("Missing mandatory Input File\n");
  			} else if (optopt == 's') {
     				printf("Missing mandatory Signature File\n");
  			} else if (optopt == 'k') {
     				printf("Missing mandatory Key File\n");
  			} else {
     				printf("Invalid option received\n");
  			}
                        usage();
  			break;
 	    }
 	}
        if ( dataFile == NULL || sigFile == NULL || keyFile == NULL ) {
                usage();
                exit(1);
        }

        status = rdm_openssl_rsa_file_signature_verify( dataFile, -1, sigFile,
                                  keyFile, outputMsg, &outputMsgLen );
        debug_print("rdm_openssl_rsa_file_signature_verify returns: %s\n",outputMsg);
        if ( status == retcode_success ) {
               printf("RSA Signature Validation Success\n");
        } else {
               printf("RSA Signature Verification Failed\n");
        }
        return status;
}

/** @} */  //END OF GROUP RDM_API
