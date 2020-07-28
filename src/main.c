#include "rdm_rsa_signature_verify.h"

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
