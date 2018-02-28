#!/bin/sh
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2018 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
if [ -f /etc/rdm/downloadUtils.sh ];then
    . /etc/rdm/downloadUtils.sh
else
    echo "[/etc/rdm/downloadUtils.sh], File Not Found"
fi
# logging for verification
LOG_FILE="/opt/logs/rdm_status.log"
WORKDIR=$1
PACKAGE_FILE=$2
SIGNATURE_FILE=$3
SIGNATURE_TYPE=$4

if [ ! "$WORKDIR" -o ! "$PACKAGE_FILE" -o ! "$SIGNATURE_FILE" -o ! "$SIGNATURE_TYPE" ];then
     log_msg "Wrong Inputs: [path: $WORKDIR, pkg: $PACKAGE_FILE, sig: $SIGNATURE_FILE sig_type: SIGNATURE_TYPE]"
     exit 1
else
     log_msg "Inputs: [path: $WORKDIR, pkg: $PACKAGE_FILE, sig: $SIGNATURE_FILE sig_type: $SIGNATURE_TYPE]"
fi

# Additional parameter verification ceritifcate
# is needed for Signature Validation
if [ "$SIGNATURE_TYPE" = "openssl" ]; then
    CERT=$5
    if [ ! $CERT ] ; then
        log_msg "Wrong Input Cert is missing [Cert: $CERT]"
        exit 1
    fi
fi

# Sub routine to validate cert
validateCert()
{
    # Default use RDK CA Chain of trust for Cert validation
    RDK_CA_NAME="comcast-rdk-ca-chain.cert.pem"
    # Default path to locate RDK CA into firmware
    SSL_PATH="/etc/ssl"
    RDK_CA_PATH=`find ${SSL_PATH} -name ${RDK_CA_NAME} -type f | xargs dirname`
    if [ ! $RDK_CA_PATH ]; then
        log_msg "RDK CA Chain missing from firmware"
        exit 1
    fi
    VER_CERT=${WORKDIR}/${CERT}
	# Validate Certificate
    openssl verify -CAfile ${RDK_CA_PATH}/${RDK_CA_NAME} ${VER_CERT}	
    if [ $? -ne 0 ]; then
         log_msg "Certificate $CERT Validation Failed"
         exit 1
    else
         log_msg "Certificate $CERT Validated Successfully"
    fi
}

# Decode the RSA Public Key
if [ "$SIGNATURE_TYPE" = "kms" ];then
        log_msg "Package with KMS signature"
        CONFIGPARAMGEN=/usr/bin/configparamgen
        KMS_RSA_PUBLIC_KEY_FILE=/etc/rdm/vjyrepbsb.ijv
        KMS_INTERMEDIATE_RSA_KEY_FILE=${WORKDIR}/vstuvwx.file
        # Since KMS is adding 3 Bytes of Header, need to remove this before validation
        # KMS Header Removal from the Signature
        if [ -f "$WORKDIR/$SIGNATURE_FILE" ];then
              log_msg "Removing the KMS Prefix Header"
              dd if="$WORKDIR/$SIGNATURE_FILE" of="$WORKDIR/$SIGNATURE_FILE.truncated" bs=6 skip=1 && mv "$WORKDIR/$SIGNATURE_FILE.truncated" "$WORKDIR/$SIGNATURE_FILE" 
        fi
        # TODO Will remove this line once the code is stable
        cat $WORKDIR/$SIGNATURE_FILE
        # Decrypt the Key for Codebig
        $CONFIGPARAMGEN jx $KMS_RSA_PUBLIC_KEY_FILE $KMS_INTERMEDIATE_RSA_KEY_FILE

elif [ "$SIGNATURE_TYPE" = "openssl" ]; then
        # verification certificate 
        VER_CERT=${WORKDIR}/${CERT}
        RSA_KEY_FILE="${WORKDIR}/PUB.KEY"
        validateCert;
        #generate intermediate verification key from cert
        openssl x509 -in $VER_CERT -pubkey -noout > $RSA_KEY_FILE
        # Signature validation performed using CA certified
        # Perform signature validation
        openssl dgst -sha256 -verify $RSA_KEY_FILE -signature ${WORKDIR}/${SIGNATURE_FILE} ${WORKDIR}/${PACKAGE_FILE} 
        if [ $? -ne 0 ]; then
            log_msg "Signature validation Failed"
			echo "Signature validation Failed" >> $LOG_FILE
            rm -rf $RSA_KEY_FILE $VER_CERT
            exit 2
        else
            log_msg "Signature validation Successful"
            echo "Signature validation Successful" >> $LOG_FILE
            rm -rf $RSA_KEY_FILE $VER_CERT
            exit 0
       fi
else
        # TODO we can add more Signature Type validation here
        log_msg "Unknown Signature Type"
fi

log_msg "Validate the Package"
if [ -f /usr/bin/opensslVerify ];then
      status=`/usr/bin/opensslVerify -f $WORKDIR/$PACKAGE_FILE -s $WORKDIR/$SIGNATURE_FILE -k $KMS_INTERMEDIATE_RSA_KEY_FILE`
      echo $status | grep -i "Success"
      if [ $? -ne 0 ];then
           rm -rf $KMS_INTERMEDIATE_RSA_KEY_FILE
           exit 2
      else
           rm -rf $KMS_INTERMEDIATE_RSA_KEY_FILE
           exit 0
      fi
else
      log_msg "[/usr/bin/opensslVerify], The File Not Found"
      rm -rf $KMS_INTERMEDIATE_RSA_KEY_FILE
      exit 1
fi

