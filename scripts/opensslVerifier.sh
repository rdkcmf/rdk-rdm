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

WORKDIR=$1
PACKAGE_FILE=$2
SIGNATURE_FILE=$3
SIGNATURE_TYPE=$4

CPEMANIFEST_PATH=""
APP_NAME="$(echo $PACKAGE_FILE | sed 's/-pkg.tar//g')"
CPEMANIFEST=/etc/rdm/${APP_NAME}_cpemanifest
SDCARD_DLPATH=/media/apps/$APP_NAME
TMP_DLPATH=/tmp/$APP_NAME


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
    RDK_CA_PATH=`find ${SSL_PATH} -name ${RDK_CA_NAME} -type f | head -n1`
    if [ ! $RDK_CA_PATH ]; then
        log_msg "RDK CA Chain missing from firmware"
        exit 1
    fi
    VER_CERT=${WORKDIR}/${CERT}
	# Validate Certificate
    #openssl verify -CAfile ${RDK_CA_PATH}/${RDK_CA_NAME} ${VER_CERT}	
    openssl verify -CAfile ${RDK_CA_PATH} ${VER_CERT}	
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
        openssl x509 -in $VER_CERT -pubkey -noout > /tmp/pubkey.pem
        cd ${WORKDIR}
        openssl dgst -sha256 -verify /tmp/pubkey.pem -signature ${SIGNATURE_FILE} ${PACKAGE_FILE}
        if [ $? -ne 0 ]; then
            log_msg "Signature validation Failed"
            rm -rf $RSA_KEY_FILE $VER_CERT
            exit 2
        else
            log_msg "Signature validation Successful"
            rm -rf $RSA_KEY_FILE $VER_CERT
            exit 0
       fi
       if [ -f /tmp/pubkey.pem ];then
            rm -rf /tmp/pubkey.pem
       fi
       cd -
else
        # TODO we can add more Signature Type validation here
        log_msg "Unknown Signature Type"
fi

log_msg "Validate the Package"
if [ -f /usr/bin/opensslVerify ];then
      if [ -e $CPEMANIFEST -a -n "$(echo $WORKDIR | awk '/^\/media\/apps\//')" ]; then
          CPEMANIFEST_PATH=$SDCARD_DLPATH/${APP_NAME}_cpemanifest
          cp $CPEMANIFEST $CPEMANIFEST_PATH
          sed -e "s/^/\/media\/apps\/${APP_NAME}\//" -i $CPEMANIFEST_PATH
          echo "$WORKDIR/pkg_padding" >> $CPEMANIFEST_PATH
      elif [ -e $CPEMANIFEST -a -n "$(echo $WORKDIR | awk '/^\/tmp\//')" ]; then
          CPEMANIFEST_PATH=$TMP_DLPATH/${APP_NAME}_cpemanifest
          cp $CPEMANIFEST $CPEMANIFEST_PATH
          sed -e "s/^/\/tmp\/$APP_NAME\//" -i $CPEMANIFEST_PATH
          echo "$WORKDIR/pkg_padding" >> $CPEMANIFEST_PATH
      else
          CPEMANIFEST_PATH=""
      fi

      if [ "x$CPEMANIFEST_PATH" != "x" ]; then
          log_msg "Signature generated by concatenating all pkg components."
          log_msg "Manifest file having path for all package components: $CPEMANIFEST_PATH "
          status=`/usr/bin/opensslVerify -f $CPEMANIFEST_PATH -s $WORKDIR/$SIGNATURE_FILE -k $KMS_INTERMEDIATE_RSA_KEY_FILE`
      else
          status=`/usr/bin/opensslVerify -f $WORKDIR/$PACKAGE_FILE -s $WORKDIR/$SIGNATURE_FILE -k $KMS_INTERMEDIATE_RSA_KEY_FILE`
      fi

      log_msg "Openssl Verify Result: $status"
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

