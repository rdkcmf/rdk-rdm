#!/bin/bash
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
# Assigned with dummy data
APP_NAME=""
# Default Version
APP_VERSION="1.0"
# need to add changes to update with real values
# for rel number and arch name
# Default Relese number
RELEASE_NUM="0000"
ARCH_NAME="DUMMY_ARCH"

localDir=`pwd`
usage()
{
    echo "----------------------USAGE--------------------------------"
    echo "USAGE: $0 -k <SIGNING_KEY> -c <CA_CERT> -p <PACKAGED_FILE1> -a <APPMGR_CONF1>"
    echo "          -p <PACKAGED_FILE2> -a <APPMGR_CONF2> ......"
    echo "<SIGNING_KEY>: Signing Key (ext *.key) to sing the package "
    echo "               Use -k option to provide Signing key"
    echo "<CA_CERT>  : CA Certified Verification Certificate (ext *.crt)"
    echo "             Use -c to provide certificate"
    echo "<PACKAGED_FILE>: Application tar file which needs to be signed"
    echo "                 Use option -p to provide package"
    echo "                 multiple packaged file along with app mngr can be provided"
    echo "<APPMGR_CONF>: App Manager config file"
    echo "               Use option -a to provide package config"
    echo "               Multiple app manager config file for multiple package"
    echo "----------------------------------------------------------"
}

# Subroutine to read application meta data from given config file
readAppConfig()
{
    APP_CONFIG=$1
# Dummy data shall be used in case of missing 
# required meta data
    APP_NAME=""
        # Define with default value
    APP_VERSION="1.0"
   
    echo "Reading config file $APP_CONFIG"
    APP_NAME=`cat $APP_CONFIG | grep -w \"displayName\" | tail -1 | cut -d\" -f4`
    APP_VERSION=`cat $APP_CONFIG | grep -w \"version\" | tail -1 | cut -d\" -f4`
    if [ "$APP_NAME" = "" ] ;then 
         echo "App Name is missing in provided config file"
         exit 0
    fi
}

# flag to confirm app config input 
# for packaged file
appConfigReq=0

# Reading Arguement
while getopts ":k:c:p:a:" opt; do
    case $opt in
    k)
      if [ $appConfigReq = 1 ]; then
          echo "App manager config file expected after packaged file"
          usage
          exit 0
      fi
      SIGNING_KEY=("$OPTARG")
      echo "Third Party Signing key is $SIGNING_KEY"
    ;;
    c)
      if [ $appConfigReq = 1 ]; then
          echo "App manager config file expected after packaged file"
          usage
          exit 0
      fi
      CA_CERT=("$OPTARG")
    ;;
    p)
      if [ $appConfigReq = 1 ]; then
          echo "App manager config file expected after packaged file"
          usage
          exit 0
      fi
      PACKAGE_LIST+=("$OPTARG")
      appConfigReq=1
    ;;
    a)
      if [ $appConfigReq = 0 ]; then
          echo "Packaged file expected prior to App manager config"
          usage
          exit 0
      fi
      APPCONF_LIST+=("$OPTARG")
      appConfigReq=0
    ;;
    *)
      echo "Invalid Input Arguement !!"
      usage 
      exit 0
    ;;
    esac
done

# Verify the input arguement
if [ ! -f "$SIGNING_KEY" ]; then
    echo "Signing Key does not exists"
    usage
    exit 0
fi

if [ ! -f "$CA_CERT" ]; then
     echo "Verification Certificate does not exists"
    usage
     exit 0
fi

if [ ${#PACKAGE_LIST[@]} = 0 ]; then
    echo "Packaged file to be signed is missing"
    echo "Provide at least one package for signing"
    usage
    exit 0
fi

if [ ${#APPCONF_LIST[@]} = 0 ]; then
    echo "App manager config file to define package attributes is missing"
    usage
    exit 0
fi


# Validate RSA Signing Key
openssl rsa -modulus -noout -in "${SIGNING_KEY}"
if [ $? -ne 0 ] ; then
    echo "RSA Siging key is invalid"
    exit 0
else
    #creating local copy for signing
    cp "${SIGNING_KEY}" ${localDir}
    SIGNING_KEY=`echo "${SIGNING_KEY}" | xargs basename`
fi

# Validate CA Certificate
openssl x509 -modulus -noout -in "${CA_CERT}"
if [ $? -ne 0 ] ; then
    echo "CA Certificate is invalid"
    exit 0
else
    #creating localo copy for packaging
    cp "${CA_CERT}" ${localDir}
    CA_CERT=`echo "${CA_CERT}" | xargs basename`
fi

# Assumption, valid {tar/ipk} packaged file shall be provided 
# by 3rd party App developer for signing, along with application
# meta data in a config file as per format given
#
# Script subjected to modify if above assumption does not meet

for ((idx=0; idx<${#PACKAGE_LIST[@]}; idx++)); do
    # Verify if package file exists
    # Move to next component if file 
    # does not exists
    PACKAGED_FILE="${PACKAGE_LIST[idx]}"
    APPMGR_CONF="${APPCONF_LIST[idx]}"
    if [[ ( ! -f "$PACKAGED_FILE") || ( ! -f "$APPMGR_CONF") ]]; then
        echo "Package file $PACKAGED_FILE or correspding App config $APPMGR_CONF does not exists"
        continue
    fi
    readAppConfig $APPMGR_CONF
    echo "Signing for $PACKAGED_FILE"
    # Fetch Package tarball name
    PACKAGED_TAR=`echo "$PACKAGED_FILE" | xargs basename`
    PACKAGED_NAME="${PACKAGED_TAR%.*}" 
    PACKAGED_EXTENSION="${PACKAGED_TAR#*.}"

    # App config file to be packaged with tarball
    APPCONF=`echo "$APPMGR_CONF" | xargs basename`
    # Ensure that packaged file having desired extension (tar/ipk)
    if [[ (! ("$PACKAGED_EXTENSION" = "tar") || ("$PACKAGED_EXTENSION" = "ipk") ) ]]; then
        echo "Supported package extension is {tar/ipk}, $PACKAGED_EXTENSION is not supported"
        exit 0
    else
        #Appending App manager config file into existing package tar
        if [ "$PACKAGED_EXTENSION" = "tar" ]; then
            tar --append --file="${PACKAGED_FILE}" "${APPMGR_CONF}"
        fi
        if [ "$PACKAGED_EXTENSION" = "ipk" ]; then
            ar q "${PACKAGED_FILE}" -f "${APPMGR_CONF}"
        fi

        # placing the package file to local directory prior to signing
        cp "${PACKAGED_FILE}" ${localDir}
    fi

    # Signing the tar file using openssl
    openssl dgst -sha256 -sign "${SIGNING_KEY}" -out "${PACKAGED_NAME}.sig" "${PACKAGED_TAR}"

    if [ $? -ne 0 ]; then
        echo "Package ${PACKAGED_NAME}"
        echo "Signature Signing Failed"
        exit 0
    else
        echo "Package ${PACKAGED_NAME}"
        echo "Successfully Completed the package Signing"
    fi

    # Packaging all required component to create final tarball
    #finalTarFile="ThirdPartyAppSignedTarBall_${PACKAGED_NAME}-signed.tar"
    finalTarFile="$APP_NAME"-"$APP_VERSION"-"$RELEASE_NUM"."$ARCH_NAME".tar
    tar -cvf "${finalTarFile}" "${PACKAGED_NAME}.sig" "${PACKAGED_TAR}" "${CA_CERT}"

    if [ $? -ne 0 ]; then
        echo "Error in Signed tar file creation for package ${PACKAGED_NAME}" 
        exit 0
    else
        echo "Successfully created Final Tar ball $finalTarFile"
        # Cleanup tarball for signed package and app config file
        rm -rf "${PACKAGED_NAME}.sig" "${PACKAGED_TAR}"
    fi
done
# Removing Signing key & CA Certificate
rm -rf "${CA_CERT}" "${SIGNING_KEY}"
