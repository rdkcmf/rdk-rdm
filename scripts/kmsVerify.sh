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
if [ -f /etc/device.properties ];then
    . /etc/device.properties
fi

if [ -f /etc/rdmloggerUtils.sh ];then
    . /etc/rdm/loggerUtils.sh
else
    echo "[/etc/rdm/loggerUtils.sh], File Not Found"
fi

 
# Package Signature Verification  
HOME_PATH=$1
KEY_VALUE=$2
HASH_VALUE=$3
SIGN_VALUE=$4

if [ ! "$HASH_VALUE" ] || [ ! "$SIGN_VALUE" ] || [ ! "$KEY_VALUE" ];then
        log_msg "downloadAppVerification: Signing Parameter is empty"
        exit 2
fi

CONFIGPARAMGEN=/usr/bin/configparamgen
DOWNLOAD_APP_CODEBIG_KEY_FILE=/etc/rdm/tedjikmke.hlf
DOWNLOAD_APP_KMS_KEY_FILE=/etc/rdm/sgruwulgb.kes
DOWNLOAD_APP_INTERMEDIATE_KMS_KEY_FILE=$HOME_PATH/pqrstuz.file
DOWNLOAD_APP_INTERMEDIATE_KEY_FILE=$HOME_PATH/rstuvwz.file

if [ ! -x $CONFIGPARAMGEN ];then
        log_msg "Missing the Binary file for signing"
        exit 3
fi

if [ ! -f $DOWNLOAD_APP_CODEBIG_KMS_KEY_FILE ];then
        log_msg "Missing the Codebig Key File: $DOWNLOAD_APP_CODEBIG_KMS_KEY_FILE"
        exit 3
fi

# Decrypt the Key for Codebig
$CONFIGPARAMGEN jx $DOWNLOAD_APP_CODEBIG_KEY_FILE $DOWNLOAD_APP_INTERMEDIATE_KEY_FILE

# Decrypt the Key for KMS Server
$CONFIGPARAMGEN jx $DOWNLOAD_APP_KMS_KEY_FILE $DOWNLOAD_APP_INTERMEDIATE_KMS_KEY_FILE

user=`head -n1 $DOWNLOAD_APP_INTERMEDIATE_KMS_KEY_FILE`
pwd=`tail -n1 $DOWNLOAD_APP_INTERMEDIATE_KMS_KEY_FILE`

JSONSTR="{\"RSA_Verify\":{\"username\":\"$user\",\"password\":\"$pwd\",\"keyname\":\"$KEY_VALUE\",\"messagetext\":\"$HASH_VALUE\",\"signature\":\"$SIGN_VALUE\",\"transformation\":\"SHA256withRSA\"}}"

signVerifyUrl=`$CONFIGPARAMGEN 7`
if [ ! $signVerifyUrl ];then
     log_msg "downloadAppVerification: Signed URL is empty"
     exit 1
fi

serverUrl=`echo $signVerifyUrl | sed -e "s|&oauth_consumer_key.*||g"`
correctURL=`echo $serverUrl | cut -d "?" -f1 `
log_msg "URL: $correctURL"
authorizationHeader=`echo $signVerifyUrl | sed -e "s|&|\", |g" -e "s|=|=\"|g" -e "s|.*oauth_consumer_key|oauth_consumer_key|g"`
authorizationHeader="Authorization: OAuth $authorizationHeader\""
jsonHeader="Content-Type: application/json"

EnableOCSPStapling="/tmp/.EnableOCSPStapling"
EnableOCSP="/tmp/.EnableOCSPCA"
if [ -f $EnableOCSPStapling ] || [ -f $EnableOCSP ]; then
    CURL_CMD="curl -v --cert-status --url '$correctURL' -H '$authorizationHeader' -H '$jsonHeader' -w '%{http_code}\n' -o $HOME_PATH/output.txt -d '$JSONSTR'"
else
    CURL_CMD="curl -v --url '$correctURL' -H '$authorizationHeader' -H '$jsonHeader' -w '%{http_code}\n' -o $HOME_PATH/output.txt -d '$JSONSTR'"
fi
echo $CURL_CMD
eval $CURL_CMD > /dev/null
ret=$?
 
log_msg "downloadAppVerification: Curl Execution Status: $ret and CURL output"
cat $HOME_PATH/output.txt
log_msg "Completed"
responseMsg=`cat $HOME_PATH/output.txt | cut -d":" -f1 | sed 's/[{"}]//g'`
if [ "$responseMsg" = "RSA_Verify_Response" ];then
        log_msg "downloadAppVerification: Valid Response from KMS $responseMsg"
else
       log_msg "downloadAppVerification: Invalid Response Msg From KMS"
fi

status=`cat $HOME_PATH/output.txt | cut -d":" -f3 | sed 's/[{}]//g'`
if [ "$status" = "false" ];then
        log_msg "downloadAppVerification: Package Signing Verification FAILED" 
        if [ -d $HOME_PATH ];then
             log_msg "downloadAppVerification: Deleting the App since signature verification failed"
             rm -rf $HOME_PATH/*
             exit 2
        fi
else
        log_msg "downloadAppVerification: Package Signing Verification SUCCESS"
fi

exit 0
