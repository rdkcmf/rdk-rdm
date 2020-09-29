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

if [ -f /etc/include.properties ];then
    . /etc/include.properties
fi

if [ -f /etc/rdm/downloadUtils.sh ];then
    . /etc/rdm/downloadUtils.sh
else
    echo "File Not Found, /etc/rdm/downloadUtils.sh"
fi

RDM_SSR_LOCATION=/tmp/.rdm_ssr_location
RDM_DOWNLOAD_PATH=/tmp/rdm/
PEER_COMM_DAT="/etc/dropbear/elxrretyt.swr"
PEER_COMM_ID="/tmp/elxrretyt-$$.swr"
CONFIGPARAMGEN=/usr/bin/configparamgen
APPLN_HOME_PATH=/tmp/${DOWNLOAD_APP_MODULE}
APP_MOUNT_PATH=/media/apps
DIRECT_BLOCK_FILENAME="/tmp/.lastdirectfail_rdm"
DIRECT_BLOCK_TIME=86400
CB_BLOCK_FILENAME="/tmp/.lastcodebigfail_rdm"
CB_BLOCK_TIME=1800
FORCE_DIRECT_ONCE="/tmp/.forcedirectonce_rdm"
BB_TRIES=3

#Read the Download Mgr Url fro RFC
if [ "$DEVICE_TYPE" = "broadband" ]; then
    DEFAULT_URL=`dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.CDLDM.CDLModuleUrl | grep string | awk '{print $5}'`
else
    if [ -f /usr/bin/tr181 ];then
        DEFAULT_URL=`/usr/bin/tr181 -g Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.CDLDM.CDLModuleUrl 2>&1 > /dev/null`
    fi
fi

usage()
{
    log_msg "USAGE: $0 <APPLICATION NAME> <APPICATION HOME PATH> <DOWNLOAD VALIDATION METHOD> <PACKAGE EXTN (.ipk or .bin or .tar ) <PACKAGE NAME> >"
    log_msg "Mandatory Arguments: <APPLICATION NAME> <DOWNLOAD VALIDATION METHOD>"
    log_msg "Optional Arguments: <APPLICATION HOME PATH>, Default Value /tmp/<APPLICATION NAME>"
    log_msg "Optional Arguments: <PACKAGE NAME>, if not default to <APPLICATION NAME>.<PACKAGE EXTN>"
    log_msg "Optional Arguments: <PACKAGE EXTN>, if not default to <APPLICATION NAME>.ipk"
}

cleanup()
{
    if [ -f $DOWNLOAD_MGR_PIDFILE ];then
        rm -rf $DOWNLOAD_MGR_PIDFILE
    fi
}

# Input Arguments Validation
# Input Argument: Application Name (Mandatory Field)
if [ ! "$1" ];then
     log_msg "Application Name is Empty, Execute Once Again `basename $0` "
     usage
     exit 0
else
     DOWNLOAD_APP_MODULE="$1"
fi

# Input Parameter: Application Home Path
if [ ! "$2" ];then
      APPLN_HOME_PATH=/tmp/$DOWNLOAD_APP_MODULE
      RDM_DOWNLOAD_PATH=/tmp/rdm
else
      log_msg "using the custom HOME path:$2"
      APPLN_HOME_PATH=$2/$DOWNLOAD_APP_MODULE
      RDM_DOWNLOAD_PATH=$2/rdm
fi

DOWNLOAD_MGR_PIDFILE=/tmp/.dlApp${DOWNLOAD_APP_MODULE}.pid

# Upon exit, remove pid file
trap cleanup EXIT

# Ensure only one instance of script is running
if [ -f $DOWNLOAD_MGR_PIDFILE ];then
   pid=`cat $DOWNLOAD_MGR_PIDFILE`
   if [ -d /proc/$pid ];then
      log_msg "Another instance of this app $0 is already running..!"
      log_msg "Exiting without starting the $0..!"
      exit 0
   fi
else
   echo $$ > $DOWNLOAD_MGR_PIDFILE
fi

# Input Parameter: Authentication Method for Package Validation
if [ ! "$3" ];then
      log_msg "Application Download Not possible without Authentication"
      log_msg "Supported Authentications: KMS Signature Validation and OpenSSL Verifications"
      usage
      exit 1
else
      PKG_AUTHENTICATION=$3
fi

# Input Parameter: Package Extension
if [ ! $4 ];then
     PACKAGE_EXTN="ipk"
     log_msg "Using Default Package Extension $PACKAGE_EXTN"
else
     PACKAGE_EXTN=$4
     log_msg "Package Extension is $PACKAGE_EXTN"
fi

IsDirectBlocked()
{
    directret=0
    if [ -f $DIRECT_BLOCK_FILENAME ]; then
        modtime=$(($(date +%s) - $(date +%s -r $DIRECT_BLOCK_FILENAME)))
        remtime=$((($DIRECT_BLOCK_TIME/3600) - ($modtime/3600)))
        if [ "$modtime" -le "$DIRECT_BLOCK_TIME" ]; then
            log_msg "AppDownload:Last direct failed blocking is still valid for $remtime hrs, preventing direct"
            directret=1
        else
            log_msg "AppDownload:Last direct failed blocking has expired, removing $DIRECT_BLOCK_FILENAME, allowing direct"
            rm -f $DIRECT_BLOCK_FILENAME
        fi
    fi
    return $directret
}

IsCodeBigBlocked()
{
    codebigret=0
    if [ -f $CB_BLOCK_FILENAME ]; then
        modtime=$(($(date +%s) - $(date +%s -r $CB_BLOCK_FILENAME)))
        cbremtime=$((($CB_BLOCK_TIME/60) - ($modtime/60)))
        if [ "$modtime" -le "$CB_BLOCK_TIME" ]; then
            log_msg "AppDownload:Last Codebig failed blocking is still valid for $cbremtime mins, preventing Codebig"
            codebigret=1
        else
            log_msg "AppDownload:Last Codebig failed blocking has expired, removing $CB_BLOCK_FILENAME, allowing Codebig"
            rm -f $CB_BLOCK_FILENAME
        fi
    fi
    return $codebigret
}

# Get the configuration of codebig settings
get_Codebigconfig()
{

   if [ "$DEVICE_TYPE" = "broadband" ]; then
       UseCodebig=0
       conn_str="Direct"
   
       # If configparamgen not available, then only direct connection available and no fallback mechanism
       if [ -f $CONFIGPARAMGEN ]; then
          CodebigAvailable=1
       fi
       if [ "$CodebigAvailable" -eq "1" ]; then
          CodeBigEnable=`dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.CodeBigFirst.Enable | grep true 2>/dev/null`
       fi

       if [ -f $FORCE_DIRECT_ONCE ];then
           rm -f $FORCE_DIRECT_ONCE
           log_msg "RDM Download: Last Codebig attempt failed, forcing direct once"
       elif [ "$CodebigAvailable" -eq "1" ] && [ "x$CodeBigEnable" != "x" ];then 
           UseCodebig=1
           conn_str="Codebig" 
       fi

       if [ "$CodebigAvailable" -eq "1" ]; then
           log_msg "RDM Download:: Using $conn_str connection as the Primary"
       else
           log_msg "RDM Download: Only $conn_str connection is available"
       fi
   fi
}

downloadApp_getVersionPrefix()
{
   buildType=`downloadApp_getBuildType`
   version=$(downloadApp_getFWVersion)
   versionPrefix=`echo $version | sed 's/_'$buildType'//g'`
   echo $versionPrefix
}

# Extract the App file name from /version.txt
downloadApp_getFWVersion()
{
    versionTag1=$FW_VERSION_TAG1
    versionTag2=$FW_VERSION_TAG2
    verStr=`cat /version.txt | grep ^imagename:$versionTag1`
    if [ $? -eq 0 ];then
         version=`echo $verStr | cut -d ":" -f2`
    else
         version=`cat /version.txt | grep ^imagename:$versionTag2 | cut -d ":" -f2`
    fi
    echo $version
}

# identifies whether it is a VBN or PROD build
downloadApp_getBuildType()
{
    str=$(downloadApp_getFWVersion)
    echo $str | grep -q 'VBN'
    if [[ $? -eq 0 ]] ; then
          echo 'VBN'
          exit 0
    fi
    echo $str | grep -q 'PROD'
    if [[ $? -eq 0 ]] ; then
          echo 'PROD'
          exit 0
    fi
    echo $str | grep -q 'QA'
    if [[ $? -eq 0 ]] ; then
           echo 'QA'
           exit 0
    fi
    echo $str | grep -q 'DEV'
    if [[ $? -eq 0 ]] ; then
          echo 'DEV'
          exit 0
    fi
    echo $str | grep -q 'VBN_BCI'
    if [[ $? -eq 0 ]] ; then
          echo 'VBN'
          exit 0
    fi
    echo $str | grep -q 'PROD_BCI'
    if [[ $? -eq 0 ]] ; then
          echo 'PROD'
          exit 0
    fi
    echo $str | grep -q 'DEV_BCI'
    if [[ $? -eq 0 ]] ; then
          echo 'DEV'
          exit 0
    fi
}

# Generating the Download Package Name from Version.txt
if [ ! $5 ];then
     log_msg "Package Name from meta data: /etc/rdm/rdm-manifest.json"
     # Retrive the Appln metadata
     DOWNLOAD_PKG_NAME=`/usr/bin/jsonquery -f /etc/rdm/rdm-manifest.json  --path=//packages/$DOWNLOAD_APP_MODULE/pkg_name`
     log_msg "Meta-data: package name: $DOWNLOAD_PKG_NAME"
else
     DOWNLOAD_PKG_NAME=$5
     applicationSuffix="${DOWNLOAD_PKG_NAME}-signed"
     DOWNLOAD_PKG_NAME="${applicationSuffix}.tar"
     log_msg "Using the custom Package name: $DOWNLOAD_PKG_NAME"
fi

log_msg "DOWNLOAD_APP_MODULE = $DOWNLOAD_APP_MODULE"
log_msg "PKG_AUTHENTICATION = $PKG_AUTHENTICATION"
log_msg "PKG_EXTN = $PKG_EXTN"

DOWNLOAD_APP_NAME=`/usr/bin/jsonquery -f /etc/rdm/rdm-manifest.json  --path=//packages/$DOWNLOAD_APP_MODULE/app_name`
log_msg "Meta-data: package name: $DOWNLOAD_APP_NAME"
DOWNLOAD_APP_SIZE=`/usr/bin/jsonquery -f /etc/rdm/rdm-manifest.json  --path=//packages/$DOWNLOAD_APP_MODULE/app_size`
log_msg "Meta-data: package size: $DOWNLOAD_APP_SIZE"

if [ ! "$DOWNLOAD_APP_NAME" ];then
    DOWNLOAD_APP_NAME=$DOWNLOAD_APP_MODULE
fi

# Setup the workspace
if [ ! "$2" ];then
    APPLN_HOME_PATH=/tmp/${DOWNLOAD_APP_NAME}
else
    APPLN_HOME_PATH=$2/${DOWNLOAD_APP_NAME}
fi

DOWNLOAD_LOCATION=$RDM_DOWNLOAD_PATH/downloads/$DOWNLOAD_APP_NAME
if [ ! -d $DOWNLOAD_LOCATION ];then
       mkdir -p $DOWNLOAD_LOCATION
fi

log_msg "APPLN_HOME_PATH = $APPLN_HOME_PATH"
## Retry Interval in seconds
DOWNLOAD_APP_DEFAULT_RETRY_DELAY=10
DOWNLOAD_APP_DIRECT_RETRY_DELAY=30
## Maximum Retry Count
DOWNLOAD_APP_RETRY_COUNT=2
DOWNLOAD_APP_CB_RETRY_COUNT=1
DOWNLOAD_APP_PROGRESS_FLAG="${APPLN_HOME_PATH}/.dlAppInProgress"
## File to save http code
DOWNLOAD_APP_HTTP_OUTPUT="$APPLN_HOME_PATH/download_httpoutput"
## File to save curl/wget response
DOWNLOAD_APP_HTTP_RESPONSE="$APPLN_HOME_PATH/download_http_response"
# TODO Will Update after RFC changes
DOWNLOAD_APP_SSR_LOCATION=/nvram/.download_ssr_location

CURL_TIMEOUT=10
CURL_OPTION="-w"
TLS="--tlsv1.2"
CURL_TLS_TIMEOUT=30
downloadStatus=1

HTTP_CODE="$APPLN_HOME_PATH/httpcode"
TLSRet=""
http_code=1

EnableOCSPStapling="/tmp/.EnableOCSPStapling"
EnableOCSP="/tmp/.EnableOCSPCA"

# Initialize codebig flag value
UseCodebig=0
log_msg "Checking Codebig flag..." 
IsDirectBlocked
UseCodebig=$?

getCodebigUrl()
{
    dnlUrl=$1

    if [ -f $CONFIGPARAMGEN ];then
       domainName=`echo $dnlUrl | awk -F/ '{print $3}'`
       imageHTTPURL=`echo $dnlUrl | sed -e "s|.*$domainName||g"`
       request_type=1

       # Use DAC15 codebig Endpoint url for Non-Prod builds
       if [ "$domainName" == "dac15cdlserver.ae.ccp.xcal.tv" ]; then
           request_type=14
       fi

       SIGN_CMD="$CONFIGPARAMGEN $request_type \"$imageHTTPURL\""
       eval $SIGN_CMD > /tmp/.signedRequest
       cbSignedimageHTTPURL=`cat /tmp/.signedRequest`
       rm -f /tmp/.signedRequest
       
       # Work around for resolving SSR url encoded location issue
       # Correcting stb_cdl location in CB signed request
       cbSignedimageHTTPURL=`echo $cbSignedimageHTTPURL | sed 's|stb_cdl%2F|stb_cdl/|g'`
       serverUrl=`echo $cbSignedimageHTTPURL | sed -e "s|?oauth_consumer_key.*||g"`
       authorizationHeader=`echo $cbSignedimageHTTPURL | sed -e "s|&|\", |g" -e "s|=|=\"|g" -e "s|.*oauth_consumer_key|oauth_consumer_key|g"`
       authorizationHeader="Authorization: OAuth realm=\"\", $authorizationHeader\""
    else
       log_msg "getCodebigUrl: $CONFIGPARAMGEN file not found"
       exit 2
    fi
}

generateDownloadUrl()
{
    file=$1
    url=$2
    flag=$3

    if [ $flag -eq 1 ]; then
        getCodebigUrl $url
        if [ -f $EnableOCSPStapling ] || [ -f $EnableOCSP ]; then
            CURL_CMD="curl $TLS $IF_OPTION -fgL --cert-status --connect-timeout $CURL_TLS_TIMEOUT  -H '$authorizationHeader' -w '%{http_code}\n' -o \"$DOWNLOAD_LOCATION/$file\" '$serverUrl' > $HTTP_CODE"
        else
            CURL_CMD="curl $TLS $IF_OPTION -fgL --connect-timeout $CURL_TLS_TIMEOUT  -H '$authorizationHeader' -w '%{http_code}\n' -o \"$DOWNLOAD_LOCATION/$file\" '$serverUrl' > $HTTP_CODE"
        fi
    else
        if [ -f $EnableOCSPStapling ] || [ -f $EnableOCSP ]; then
            CURL_CMD="curl $TLS $IF_OPTION -fgL $CURL_OPTION '%{http_code}\n' -o \"$DOWNLOAD_LOCATION/$file\" \"$url\" --cert-status --connect-timeout $CURL_TLS_TIMEOUT -m 600"
        else
            CURL_CMD="curl $TLS $IF_OPTION -fgL $CURL_OPTION '%{http_code}\n' -o \"$DOWNLOAD_LOCATION/$file\" \"$url\" --connect-timeout $CURL_TLS_TIMEOUT -m 600"
        fi
    fi
}

sendDownloadRequest()
{
    status=1
    counter=0
    curl_request=$1

    #Sensitive info like Authorization signature should not print
    curl_cmd=`echo $curl_request | sed -e "s|-H.*-w|-H 'AuthorizationHeader' -w|g"`
    while [ $status -ne 0 ]
    do
        log_msg "sendDownloadRequest: CURL_CMD: ${curl_cmd}"
        eval $curl_request > $HTTP_CODE
        TLSRet=$?
        http_code=$(awk -F\" '{print $1}' $HTTP_CODE)
        if [ $TLSRet -ne 0 ];then
            log_msg "sendDownloadRequest: Package download http_code : $http_code   ret : $TLSRet"
            if [ -f $DOWNLOAD_LOCATION/$downloadFile ];then
                  log_msg "sendDownloadRequest: Curl partial Download, Failed download for $downloadUrl"
                  rm $DOWNLOAD_LOCATION/$downloadFile
            else
                  log_msg "sendDownloadRequest: Curl Download Failed for $downloadUrl"
            fi
            counter=`expr $counter + 1`
            log_msg "sendDownloadRequest: Retry: $counter"
            if [ "$counter" -ge "$BB_TRIES" ];then
                log_msg "sendDownloadRequest: $BB_TRIES attempts failed, exiting from retry..!"
                status=0
                break
            else
 		# Needs to be less sleep, Since it causes holdoff expiry of MeshAgent.service
                if [ "$UseCodebig" -eq "0" ] || [ "$counter" -eq "1" ]; then
                    sleep_time=10
                else
                    sleep_time=30
                fi                    
                sleep $sleep_time
            fi
        else
            log_msg "sendDownloadRequest: Package download http_code : $http_code   ret : $TLSRet"
            if [ "$http_code" = "200" ]; then
                  downloadStatus=0
                  status=0
                  log_msg "sendDownloadRequest: Curl Download Success for $downloadUrl"
            fi
        fi
    done
}

sendAppDownloadRequest()
{
    curl_request=$1

    #Sensitive info like Authorization signature should not print
    curl_cmd=`echo $curl_request | sed -e "s|-H.*-w|-H 'AuthorizationHeader' -w|g"`
    log_msg "sendAppDownloadRequest: CURL_CMD: ${curl_cmd}"

    eval $curl_request > $HTTP_CODE
    TLSRet=$?
    http_code=$(awk -F\" '{print $1}' $HTTP_CODE)
    if [ $TLSRet -ne 0 ];then
        log_msg "sendAppDownloadRequest: Package download http_code : $http_code   ret : $TLSRet"
        if [ -f $DOWNLOAD_LOCATION/$downloadFile ];then
              log_msg "sendAppDownloadRequest: Curl partial Download, Failed download for $downloadUrl"
              rm $DOWNLOAD_LOCATION/$downloadFile
        else
              log_msg "sendAppDownloadRequest: Curl Download Failed for $downloadUrl"
        fi
    else
        log_msg "sendAppDownloadRequest: Package download http_code : $http_code   ret : $TLSRet"
        if [ "$http_code" = "200" ]; then
              downloadStatus=0
              log_msg "sendAppDownloadRequest: Curl Download Success for $downloadUrl"
        fi
    fi
}

applicationDownload()
{
    downloadUrl=$1
    downloadStatus=1
    downloadFile=`basename $downloadUrl`
    ret=1
    retries=0
    cbretries=0

    log_msg "applicationDownload: DOWNLOADING: tar file $downloadUrl"
    TLS="--tlsv1.2"
    IF_OPTION=""
    if [ "$DEVICE_TYPE" = "broadband" ] && [ "$MULTI_CORE" = "yes" ];then
          core_output=`get_core_value`
          if [ "$core_output" = "ARM" ];then 
                IF_OPTION="--interface $ARM_INTERFACE"
          fi
    fi
    # Clean up to clear any previous partial files before downloading new package
    rm -rf $DOWNLOAD_LOCATION/*
    mkdir -p $DOWNLOAD_LOCATION

    if [ "$DEVICE_TYPE" = "broadband" ]; then
        get_Codebigconfig
        if [ "$UseCodebig" -eq "1" ]; then
            IsCodeBigBlocked
            if [ $? -eq 1 ];then
                return
            fi
        fi

        generateDownloadUrl $downloadFile $downloadUrl $UseCodebig
        sendDownloadRequest "${CURL_CMD}"
        ret=$TLSRet
        http_code=$(awk -F\" '{print $1}' $HTTP_CODE)
        if [ $ret -ne 0 ] && [ "$http_code" == "000" ]; then
            if [ "$UseCodebig" -eq "1" ]; then
                [ -f $CB_BLOCK_FILENAME ]; touch $CB_BLOCK_FILENAME
                touch $FORCE_DIRECT_ONCE
            fi
        fi
    else
        if [ $UseCodebig -eq 1 ]; then
            log_msg "applicationDownload: Codebig is enabled UseCodebig=$UseCodebig" 
            if [ "$DEVICE_TYPE" = "mediaclient" ]; then
                # Use Codebig connection connection on XI platforms
                IsCodeBigBlocked
                skipcodebig=$?
                if [ $skipcodebig -eq 0 ]; then
                    while [ $cbretries -le $DOWNLOAD_APP_CB_RETRY_COUNT ]
                    do
                        if [ $retries -eq 1 ];then
                            sleep $DOWNLOAD_APP_DEFAULT_RETRY_DELAY
                        fi
                        log_msg "applicationDownload: Attempting Codebig App download"
                        generateDownloadUrl $downloadFile $downloadUrl $UseCodebig
                        sendAppDownloadRequest "$CURL_CMD"
                        ret=$TLSRet
                        http_code=$(awk -F\" '{print $1}' $HTTP_CODE)
                        if [ "$http_code" = "200" ]; then
                            log_msg "applicationDownload: Codebig App download success, return:$ret, httpcode:$http_code"
                            IsDirectBlocked
                            skipDirect=$?
                            if [ $skipDirect -eq 0 ]; then
                                UseCodebig=0
                            fi
                            break
                        fi
                        log_msg "applicationDownload: Codebig App download failed, retry:$cbretries, return:$ret, httpcode:$http_code"
                        cbretries=`expr $cbretries + 1`
                    done
                fi
                if [ $ret -ne 0 ] && [ "$http_code" != "200" ]; then
                    log_msg "applicationDownload: Codebig App download failed with return:$ret httpcode:$http_code after $DOWNLOAD_APP_CB_RETRY_COUNT attempts"
                    IsCodeBigBlocked
                    skipcodebig=$?
                    if [ $skipcodebig -eq 0 ]; then
                        log_msg "applicationDownload: Earlier Codebig block released"
                        touch $CB_BLOCK_FILENAME
                        log_msg "applicationDownload: No App download attempts allowed, Again Blocking Codebig for 30 mins"    
                    fi
                    exit 4
                fi
            else
                log_msg "applicationDownload: Codebig App download is not supported"
                exit 1
            fi
        else
            log_msg "applicationDownload: Codebig is disabled: UseCodebig=$UseCodebig"
            IsDirectBlocked
            skipdirect=$?
            if [ $skipdirect -eq 0 ]; then
                while [ $retries -le $DOWNLOAD_APP_RETRY_COUNT ]
                do
                    if [ $retries -eq 1 ];then
                        sleep $DOWNLOAD_APP_DEFAULT_RETRY_DELAY
                    elif [ $retries -eq 2 ];then
                        sleep $DOWNLOAD_APP_DIRECT_RETRY_DELAY
                    fi
                    log_msg "applicationDownload: Attempting Direct App download"
                    generateDownloadUrl $downloadFile $downloadUrl $UseCodebig
                    sendAppDownloadRequest "$CURL_CMD"
                    ret=$TLSRet
                    http_code=$(awk -F\" '{print $1}' $HTTP_CODE)
                    if [ "$http_code" == "200" ]; then
                        log_msg "applicationDownload: Direct App download success, return:$ret, httpcode:$http_code"
                        break
                    fi
                    log_msg "applicationDownload: Direct App download failed, retry:$retries, return:$ret, httpcode:$http_code"
                    retries=`expr $retries + 1`
                done
            fi
            # Retry image download attempts via CodeBig
            if [ $ret -ne 0 ] && [ "$http_code" == "000" ]; then
                if [ "$DEVICE_TYPE" = "mediaclient" ];then
                    log_msg "applicationDownload: Direct App download failed with return:$ret, httpcode:$http_code , Retrying to SSR via CodeBig server"
                    UseCodebig=1
                    IsCodeBigBlocked
                    skipcodebig=$?
                    if [ $skipcodebig -eq 0 ]; then
                        while [ $cbretries -le $DOWNLOAD_APP_CB_RETRY_COUNT ]
                        do
                            if [ $retries -eq 1 ];then
                                sleep $DOWNLOAD_APP_DEFAULT_RETRY_DELAY
                            fi
                            log_msg "applicationDownload: Attempting Codebig App download"
                            generateDownloadUrl $downloadFile $downloadUrl $UseCodebig
                            sendAppDownloadRequest "$CURL_CMD"
                            ret=$TLSRet
                            http_code=$(awk -F\" '{print $1}' $HTTP_CODE)
                            if [ "$http_code" = "200" ]; then
                                log_msg "applicationDownload: Codebig App download success, return:$ret, httpcode:$http_code"
                                UseCodebig=1
                                if [ ! -f $DIRECT_BLOCK_FILENAME ]; then
                                    touch $DIRECT_BLOCK_FILENAME
                                    log_msg "applicationDownload: Use Codebig connection and Block Direct for 24 hrs"
                                fi
                                break
                            fi
                            log_msg "applicationDownload: Codebig App download failed, retry:$cbretries, return:$ret, httpcode:$http_code"
                            cbretries=`expr $cbretries + 1`
                        done
                    fi
                    if [ $ret -ne 0 ] && [ "$http_code" != "200" ]; then
                        log_msg "applicationDownload: Codebig App download failed with return:$ret, httpcode:$http_code after $DOWNLOAD_APP_CB_RETRY_COUNT attempts"
                        UseCodebig=0
                        if [ ! -f $CB_BLOCK_FILENAME ]; then
                            touch $CB_BLOCK_FILENAME
                            log_msg "applicationDownload: No App download attempts allowed, Blocking Codebig for 30 mins"
                            exit 4
                        fi
                    fi
                else
                    log_msg "applicationDownload: Direct App download failed with return:$ret, httpcode:$http_code after $DOWNLOAD_APP_RETRY_COUNT attempts"
                    exit 4
                fi
            fi
        fi
    fi
              
    if [ -f $DOWNLOAD_LOCATION/$downloadFile ];then
         log_msg "Size Info After Download: `ls -lh $DOWNLOAD_LOCATION/$downloadFile`"
    fi
}

applicationExtraction()
{
    downloadUrl=$1
    downloadFile=`basename $downloadUrl`
    if [ ! -f $DOWNLOAD_LOCATION/$downloadFile ];then
           downloadStatus=1
           log_msg  "applicationExtraction: File Not Found for Extraction: $DOWNLOAD_LOCATION/$downloadFile"
           exit 2
    fi
    tar -xvf $DOWNLOAD_LOCATION/$downloadFile -C $DOWNLOAD_LOCATION/
    if [ $? -ne 0 ];then
            log_msg "applicationExtraction: $downloadFile: tar Extraction Failed..! Clearing $DOWNLOAD_LOCATION"
            rm -rf $DOWNLOAD_LOCATION/*
            exit 3
    fi
}

# setup the workspace and initial cleanup
if [ ! -d $APPLN_HOME_PATH ];then
     mkdir -p $APPLN_HOME_PATH
fi

# Setup the Download Path
if [ ! -d $DOWNLOAD_LOCATION ]; then
      mkdir -p $DOWNLOAD_LOCATION
fi

#Setup the URL Location for RDM packages
ARM_SCP_IP_ADRESS=$ARM_INTERFACE_IP
if [ ! $ARM_SCP_IP_ADRESS ];then
      log_msg "Either Missing ARM SCP IP ADDRESS , Please Check /etc/device.properties "
      log_msg "             Or               "
      log_msg "Platform with Single Processor "
      log_msg "             Or               "
      log_msg "Processes are running on the ATOM side "
fi

if [ -f /tmp/.xconfssrdownloadurl ];then
           cp /tmp/.xconfssrdownloadurl /tmp/.rdm_ssr_location
           cp /tmp/.rdm_ssr_location /nvram/.rdm_ssr_location
else
           checkstatus=1
           counter=0
           log_msg "DOWNLOADING: /tmp/.xconfssrdownloadurl from ARM Side"
           $CONFIGPARAMGEN jx $PEER_COMM_DAT $PEER_COMM_ID
           while [ $checkstatus -eq 1 ]
           do
                scp -i $PEER_COMM_ID root@$ARM_SCP_IP_ADRESS:/tmp/.xconfssrdownloadurl $RDM_SSR_LOCATION
                checkstatus=$?
                if [ $checkstatus -eq 0 ] && [ -f $RDM_SSR_LOCATION ];then
                     cp $RDM_SSR_LOCATION /nvram/.rdm_ssr_location
                else
                     log_msg "scp failed for /tmp/.xconfssrdownloadurl, Please Check Firmware Upgrade Status at ARM side"
                     sleep 5
                fi
                counter=`expr $counter + 1`
                if [ $counter -eq 3 ];then
                     checkstatus=0
                     if [ -f /nvram/.rdm_ssr_location ];then
                          cp /nvram/.rdm_ssr_location /tmp/.rdm_ssr_location
                     fi
                fi
          done
          rm -f $PEER_COMM_ID
fi

if [ ! -f $RDM_SSR_LOCATION ];then
        log_msg "$RDM_SSR_LOCATION SSR URL Location Input File is not there"
        exit 1
elif [ ! -s $RDM_SSR_LOCATION ];then
        log_msg "Download URL is empty Inside $RDM_SSR_LOCATION"
        exit 1
else
        url=`cat $RDM_SSR_LOCATION`

        # Verify the Xconf response in /tmp/.xconfssrdownloadurl
        if [ "$url" == "404" ]; then     
            log_msg "Received 404 error from Xconf Server, checking RFC for RDM Default url"
            if  [  ! -z "$DEFAULT_URL" ] && [ "$DEFAULT_URL" == " " ]; then
                log_msg "RFC Param Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.CDLDM.CDLModuleUrl is not set"
                exit 1
            else
                #Use default url from RFC param
                log_msg "Using RDM Default url $DEFAULT_URL to download from the Xconf Server"
                url=$DEFAULT_URL
            fi
        fi
        # Enforce HTTPs download for Downloadable modules
        log_msg "Replacing http with https in curl download request"
        url=`echo $url | sed "s/http:/https:/g"` 

        log_msg "RDM App Download URL Location is $url"
fi

# Download the File Package  if not already downloaded
if [ ! -f $DOWNLOAD_LOCATION/${DOWNLOAD_PKG_NAME} ]; then
    log_msg "Downloading The Package $url/${DOWNLOAD_PKG_NAME}"
    applicationDownload $url/${DOWNLOAD_PKG_NAME}
else
    log_msg "File package $DOWNLOAD_LOCATION/${DOWNLOAD_PKG_NAME} already available"
fi

if [ "$DOWNLOAD_APP_SIZE" ];then
     sizeVal=$DOWNLOAD_APP_SIZE
     scale=`echo "${sizeVal#"${sizeVal%?}"}"`
     value=`echo ${sizeVal%?}`

     floatNum="${value//[^.]}"
     if [ $floatNum ];then
          factor=1024
          case $scale in
            "G"|"g")
               log_msg "App Size is in GigaBytes"
               t=$(echo $factor $value | awk '{printf "%4.3f\n",$1*$2}')
               tx=`echo $t | cut -d '.' -f1`
               t=`expr $tx + 1`
               FINAL_DOWNLOAD_APP_SIZE=${t}M
               log_msg "App Size converted from $DOWNLOAD_APP_SIZE to $FINAL_DOWNLOAD_APP_SIZE"
               ;;
            "M"|"m")
               log_msg "App Size is in MegaBytes"
               t=$(echo $factor $value | awk '{printf "%4.3f\n",$1*$2}')
               tx=`echo $t | cut -d '.' -f1`
               t=`expr $tx + 1`
               FINAL_DOWNLOAD_APP_SIZE=${t}K
               log_msg "App Size converted from $DOWNLOAD_APP_SIZE to $FINAL_DOWNLOAD_APP_SIZE"
               ;;
            "K"|"k")
               log_msg "App Size is in KiloBytes"
               t=$(echo $factor $value | awk '{printf "%4.3f\n",$1*$2}')
               tx=`echo $t | cut -d '.' -f1`
               t=`expr $tx + 1`
               FINAL_DOWNLOAD_APP_SIZE=${t}B
               log_msg "App Size converted from $DOWNLOAD_APP_SIZE to $FINAL_DOWNLOAD_APP_SIZE"
               ;;
            "*")
               log_msg "Wrong Measurement Unit for App Size (nB/nK/nM/nG)"
               exit
               ;; 
         esac
     else
         FINAL_DOWNLOAD_APP_SIZE=$value$scale
         log_msg "App Size is $FINAL_DOWNLOAD_APP_SIZE"
     fi
     if [ "$APPLN_HOME_PATH" != "$APP_MOUNT_PATH/${DOWNLOAD_APP_MODULE}" ]; then
         if [ -d $APPLN_HOME_PATH ];then rm -rf $APPLN_HOME_PATH/* ; fi
         mountFlag=`mount | grep $APPLN_HOME_PATH`
         if [ "$mountFlag" ];then umount $APPLN_HOME_PATH ; fi
         mount -t tmpfs -o size=$FINAL_DOWNLOAD_APP_SIZE -o mode=544 tmpfs $APPLN_HOME_PATH
     fi
fi 

# Extract the Package
package_signatureFile=`ls $DOWNLOAD_LOCATION/*-pkg.sig| xargs basename`
package_tarFile=`ls $DOWNLOAD_LOCATION/*-pkg.tar| xargs basename`
pkg_extracted=false
# Keeping backup of signature and tarball on secondary storage to avoid top level package extraction on every reboot
# As extraction could account for the SD card write cycle on every reboot.
if ! [[  -f $DOWNLOAD_LOCATION/$package_signatureFile && -f $DOWNLOAD_LOCATION/$package_tarFile ]]; then
    log_msg "Extracting The Package $url/${DOWNLOAD_PKG_NAME}"
    applicationExtraction $url/${DOWNLOAD_PKG_NAME}
else
    pkg_extracted=true
fi

package_tarFile=`ls $DOWNLOAD_LOCATION/*-pkg.tar| xargs basename`
log_msg "Intermediate PKG File: $package_tarFile"
if [ $package_tarFile ] && [ -f $DOWNLOAD_LOCATION/$package_tarFile ];then
      ls -l $DOWNLOAD_LOCATION/$package_tarFile
      hashVal=`sha256sum $DOWNLOAD_LOCATION/$package_tarFile | cut -d " " -f1`
      if [ "x$pkg_extracted" != "xtrue" ]; then
          tar -xvf $DOWNLOAD_LOCATION/$package_tarFile -C $DOWNLOAD_LOCATION/
      fi
fi

package_signatureFile=`ls $DOWNLOAD_LOCATION/*-pkg.sig| xargs basename`
if [ $package_signatureFile ];then
       if [ -f $DOWNLOAD_LOCATION/$package_signatureFile ];then
            signVal=`cat $DOWNLOAD_LOCATION/$package_signatureFile`
       else
           log_msg "$DOWNLOAD_LOCATION/$package_signatureFile file not found"
       fi
fi

package_keyFile=`ls $DOWNLOAD_LOCATION/*nam.txt| xargs basename`
if [ $package_keyFile ];then
       if [ -f $DOWNLOAD_LOCATION/$package_keyFile ];then
            keyVal=`head -n1  $DOWNLOAD_LOCATION/$package_keyFile`
       else
           log_msg "$DOWNLOAD_LOCATION/$package_keyFile file not found"
       fi
fi

if [ -f ${APPLN_HOME_PATH}/${DOWNLOAD_APP_MODULE}_cpemanifest ];then
    #Individual component signing enabled and package already extracted
    log_msg "Package already extracted"
else
    log_msg "Extract the package" 
    CURRENT_PATH=`pwd` 
    cd $DOWNLOAD_LOCATION

    if [ -f $DOWNLOAD_LOCATION/packages.list ];then
        while read -r finalPackage
        do
          loop=0
          extension="${finalPackage##*.}"
          log_msg "Extracting the Package: ${finalPackage} ${extension}"
          while [ $loop -lt 2 ]
          do
             loop=`expr $loop + 1`
             case "${extension}" in
             ipk )
                log_msg "Size of ipk [$finalPackage]: `ls -lh $finalPackage`"
                ar -x $finalPackage
                if [ $? -ne 0 ];then
                     log_msg "IPK Extraction of $finalPackage Failed.."
                else    
                     umask 544
                     #default compression method in opkg is gz for daisy/morty and xz for dunfell
                     data_file=`ls data.tar.* | tail -n1`
                     log_msg "Size of data [$data_file]: `ls -lh $data_file`"
                     tar -xvf $data_file -C $APPLN_HOME_PATH/
                     if [ $? -ne 0 ];then
                          log_msg "tar Extraction Failed for $data_file"
                     else
                          loop=2
                     fi
                fi 
                if [ "$finalPackage" == "${DOWNLOAD_APP_MODULE}_container.ipk" ];then
                   log_msg "LXC Container IPK detected..."
                   log_msg "LXC Container IPK post download processing..."
                   DWL_DIRS=$(ls -l $APPLN_HOME_PATH | grep ^d | tr -s " " | cut -d " " -f 9 | grep -v 'rootfs\|conf\|launcher')
                   DWL_FILES=$(ls -l $APPLN_HOME_PATH | grep ^- | tr -s " " | cut -d " " -f 9 | grep -v $DOWNLOAD_APP_MODULE'_cpemanifest')
                   if [ -f $APPLN_HOME_PATH/conf/lxc.conf ];then

                       ROOTFS_PATH="$(echo $APPLN_HOME_PATH/rootfs | sed 's/\//\\\//g')"
                       sed -i 's/lxc.rootfs = .*/lxc.rootfs = '"$ROOTFS_PATH"'/' $APPLN_HOME_PATH/conf/lxc.conf
                       chown $DOWNLOAD_APP_MODULE:$DOWNLOAD_APP_MODULE $APPLN_HOME_PATH/
                   fi

                   if [ -f $APPLN_HOME_PATH/launcher/${DOWNLOAD_APP_MODULE}.sh ];then
                       CONF_PATH="$(echo $APPLN_HOME_PATH/conf/lxc.conf | sed 's/\//\\\//g')"
                       sed -i 's/\/container\/'"$DOWNLOAD_APP_MODULE"'\/conf\/lxc.conf/'"$CONF_PATH"'/g' $APPLN_HOME_PATH/launcher/${DOWNLOAD_APP_MODULE}.sh

                       if [ -f $DOWNLOAD_LOCATION/executables.txt ]; then
                           EXECS=`cat ${DOWNLOAD_LOCATION}/executables.txt`
                           for EXE in $EXECS; do
                               EXE_LOC="$(echo $EXE | sed 's/\//\\\//g')"
                               REPLACE_EXE_LOC="$(echo $APPLN_HOME_PATH$EXE | sed 's/\//\\\//g')"
                               sed -i 's/'"$EXE_LOC"'/'"$REPLACE_EXE_LOC"'/g' $APPLN_HOME_PATH/launcher/${DOWNLOAD_APP_MODULE}.sh
                           done
                       fi
                   fi
                fi

                rm -rf $DOWNLOAD_LOCATION/debian-binary
                #default compression method in opkg is gz for daisy/morty and xz for dunfell
                rm -rf $DOWNLOAD_LOCATION/control.tar.*         
                rm -rf $DOWNLOAD_LOCATION/data.tar.*

             ;;
             tar )
               log_msg "Size of data [$finalPackage]: `ls -lh $finalPackage`"
               tar -xvf $finalPackage -C $APPLN_HOME_PATH/
               if [ $? -ne 0 ];then
                     log_msg "tar Extraction Failed for $finalPackage"
               else
                     loop=2
               fi
             ;;
             *)
              log_msg "Unknown Package Extension"
              break
             ;;
             esac
          done

          if [ -f ./${finalPackage} ];then
               log_msg "Removing $finalPackage after Extraction"
               rm -rf ./$finalPackage
          fi
        done <$DOWNLOAD_LOCATION/packages.list
    else
        log_msg "Not Found the Packages List file"
        rm -rf $DOWNLOAD_LOCATION/*
        exit 3
    fi
#Modify permission only for non-container packages via rdm,This is to retain the permissions for container made in build time.
    if [ ! -f $DOWNLOAD_LOCATION/executables.txt ]; then
        chmod -R 544 $APPLN_HOME_PATH/
    fi

    log_msg "Download and Extraction Completed"
    cd $CURRENT_PATH
fi

# Signature Validation
if [ "$PKG_AUTHENTICATION" = "kms" ];then
     log_msg "KMS Validation on the Package"
     #kmsVerification $keyVal $hashVal $signVal
     sh /etc/rdm/kmsVerify.sh ${DOWNLOAD_LOCATION} $keyVal $hashVal $signVal
elif [ "$PKG_AUTHENTICATION" = "openssl" ];then
     log_msg "openSSL Validation on the Package"
     if [ "x$pkg_extracted" != "xtrue" ]; then
        # Since KMS is adding 6 Bytes of Header, need to remove this before validation
        # KMS Header Removal from the Signature
         log_msg "Removing the KMS Prefix Header"
         dd if="$DOWNLOAD_LOCATION/$package_signatureFile" of="$DOWNLOAD_LOCATION/$package_signatureFile.truncated" bs=6 skip=1 && mv "$DOWNLOAD_LOCATION/$package_signatureFile.truncated" "$DOWNLOAD_LOCATION/$package_signatureFile"
     fi

     sh /etc/rdm/opensslVerifier.sh ${DOWNLOAD_LOCATION}/ $package_tarFile $package_signatureFile "kms"
else
     log_msg "Application Download Not possible without Authentication"
     log_msg "Supported Authentications: KMS Signature Validation and OpenSSL Verifications"
fi

if [ $? -ne 0 ];then
     log_msg "signature validation failed"
     # Clear all files as partial extraction may happen due to corrupted tar file 
     rm -rf $DOWNLOAD_LOCATION/*
     if [ -d $APPLN_HOME_PATH ];then rm -rf $APPLN_HOME_PATH/* ; fi
     exit 3
fi

log_msg "$DOWNLOAD_LOCATION// CleanUp"
if [ "$APPLN_HOME_PATH" != "$APP_MOUNT_PATH/${DOWNLOAD_APP_MODULE}" ]; then
    rm -rf $DOWNLOAD_LOCATION/$downloadFile
fi
rm -rf $DOWNLOAD_LOCATION/*.ipk
for script in ${APPLN_HOME_PATH}/etc/rdm/post-services/*.sh; do
    if [ -f $script ]; then
        [ -r $script ] && sh $script &> /dev/null
        log_msg "RDM Post script Execution $script"
    fi
done
exit 0
