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

if [ -f /etc/device.properties ]; then
	source /etc/device.properties
fi

if [ -f /etc/include.properties ]; then
	source /etc/include.properties
fi

if [ -f /etc/rdm/loggerUtils.sh ]; then
    source /etc/rdm/loggerUtils.sh
fi

if [ -f /lib/rdk/t2Shared_api.sh ]; then
    source /lib/rdk/t2Shared_api.sh
fi

JSONQUERY="/usr/bin/jsonquery"
CONFIGPARAMGEN=/usr/bin/configparamgen
DIRECT_BLOCK_FILENAME="/tmp/.lastdirectfail"
DIRECT_BLOCK_TIME=86400
CB_BLOCK_FILENAME="/tmp/.lastcodebigfail"
CB_BLOCK_TIME=1800
FORCE_DIRECT_ONCE="/tmp/.forcedirectonce"
BB_TRIES=3
RDM_SSR_LOCATION=/tmp/.rdm_ssr_location
PEER_COMM_DAT="/etc/dropbear/elxrretyt.swr"
PEER_COMM_ID="/tmp/elxrretyt-rdm.swr"
ARM_SCP_IP_ADRESS=$ARM_INTERFACE_IP

JSONQUERY="/usr/bin/jsonquery"
DEVICE_MODEL=$MODEL_NUM
DEVICE_BRANCH=$(grep BRANCH /version.txt |  cut -d "=" -f2)

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

CURL_TIMEOUT=10
CURL_OPTION="-w"
TLS="--tlsv1.2"
CURL_TLS_TIMEOUT=30
downloadStatus=1

HTTP_CODE="/tmp/.httpcode"
TLSRet=""
http_code=1

EnableOCSPStapling="/tmp/.EnableOCSPStapling"
EnableOCSP="/tmp/.EnableOCSPCA"

#Read the Download Mgr Url from RFC
if [ "$DEVICE_TYPE" = "broadband" ]; then
    DEFAULT_URL=`dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.CDLDM.CDLModuleUrl | grep string | awk '{print $5}'`
else
    if [ -f /usr/bin/tr181 ];then
        DEFAULT_URL=`/usr/bin/tr181 -g Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.CDLDM.CDLModuleUrl 2>&1 > /dev/null`
    fi
fi

getJSONValue()
{
    $JSONQUERY -f $1 -p $2 2> /dev/null
}

getJSONArraySize()
{
    $JSONQUERY -f $1 -p $2 -l 2> /dev/null
}

get_core_value()
{
    core=""
    if [ -f /tmp/cpu_info ];then
         core=`cat /tmp/cpu_info`
    fi
    if [ ! "$core" ];then
           processor=`grep -ic "Atom" /proc/cpuinfo`
           if [ $processor ] && [ $processor -gt 0 ] ;then
                  core="ATOM"
           fi
           processor=`grep -c "ARM" /proc/cpuinfo`
           if [ $processor ] && [ $processor -gt 0 ] ;then
                  core="ARM"
           fi
           echo $core > /tmp/cpu_info
    fi
    echo $core
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


downloadApp_getVersionPrefix()
{
   buildType=`downloadApp_getBuildType`
   version=$(downloadApp_getFWVersion)
   versionPrefix=`echo $version | sed 's/_'$buildType'//g'`
   echo $versionPrefix
}

getDownloadUrl()
{
    #Setup the URL Location for RDM packages
    if [ -f /tmp/.xconfssrdownloadurl ];then
        cp /tmp/.xconfssrdownloadurl /tmp/.rdm_ssr_location
        if [ -d "/nvram" ]; then
            cp /tmp/.rdm_ssr_location /nvram/.rdm_ssr_location
        fi
    elif [ "$BOX_TYPE" = "XB3" ]; then
        checkstatus=1
        counter=0
        log_msg "DOWNLOADING: /tmp/.xconfssrdownloadurl from ARM Side"
        if [ ! -f $PEER_COMM_ID ]; then
            $CONFIGPARAMGEN jx $PEER_COMM_DAT $PEER_COMM_ID
        fi
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
    fi

    if [ -f $RDM_SSR_LOCATION ]; then
        get_url=`sed -n '/^http/p' $RDM_SSR_LOCATION`
        if [ -z $get_url ]; then
            log_msg "Download URL is not available in $RDM_SSR_LOCATION"
            if [ -n "$DEFAULT_URL" ]; then
                log_msg "Using RDM Default url $DEFAULT_URL to download from the Xconf Server"
                url=$DEFAULT_URL
            else
                log_msg "RFC Param Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.CDLDM.CDLModuleUrl is not set. Exiting..."
                exit 1
            fi
       else
           log_msg "Download URL available in $RDM_SSR_LOCATION is $(cat $RDM_SSR_LOCATION)"
           url=`cat $RDM_SSR_LOCATION`
       fi
    elif [ -n "$DEFAULT_URL" ]; then
        log_msg "Using RDM Default url $DEFAULT_URL to download from the Xconf Server"
        url=$DEFAULT_URL
    fi

    # Enforce HTTPs download for Downloadable modules
    if [ -n "$url" ]; then
        log_msg "Replacing http with https in curl download request"
        url=`echo $url | sed "s/http:/https:/g"`
        log_msg "RDM App Download URL Location is $url"
    fi
    echo $url
}

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
    
    if [ "$DEVICE_TYPE" = "broadband" ]; then
    	return $codebigret
    fi
    
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
       eval $SIGN_CMD > /tmp/.signedRequest_${DOWNLOAD_APP_MODULE}
       cbSignedimageHTTPURL=`cat /tmp/.signedRequest_${DOWNLOAD_APP_MODULE}`
       rm -f /tmp/.signedRequest_${DOWNLOAD_APP_MODULE}
       
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
    if [ "$flag" = 1 ]; then
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
                t2CountNotify "RDM_ERR_rdm_retry_fail"
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
    pkgType=$2
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
                log_msg "applicationDownload: No App download attempts since Codebig is blocked"
                [ "x$pkgType" = "bundle" ] && return 1
                exit 4
            fi
        fi
        generateDownloadUrl $downloadFile $downloadUrl $UseCodebig
        sendDownloadRequest "${CURL_CMD}"
        ret=$TLSRet
        http_code=$(awk -F\" '{print $1}' $HTTP_CODE)
        if [ $ret -ne 0 ] && [ "$http_code" == "000" ]; then
            if [ "$UseCodebig" -eq "1" ]; then
                if [ ! -f $CB_BLOCK_FILENAME ]; then
                        touch $CB_BLOCK_FILENAME
                fi
                touch $FORCE_DIRECT_ONCE
            fi
            return 1
        fi
    else
        if [ "$UseCodebig" = 1 ]; then
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
         return 0
    fi
}


applicationExtraction()
{
    downloadUrl=$1
    downloadFile=`basename $downloadUrl`
    if [ ! -f $DOWNLOAD_LOCATION/$downloadFile ];then
           downloadStatus=1
           log_msg  "applicationExtraction: File Not Found for Extraction: $DOWNLOAD_LOCATION/$downloadFile"
           t2CountNotify "NF_ERR_rdm_filenotfound_extraction"
           exit 2
    fi
    tar -xvf $DOWNLOAD_LOCATION/$downloadFile -C $DOWNLOAD_LOCATION/ >> $LOG_PATH/rdm_status.log 2>&1
    if [ $? -ne 0 ];then
            log_msg "applicationExtraction: $downloadFile: tar Extraction Failed..! Clearing $DOWNLOAD_LOCATION"
            rm -rf $DOWNLOAD_LOCATION/*
            exit 3
    fi
}


is_file_exists()
{
	if [ -e $1 ];then
        	echo `ls $1 | xargs basename`
	fi	
}
