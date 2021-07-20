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

if [ -f /etc/rdm/loggerUtils.sh ];then
    . /etc/rdm/loggerUtils.sh
else
    echo "File Not Found, /etc/rdm/loggerUtils.sh"
fi

CONFIGPARAMGEN=/usr/bin/configparamgen
DIRECT_BLOCK_FILENAME="/tmp/.lastdirectfail_rdm"
DIRECT_BLOCK_TIME=86400
CB_BLOCK_FILENAME="/tmp/.lastcodebigfail_rdm"
CB_BLOCK_TIME=1800

## Retry Interval in seconds
DOWNLOAD_APP_DEFAULT_RETRY_DELAY=10
## Maximum Retry Count
DOWNLOAD_APP_CB_RETRY_COUNT=1

CURL_OPTION="-w"
TLS="--tlsv1.2"
CURL_TLS_TIMEOUT=30
HTTP_CODE="/tmp/.rdm_httpcode"
TLSRet=""
http_code=1

EnableOCSPStapling="/tmp/.EnableOCSPStapling"
EnableOCSP="/tmp/.EnableOCSPCA"

# Initialize codebig flag values
UseCodebig=0
direct_failed=0

usage()
{
    log_msg "USAGE: $0 <download_url> <download_path>"
}

IsDirectBlocked()
{
    directret=0
    if [ -f $DIRECT_BLOCK_FILENAME ]; then
        modtime=$(($(date +%s) - $(date +%s -r $DIRECT_BLOCK_FILENAME)))
        remtime=$((($DIRECT_BLOCK_TIME/3600) - ($modtime/3600)))
        if [ "$modtime" -le "$DIRECT_BLOCK_TIME" ]; then
            log_msg "Last direct failed blocking is still valid for $remtime hrs, preventing direct"
            directret=1
        else
            log_msg "Last direct failed blocking has expired, removing $DIRECT_BLOCK_FILENAME, allowing direct"
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
            log_msg "Last Codebig failed blocking is still valid for $cbremtime mins, preventing Codebig"
            codebigret=1
        else
            log_msg "Last Codebig failed blocking has expired, removing $CB_BLOCK_FILENAME, allowing Codebig"
            rm -f $CB_BLOCK_FILENAME
        fi
    fi
    return $codebigret
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
       exit -1
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
            CURL_CMD="curl $TLS -fgL --cert-status --connect-timeout $CURL_TLS_TIMEOUT  -H '$authorizationHeader' -w '%{http_code}\n' -o \"$download_path/$file\" '$serverUrl' > $HTTP_CODE"
        else
            CURL_CMD="curl $TLS -fgL --connect-timeout $CURL_TLS_TIMEOUT  -H '$authorizationHeader' -w '%{http_code}\n' -o \"$download_path/$file\" '$serverUrl' > $HTTP_CODE"
        fi
    else
        if [ -f $EnableOCSPStapling ] || [ -f $EnableOCSP ]; then
            CURL_CMD="curl $TLS -fgL $CURL_OPTION '%{http_code}\n' -o \"$download_path/$file\" \"$url\" --cert-status --connect-timeout $CURL_TLS_TIMEOUT -m 600"
        else
            CURL_CMD="curl $TLS -fgL $CURL_OPTION '%{http_code}\n' -o \"$download_path/$file\" \"$url\" --connect-timeout $CURL_TLS_TIMEOUT -m 600"
        fi
    fi
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
        if [ -f $download_path/$downloadFile ];then
              log_msg "sendAppDownloadRequest: Curl partial Download, Failed download for $downloadUrl"
              rm $download_path/$downloadFile
        else
              log_msg "sendAppDownloadRequest: Curl Download Failed for $downloadUrl"
        fi
    else
        log_msg "sendAppDownloadRequest: Package download http_code : $http_code   ret : $TLSRet"
        if [ "$http_code" = "200" ]; then
              log_msg "sendAppDownloadRequest: Curl Download Success for $downloadUrl"
        fi
    fi
}

applicationDownload()
{
    downloadUrl=$1
    downloadFile=`basename $downloadUrl`
    ret=1
    cbretries=0

    log_msg "applicationDownload: DOWNLOADING: tar file $downloadUrl"

    # Clean up to clear any previous partial files before downloading new package
    rm -rf $download_path/*
    mkdir -p $download_path

    if [ $UseCodebig -eq 1 ]; then
        log_msg "applicationDownload: Codebig is enabled UseCodebig=$UseCodebig" 
        if [ "$DEVICE_TYPE" = "mediaclient" ]; then
            # Use Codebig connection connection on XI platforms
            IsCodeBigBlocked
            skipcodebig=$?
            if [ $skipcodebig -eq 0 ]; then
                while [ $cbretries -le $DOWNLOAD_APP_CB_RETRY_COUNT ]
                do
                    if [ $cbretries -eq 1 ];then
                        sleep $DOWNLOAD_APP_DEFAULT_RETRY_DELAY
                    fi
                    log_msg "applicationDownload: Attempting Codebig App download"
                    generateDownloadUrl $downloadFile $downloadUrl $UseCodebig
                    sendAppDownloadRequest "$CURL_CMD"
                    ret=$TLSRet
                    http_code=$(awk -F\" '{print $1}' $HTTP_CODE)
                    if [ "$http_code" = "200" ]; then
                        log_msg "applicationDownload: Codebig App download success, return:$ret, httpcode:$http_code"
                        if [ $direct_failed -eq 1 ]; then
                            UseCodebig=1
                            if [ ! -f $DIRECT_BLOCK_FILENAME ]; then
                                touch $DIRECT_BLOCK_FILENAME
                                log_msg "applicationDownload: Use Codebig connection and Block Direct for 24 hrs"
                            fi
                        else
                            IsDirectBlocked
                            skipDirect=$?
                            if [ $skipDirect -eq 0 ]; then
                                UseCodebig=0
                            fi
                        fi
                        break
                    fi
                    log_msg "applicationDownload: Codebig App download failed, retry:$cbretries, return:$ret, httpcode:$http_code"
                    cbretries=`expr $cbretries + 1`
                done
            fi
            if [ $ret -ne 0 ] && [ "$http_code" != "200" ]; then
                log_msg "applicationDownload: Codebig App download failed with return:$ret httpcode:$http_code after $DOWNLOAD_APP_CB_RETRY_COUNT attempts"
                if [ $direct_failed -eq 1 ]; then
                    UseCodebig=0
                    if [ ! -f $CB_BLOCK_FILENAME ]; then
                        touch $CB_BLOCK_FILENAME
                        log_msg "applicationDownload: No App download attempts allowed, Blocking Codebig for 30 mins"
                    fi
                else
                    IsCodeBigBlocked
                    skipcodebig=$?
                    if [ $skipcodebig -eq 0 ]; then
                        log_msg "applicationDownload: Earlier Codebig block released"
                        touch $CB_BLOCK_FILENAME
                        log_msg "applicationDownload: No App download attempts allowed, Again Blocking Codebig for 30 mins"    
                    fi
                fi
                exit -1
            fi
        else
            log_msg "applicationDownload: Codebig App download is not supported"
            exit -1
        fi
    fi  

    if [ -f $download_path/$downloadFile ];then
         log_msg "Size Info After Download: `ls -lh $download_path/$downloadFile`"
    fi
}

### Main App ###
log_msg "Checking Codebig flag..."

if [ -n "$3" ]; then
    if [ "$3" -eq "1" ]; then
        log_msg "Direct download failed. Trying codebig download"
        direct_failed=1
        UseCodebig=1
    fi
fi

if [ $direct_failed -eq 0 ]; then
    IsDirectBlocked
    UseCodebig=$?
    if [ $UseCodebig -eq 0 ]; then
        log_msg "Direct download not blocked. Exiting"
        exit 1
    else
        log_msg "Direct download blocked. Trying codebig download"
    fi
fi

if [ -n "$1" -a -n "$2" ]; then
    download_url=$1
    download_path=$2
else
    usage
    log_msg "Missing arguments. Exiting"
    exit -1
fi

download_filename="$(basename $download_url)"
log_msg "download_url = $download_url"
log_msg "download_path = $download_path"
log_msg "download_filename = $download_filename"

# Download the File Package if not already downloaded
log_msg "Downloading package ${download_url}"
applicationDownload ${download_url}

exit 0
