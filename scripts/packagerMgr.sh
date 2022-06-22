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

if [ -f /etc/rdm/downloadUtils.sh ];then
    . /etc/rdm/downloadUtils.sh
else
    echo "File Not Found, /etc/rdm/downloadUtils.sh"
fi

if [ -f /lib/rdk/t2Shared_api.sh ]; then
    source /lib/rdk/t2Shared_api.sh
fi

RDM_DOWNLOAD_PATH=/tmp/rdm/
THUNDER_SECURITY_UTIL=/usr/bin/WPEFrameworkSecurityUtility
THUNDER_SECURITY_TOKEN_FILE=/tmp/.wpe_secure_token
APP_MOUNT_PATH=/media/apps
# Packager flags
PACKAGE_EXTRACTION_FAILED=/tmp/.opkg_rdm_extract_failed
PACKAGE_DOWNLOAD_FAILED=/tmp/.opkg_rdm_download_failed
PACKAGE_SIGN_VERIFY_FAILED=/tmp/.opkg_rdm_sign_verify_failed
PACKAGE_SIGN_VERIFY_SUCCESS=/tmp/.opkg_rdm_sign_verify_success

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

# Input Parameter: Application Home Path
if [ ! "$2" ];then
      APPLN_HOME_PATH=/tmp/$DOWNLOAD_APP_MODULE
      RDM_DOWNLOAD_PATH=/tmp/rdm
else
      log_msg "using the custom HOME path:$2"
      APPLN_HOME_PATH=$2/$DOWNLOAD_APP_MODULE
      RDM_DOWNLOAD_PATH=$2/rdm
fi

# Input Parameter: Authentication Method for Package Validation
if [ ! "$3" ];then
      log_msg "Application Download Not possible without Authentication"
      log_msg "Supported Authentication: OpenSSL Verification"
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

if [ ! $5 ];then
     log_msg "Package Name from meta data: /etc/rdm/rdm-manifest.json"
     # Retrive the Appln metadata
     DOWNLOAD_PKG_NAME=`/usr/bin/jsonquery -f /etc/rdm/rdm-manifest.json  --path=//packages/$DOWNLOAD_APP_MODULE/pkg_name`
else
     DOWNLOAD_PKG_NAME=$5
     applicationSuffix="${DOWNLOAD_PKG_NAME}-signed"
     DOWNLOAD_PKG_NAME="${applicationSuffix}.tar"
     log_msg "Using the custom Package name: $DOWNLOAD_PKG_NAME"
fi

log_msg "DOWNLOAD_APP_MODULE = $DOWNLOAD_APP_MODULE"
log_msg "PKG_AUTHENTICATION = $PKG_AUTHENTICATION"
log_msg "PKG_EXTN = $PACKAGE_EXTN"

DOWNLOAD_APP_NAME=`/usr/bin/jsonquery -f /etc/rdm/rdm-manifest.json  --path=//packages/$DOWNLOAD_APP_MODULE/app_name`

if [ -f /tmp/.rdm-apps-data/${DOWNLOAD_APP_MODULE}.conf ]; then
    source /tmp/.rdm-apps-data/${DOWNLOAD_APP_MODULE}.conf
fi

log_msg "Meta-data: App name: $DOWNLOAD_APP_NAME"
log_msg "Meta-data: Package name: $DOWNLOAD_PKG_NAME"

if [ ! "$DOWNLOAD_APP_NAME" ];then
    DOWNLOAD_APP_NAME=$DOWNLOAD_APP_MODULE
fi

DOWNLOAD_LOCATION=$RDM_DOWNLOAD_PATH/downloads/$DOWNLOAD_APP_NAME

log_msg "APPLN_HOME_PATH = $APPLN_HOME_PATH"
## Retry Interval in seconds
PACKAGER_RETRY_DELAY=5
## Maximum Retry Count
PACKAGER_RETRY_COUNT=2

CURL_OPTION="-w"
HTTP_CODE="/tmp/rdm_httpcode"
TLSRet=""
http_code=1

generateDownloadUrl()
{
    downloadUrl=$1

    $THUNDER_SECURITY_UTIL | grep token > $THUNDER_SECURITY_TOKEN_FILE
    # wpesecurity utility will return a json. so get the token value
    auth_token=`/usr/bin/jsonquery -f $THUNDER_SECURITY_TOKEN_FILE --path=//token`
    curl_header="\"Content-Type: application/json\""
    auth_header="\"Authorization: Bearer $auth_token\""
    wpe_url="http://127.0.0.1:9998/jsonrpc"
    json_data="'{\"jsonrpc\":\"2.0\",\"id\":\"1234567890\",\"method\": \"Packager.1.install\",\"params\": {\"package\": \"$downloadUrl\",\"version\": \"1.0\",\"architecture\": \"arm\"}}'"

    CURL_CMD="curl $CURL_OPTION '%{http_code}\n' -H $curl_header -H $auth_header -X POST -d $json_data $wpe_url"
}

sendRequestToPackager()
{
    curl_request=$1

    #Sensitive info like Authorization signature should not print
    curl_cmd=`echo $curl_request | sed -e "s|-H.*-w|-H 'AuthorizationHeader' -w|g"`
    log_msg "sendRequestToPackager: CURL_CMD: ${curl_cmd}"

    eval $curl_request > $HTTP_CODE
    TLSRet=$?
    http_code=$(awk -F} '{print $NF}' $HTTP_CODE)
    rm $HTTP_CODE
    if [ $TLSRet -ne 0 ];then
        log_msg "sendRequestToPackager: Curl to Packager failed with http_code : $http_code   ret : $TLSRet"
        return 1
    else
        log_msg "sendRequestToPackager: Curl to Packager returned with http_code : $http_code   ret : $TLSRet"
        if [ "$http_code" = "200" ]; then
            log_msg "sendRequestToPackager: Curl to Packager success"
            return 0
        fi
    fi
}

invokePackager()
{
    downloadUrl=$1
    downloadFile=`basename $downloadUrl`
    ret=1
    retries=0

    log_msg "invokePackager: $downloadUrl"

    while [ $retries -le $PACKAGER_RETRY_COUNT ]
    do
        if [ -n "$(pgrep -f 'WPEProcess -l libWPEFrameworkPackager.so')" ]; then
            log_msg "invokePackager: Packager is running. Sending the request"
            generateDownloadUrl $downloadUrl
            sendRequestToPackager "$CURL_CMD"
            if [ "$?" -eq "0" ]; then
                log_msg "invokePackager: Request success"
                break
            fi
            log_msg "invokePackager: Request failed. Retrying after $PACKAGER_RETRY_DELAY sec"
            sleep $PACKAGER_RETRY_DELAY
        else
            log_msg "invokePackager: Packager not running. Retrying after $PACKAGER_RETRY_DELAY sec"
            sleep $PACKAGER_RETRY_DELAY
        fi
        retries=`expr $retries + 1`
        if [ $retries -gt $PACKAGER_RETRY_COUNT ]; then
            log_msg "invokePackager: Packager retries exhausted. Exiting"
            exit 4
        fi
    done
}

url=$(getDownloadUrl)
if [ -z $url ]; then
    log_msg "RDM download url is not available in both $RDM_SSR_LOCATION and RFC parameter. Exiting..."
    exit 1
fi

invokePackager $url/${DOWNLOAD_PKG_NAME}

# Since the request to Packager is asynchronous, we need to wait in a loop until Packager completes its execution.
# We wait for a maximum of 300s in a loop of 6s each (probably less sleep & more loops because we dont want sleep more even in ideal conditions)
# This 300s is considering worst case scenario where both direct & codebig download fails (includes 3 retries, sleep between retries & 30s curl timeout for each try)
# In a perfect working condition, Packager takes atmost 10s to complete its execution
# TODO DELIA-45542 - Implement methods in Packager plugin to track the progress
loop_count=1
max_loop_count=50

while [ $loop_count -le $max_loop_count ]
do
    if [ -f $PACKAGE_SIGN_VERIFY_SUCCESS ]; then
        if [ -s "$DOWNLOAD_LOCATION/$downloadFile" ]; then
            log_msg "Size Info After Download: `ls -lh $DOWNLOAD_LOCATION/$downloadFile`"
        fi
        log_msg "RSA Signature Validation Success for ${DOWNLOAD_APP_MODULE} package"
        t2CountNotify "RDM_INFO_rsa_valid_signature"
        rm $PACKAGE_SIGN_VERIFY_SUCCESS
        # cleanup tmp dirs created by opkg
        rm -rf /tmp/{opkg,var/lib/opkg}
        break
    elif [ -f $PACKAGE_DOWNLOAD_FAILED -o -f $PACKAGE_EXTRACTION_FAILED -o -f $PACKAGE_SIGN_VERIFY_FAILED -o $loop_count -eq $max_loop_count ]; then
        if [ -f $PACKAGE_DOWNLOAD_FAILED ]; then
            log_msg "${DOWNLOAD_APP_MODULE} package download failed"
            rm $PACKAGE_DOWNLOAD_FAILED
        elif [ -f $PACKAGE_EXTRACTION_FAILED ]; then
            log_msg "${DOWNLOAD_APP_MODULE} package extraction failed"
            rm $PACKAGE_EXTRACTION_FAILED
        elif [ -f $PACKAGE_SIGN_VERIFY_FAILED ]; then
            log_msg "${DOWNLOAD_APP_MODULE} package signature verification failed"
            rm $PACKAGE_SIGN_VERIFY_FAILED
        else
            log_msg "Max time reached. Failure in processing ${DOWNLOAD_APP_MODULE} package"
        fi
        log_msg "Packager execution not successful. Cleanup and exit"
        # cleanup & exit
        if [ -d $DOWNLOAD_LOCATION ]; then rm -rf $DOWNLOAD_LOCATION ; fi
        if [ -d $APPLN_HOME_PATH ]; then rm -rf $APPLN_HOME_PATH ; fi
        exit 4
    else
        loop_count=`expr $loop_count + 1`
        sleep 6
    fi
done

log_msg "Packager execution completed successfully"
 
chown -R root:lxcgrp $APPLN_HOME_PATH/
chmod -R 775 $APPLN_HOME_PATH/

log_msg "Checking if ${DOWNLOAD_APP_MODULE} package contains container bundle"
CURRENT_PATH=`pwd` 
cd $DOWNLOAD_LOCATION

if [ -f $DOWNLOAD_LOCATION/packages.list ];then
    while read -r finalPackage
    do
        if [ "$finalPackage" == "${DOWNLOAD_APP_MODULE}_container.ipk" ];then
            log_msg "LXC Container IPK detected..."
            log_msg "LXC Container IPK post download processing..."

            if [ -f $APPLN_HOME_PATH/conf/lxc.conf ];then
                ROOTFS_PATH="$(echo $APPLN_HOME_PATH/rootfs | sed 's/\//\\\//g')"
                sed -i 's/lxc.rootfs = .*/lxc.rootfs = '"$ROOTFS_PATH"'/' $APPLN_HOME_PATH/conf/lxc.conf
            fi

            if [ -f $APPLN_HOME_PATH/launcher/${DOWNLOAD_APP_MODULE}.sh ];then
                CONF_PATH="$(echo $APPLN_HOME_PATH/conf/lxc.conf | sed 's/\//\\\//g')"
                sed -i 's/\/container\/'"$DOWNLOAD_APP_MODULE"'\/conf\/lxc.conf/'"$CONF_PATH"'/g' $APPLN_HOME_PATH/launcher/${DOWNLOAD_APP_MODULE}.sh
                if [ -f $DOWNLOAD_LOCATION/executables.txt ]; then
                    EXECS=`cat ${DOWNLOAD_LOCATION}/executables.txt`
                    for EXE in $EXECS; do
                        EXE_LOC="$(echo $EXE | sed 's/\//\\\//g')"
                        REPLACE_EXE_LOC="$(echo $APPLN_HOME_PATH$EXE | sed 's/\//\\\//g')"
                        grep -q "$REPLACE_EXE_LOC" $APPLN_HOME_PATH/launcher/${DOWNLOAD_APP_MODULE}.sh
                        if [ "0" -ne "$?" ]; then
                            sed -i 's/'"$EXE_LOC"'/'"$REPLACE_EXE_LOC"'/g' $APPLN_HOME_PATH/launcher/${DOWNLOAD_APP_MODULE}.sh
                        fi
                    done
                fi
            fi
        fi

        if [ -f ./${finalPackage} ];then
            log_msg "Removing $finalPackage"
            if [ $finalPackage == "netflix_container.ipk" ]; then
                t2CountNotify "NF_INFO_rdm_success"
            fi
            rm -rf ./$finalPackage
        fi
    done <$DOWNLOAD_LOCATION/packages.list
else
    log_msg "${DOWNLOAD_APP_MODULE} package does not contain packages.list. Exiting"
    rm -rf $DOWNLOAD_LOCATION
    rm -rf $APPLN_HOME_PATH
    exit 4
fi

# Modify permission only for non-container packages via rdm,This is to retain the permissions for container made in build time.
if [ ! -f $DOWNLOAD_LOCATION/executables.txt ]; then
    chmod -R 544 $APPLN_HOME_PATH/
fi

log_msg "Container bundle check completed"
cd $CURRENT_PATH

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
