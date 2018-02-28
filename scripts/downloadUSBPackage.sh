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

# Logging to verify USB status
LOG_FILE="/opt/logs/rdm_status.log"

log_msg() {
  #get current dateandtime
  DateTime=`date "+%m%d%y-%H:%M:%S:%N"`
  STR=""
  #check if parameter non zero size
  if [ -n "$1" ];
  then
    STR="$1"
  else
    DONE=false
    until $DONE ;do
    read IN || DONE=true
    STR=$STR$IN
    done
  fi
  #print log message
  echo "[$DateTime] [pid=$$] $STR" >>$LOG_FILE
}

appManagerconf="/opt/appmanagerregistry.conf"

# Initialize package attributes
APP_NAME=""
APP_TYPE=""
APP_VERSION=""
APP_LAUNCHER=""
CMD_NAME=""
packageLocation=""
appConfigFile=""
# Query RFC to check if USB auto mount Enabled or not
USBMOUNT_ENABLE=`/usr/bin/tr181Set -g Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.USB_AutoMount.Enable 2>&1 > /dev/null`
if [ "x$USBMOUNT_ENABLE" != "xtrue" ]; then
    log_msg "USB AutoMount is DISABLED for this device"
    exit 0
fi

# Subroutine to read application config file
readAppConfig()
{
    # defining with default values
    APP_CONFIG=$1
    APP_NAME=""
    CMD_NAME=""
    APP_LAUNCHER=""
    APP_TYPE=""
    APP_VERSION=""
    
    log_msg "Reading config file $APP_CONFIG"
    APP_NAME=`cat $APP_CONFIG | grep -w \"displayName\" | tail -1 | cut -d\" -f4`
    CMD_NAME=`cat $APP_CONFIG | grep -w \"cmdName\" | tail -1 | cut -d\" -f4`
    APP_LAUNCHER=`cat $APP_CONFIG | grep -w \"uri\" | tail -1 | cut -d\" -f4`
    APP_TYPE=`cat $APP_CONFIG | grep -w \"applicationType\" | tail -1 | cut -d\" -f4`
    APP_VERSION=`cat $APP_CONFIG | grep -w \"version\" | tail -1 | cut -d\" -f4`
}

# Subroutine to modify appmanagerregistry
modifyAppmanager()
{
   # modify app manager config file
   if [ ! -f "$appManagerconf" ]; then
       log_msg "App manager config file does not exists"
	   log_msg "Making the package config as App Manager config"
	   cp ${appConfigFile} $appManagerconf
       return
   fi

   # Appending new entry in config file
   count=$(grep -n -m 1 "[[:space:]]*}[[:space:]]*$" $appManagerconf | cut -f1 -d: )
# Insert if version present
    if [ "$APP_VERSION" != "" ]; then
        sed -i "$count i \"version\" : \"${APP_VERSION}\"" $appManagerconf
    fi
    sed -i "$count i     \"applicationType\" : \"${APP_TYPE}\"" $appManagerconf
    sed -i "$count i     \"uri\" : \"${APP_LAUNCHER}\"" $appManagerconf
    sed -i "$count i     \"cmdName\" : \"${CMD_NAME}\"" $appManagerconf
    sed -i "$count i     \"DisplayName\" : \"${APP_NAME}\"" $appManagerconf
    sed -i "$count i     {" $appManagerconf
    sed -i "$count i     }," $appManagerconf
} 


# Extract & validate Signed package resides at given USB 
# mount point.  
USB_MOUNT_POINT=$1
if [ ! -d $USB_MOUNT_POINT ]; then
    log_msg "Mount point $USB_MOUNT_POINT does not exists"
fi
# Check if any signed tarball present
packagedFile="$(find $USB_MOUNT_POINT -name '*.tar' -type f)"
# Loop to validate all packages resides at USB Mount point
for file in $packagedFile; do
    if [ ! -f $file ]; then
        log_msg "Packaged file $file does not exists"
        log_msg "Continue to next package"
        continue;
    fi
 
    fileName=`echo $file | xargs basename`
    filePath=`echo $file | xargs dirname` 
    log_msg $fileName
    log_msg $filePath
# extract the package tar ball
# Create package directory to extract tarball
    packageDir="${fileName%.*}"
    mkdir -p "${filePath}"/"${packageDir}"
    packageLocation="${filePath}"/"${packageDir}"
    tar -xvf "${packagedFile}" -C "${filePath}"/"${packageDir}"
        
# verify if all required files present
    package_signatureFile=`ls $packageLocation/*.sig| xargs basename`
    if [ ! -f $packageLocation/$package_signatureFile ];then
        log_msg "Signature does not exists"
        exit 1
    fi
    package_cert=`ls $packageLocation/*.crt| xargs basename`
    if [ ! -f $packageLocation/$package_cert ];then
        log_msg "Verification Certificate does not exists"
        exit 1
    fi

# both tar & ipk format supported
    package_tarFile=`ls $packageLocation/*.{tar,ipk}| xargs basename`
    if [ ! -f $packageLocation/$package_tarFile ];then
        log_msg "Packaged does not exists"
        exit 1
    fi
    log_msg "$packageLocation $package_tarFile"

# openssl Signature verification 
    sh /etc/rdm/opensslVerifier.sh ${packageLocation}/ ${package_tarFile} ${package_signatureFile} "openssl" ${package_cert}
    if [ $? -ne 0 ] ; then
       log_msg "Signature validation failed"
       rm -rf $packageLocation/$package_tarFile
       rm -rf $packageLocation/$package_signatureFile
       rm -rf $packageLocation//$package_cert
       rm -rf $packageLocation/*
       exit 1
    fi
        
# extract final package
    package_extension="${package_tarFile##*.}"
    case "${package_extension}" in
    ipk)
        ar -x ${packageLocation}/${package_tarFile}
    ;;
    tar)
        tar -xvf ${packageLocation}/${package_tarFile} -C ${packageLocation}
    ;;
    *)
        log_msg "Package extension $package_extension not supported"
    ;; 
    esac
 
    # find Package config file named appmanagerregistry.conf
    appConfigFile=`find $packageLocation/ -name appmanagerregistry.conf`

    # Read config file
    readAppConfig ${appConfigFile}
    # Modify app launcher reference
    cmd=`echo $APP_LAUNCHER | xargs basename`
    APP_LAUNCHER=`find $packageLocation -name $cmd` 
    # provide execution access to app launcher
    chmod +x $APP_LAUNCHER
    # Modify App manager for package
    modifyAppmanager
    # Clean up if fail to modify the App manager 
    if [ $? -ne 0 ]; then
       rm -rf $packageLocation/*
    fi
    rm -rf $packageLocation/$package_tarFile
    rm -rf $packageLocation/$package_signatureFile
    rm -rf $packageLocation/$package_cert
# End of loop to validate all USB packages
done
