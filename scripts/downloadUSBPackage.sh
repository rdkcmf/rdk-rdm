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
if [ -f /etc/include.properties ];then
     . /etc/include.properties
fi

if [ -f /etc/device.properties ];then
     . /etc/device.properties
fi
if [ -f /lib/rdk/t2Shared_api.sh ]; then
    source /lib/rdk/t2Shared_api.sh
fi

if [ "$LOG_PATH" ];then
     LOG_FILE="$LOG_PATH/rdm_status.log"
else
     if [ -d /var/log ];then
          if [ -f /var/log/rdm_status.log ];then
               rm -rf /var/log/rdm_status.log
          fi
          LOG_FILE=/var/log/rdm_status.log
     else
          LOG_FILE=/dev/null
     fi
fi

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

packageLocation=""
# Query RFC to check if USB auto mount Enabled or not
USBMOUNT_ENABLE=`/usr/bin/tr181Set -g Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.USB_AutoMount.Enable 2>&1 > /dev/null`
if [ "x$USBMOUNT_ENABLE" != "xtrue" ]; then
    log_msg "USB AutoMount is DISABLED for this device"
    exit 0
fi

# Extract & validate Signed package resides at given USB 
# mount point.  
USB_MOUNT_POINT=$1
if [ ! -d $USB_MOUNT_POINT ]; then
    log_msg "Mount point $USB_MOUNT_POINT does not exists"
fi

if [ ! -d ${USB_MOUNT_POINT}/partnerapps ];then
     mkdir -p ${USB_MOUNT_POINT}/partnerapps
else
     rm -rf ${USB_MOUNT_POINT}/partnerapps/*
fi

# Check if any signed tarball present
# Loop to validate all packages resides at USB Mount point
for file in `find $USB_MOUNT_POINT -name '*.tar' -type f`
do
    if [ ! -f $file ]; then
        log_msg "Packaged file $file does not exists"
        log_msg "Continue to next package"
        continue;
    fi
 
    fileName=`echo $file | xargs basename`
    filePath=`echo $file | xargs dirname` 
    log_msg "Found signed tarball package $fileName on path $filePath"
    # extract the package tar ball
    # Create package directory to extract tarball
    packageDir="${fileName%.*}"
    destn_path=`echo ${packageDir%-*}`
    packageLocation="${filePath}/.rdm_tmp"
    # Check if given package has already been extracted then remove it
    if [ -d $packageLocation ]; then
        log_msg "Package $file has already extracted"
        log_msg "Removing package to extract & reValidate"
        rm -rf ${packageLocation}/*
    else
        log_msg "Extracting the Package $fileName "
    fi
    mkdir -p "${packageLocation}"
    tar -xvf "${file}" -C "${packageLocation}"
        
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
    package_tarFile=`ls $packageLocation/*.tar| xargs basename`
    if [ ! -f $packageLocation/$package_tarFile ];then
        log_msg "Packaged does not exists"
        exit 1
    fi
    log_msg "$packageLocation $package_tarFile"

    # openssl Signature verification 
    log_msg "Performing Signaure validation on ${package_tarFile}"
    sh /etc/rdm/opensslVerifier.sh ${packageLocation} ${package_tarFile} ${package_signatureFile} "openssl" ${package_cert}
    if [ $? -ne 0 ] ; then
       log_msg "Signature validation failed"
       t2CountNotify "RDM_ERR_rsa_signature_failed"
       rm -rf $packageLocation/$package_tarFile
       rm -rf $packageLocation/$package_signatureFile
       rm -rf $packageLocation//$package_cert
       rm -rf $packageLocation/*
       exit 1
    else
       log_msg "Signature validation Successful"
    fi
        
    # extract final package
    package_extension="${package_tarFile##*.}"
    case "${package_extension}" in
    ipk)
        ar -x ${packageLocation}/${package_tarFile}
    ;;
    tar)
        tar -xvf ${packageLocation}/${package_tarFile} -C ${USB_MOUNT_POINT}/partnerapps
    ;;
    *)
        log_msg "Package extension $package_extension not supported"
    ;; 
    esac
 
    rm -rf $packageLocation/$package_tarFile
    rm -rf $packageLocation/$package_signatureFile
    rm -rf $packageLocation/$package_cert
    # End of loop to validate all USB packages
done
