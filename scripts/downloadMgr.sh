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

if [ -f /etc/rdm/rdmIarmEvents.sh ];then
    . /etc/rdm/rdmIarmEvents.sh
fi

if [ -f /etc/rdm/downloadUtils.sh ];then
    . /etc/rdm/downloadUtils.sh
else
    echo "File Not Found, /etc/rdm/downloadUtils.sh"
fi

. /etc/device.properties

RDM_DOWNLOAD_PATH=/tmp/rdm/
APPLN_HOME_PATH=/tmp/${DOWNLOAD_APP_MODULE}
APP_MOUNT_PATH=/media/apps
DIRECT_BLOCK_FILENAME="${DIRECT_BLOCK_FILENAME}_rdm"
CB_BLOCK_FILENAME="${CB_BLOCK_FILENAME}_rdm"
FORCE_DIRECT_ONCE="${FORCE_DIRECT_ONCE}_rdm"

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
     exit 1
else
     DOWNLOAD_APP_MODULE="$1"
fi

# Input Parameter: Application Home Path
if [ ! "$2" -o -z "$2" -o "$2" = "/tmp" ];then
      APPLN_HOME_PATH=/tmp/$DOWNLOAD_APP_MODULE
      RDM_DOWNLOAD_PATH=/tmp/rdm
else
      log_msg "using the custom HOME path:$2"
      APPLN_HOME_PATH=$2/$DOWNLOAD_APP_MODULE
      RDM_DOWNLOAD_PATH=$APP_MOUNT_PATH/rdm
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
      exit 1
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
log_msg "PKG_EXTN = $PACKAGE_EXTN"

if [ -f /tmp/.rdm-apps-data/${DOWNLOAD_APP_MODULE}.conf ]; then
    source /tmp/.rdm-apps-data/${DOWNLOAD_APP_MODULE}.conf
fi

log_msg "Meta-data: package name: $DOWNLOAD_APP_NAME"
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

# TODO Will Update after RFC changes
DOWNLOAD_APP_SSR_LOCATION=/nvram/.download_ssr_location

HTTP_CODE="$APPLN_HOME_PATH/httpcode"

updatePkgStatus()
{
        APP_INST_STATUS="$1"

        if [ -z "$DOWNLOAD_PKG_VERSION" ]; then
            DOWNLOAD_PKG_VERSION="NA"
        fi

        pkg_info="pkg_name:$DOWNLOAD_APP_NAME\npkg_version:$DOWNLOAD_PKG_VERSION\npkg_inst_status:$APP_INST_STATUS\npkg_inst_path:$APPLN_HOME_PATH"
        broadcastRDMPkgStatus "$pkg_info"
}


# Initialize codebig flag value
UseCodebig=0
log_msg "Checking Codebig flag..." 
IsDirectBlocked
UseCodebig=$?


# setup the workspace and initial cleanup
if [ ! -d $APPLN_HOME_PATH ];then
     mkdir -p $APPLN_HOME_PATH
fi

# Setup the Download Path
if [ ! -d $DOWNLOAD_LOCATION ]; then
      mkdir -p $DOWNLOAD_LOCATION
fi

if [ ! $ARM_SCP_IP_ADRESS ];then
      log_msg "Either Missing ARM SCP IP ADDRESS , Please Check /etc/device.properties "
      log_msg "             Or               "
      log_msg "Platform with Single Processor "
      log_msg "             Or               "
      log_msg "Processes are running on the ATOM side "
fi

url=$(getDownloadUrl)
if [ -z $url ]; then
    log_msg "RDM download url is not available in both $RDM_SSR_LOCATION and RFC parameter. Exiting..."
    updatePkgStatus "$RDM_PKG_INVALID_INPUT"
    exit 1
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
package_signatureFile=$( is_file_exists $DOWNLOAD_LOCATION/*-pkg.sig )

package_tarFile=$( is_file_exists $DOWNLOAD_LOCATION/*-pkg.tar )
pkg_extracted=false
# Keeping backup of signature and tarball on secondary storage to avoid top level package extraction on every reboot
# As extraction could account for the SD card write cycle on every reboot.
if ! [[  -f $DOWNLOAD_LOCATION/$package_signatureFile && -f $DOWNLOAD_LOCATION/$package_tarFile ]]; then
    log_msg "Extracting The Package $url/${DOWNLOAD_PKG_NAME}"
    applicationExtraction $url/${DOWNLOAD_PKG_NAME}
else
    pkg_extracted=true
fi

package_tarFile=$( is_file_exists $DOWNLOAD_LOCATION/*-pkg.tar )
log_msg "Intermediate PKG File: $package_tarFile"
if [ $package_tarFile ] && [ -f $DOWNLOAD_LOCATION/$package_tarFile ];then
      ls -l $DOWNLOAD_LOCATION/$package_tarFile
      hashVal=`sha256sum $DOWNLOAD_LOCATION/$package_tarFile | cut -d " " -f1`
      if [ "x$pkg_extracted" != "xtrue" ]; then
          tar -xvf $DOWNLOAD_LOCATION/$package_tarFile -C $DOWNLOAD_LOCATION/ >> $LOG_PATH/rdm_status.log 2>&1
      fi
fi

package_signatureFile=$( is_file_exists $DOWNLOAD_LOCATION/*-pkg.sig )
if [ $package_signatureFile ];then
       if [ -f $DOWNLOAD_LOCATION/$package_signatureFile ];then
            signVal=`cat $DOWNLOAD_LOCATION/$package_signatureFile`
       else
           log_msg "$DOWNLOAD_LOCATION/$package_signatureFile file not found"
       fi
fi

package_keyFile=$( is_file_exists $DOWNLOAD_LOCATION/*nam.txt )
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
		     updatePkgStatus "$RDM_PKG_EXTRACT_ERROR"
                else    
                     umask 544
                     #default compression method in opkg is gz for daisy/morty and xz for dunfell
                     data_file=`ls data.tar.* | tail -n1`
                     log_msg "Size of data [$data_file]: `ls -lh $data_file`"
                     tar -xvf $data_file -C $APPLN_HOME_PATH/ >> $LOG_PATH/rdm_status.log 2>&1
                     if [ $? -ne 0 ];then
                          log_msg "tar Extraction Failed for $data_file"
			  updatePkgStatus "$RDM_PKG_EXTRACT_ERROR"
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
               tar -xvf $finalPackage -C $APPLN_HOME_PATH/ >> $LOG_PATH/rdm_status.log 2>&1
               if [ $? -ne 0 ];then
                     log_msg "tar Extraction Failed for $finalPackage"
		     updatePkgStatus "$RDM_PKG_EXTRACT_ERROR"
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
        t2CountNotify "RDM_ERR_rdm_package_notfound"
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

if [ "$IMAGE_TYPE" != "OSS" ]; then
# Signature Validation
    if [ "$PKG_AUTHENTICATION" = "openssl" ];then
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
       log_msg "Supported Authentications: OpenSSL Verification"
    fi

    if [ $? -ne 0 ];then
        log_msg "signature validation failed"
        updatePkgStatus "$RDM_PKG_VALIDATE_ERROR"
        t2CountNotify "RDM_ERR_rsa_signature_failed"
        # Clear all files as partial extraction may happen due to corrupted tar file 
        rm -rf $DOWNLOAD_LOCATION/*
        if [ -d $APPLN_HOME_PATH ];then rm -rf $APPLN_HOME_PATH/* ; fi
        exit 3
    fi

else
   log_msg "IMAGE_TYPE IS OSS. Signature validation not required"
fi

log_msg "RDM package download success: $DOWNLOAD_PKG_NAME"
updatePkgStatus "$RDM_PKG_INSTALL_COMPLETE"

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
