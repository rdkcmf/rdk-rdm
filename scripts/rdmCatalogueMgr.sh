#!/bin/sh
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2022 RDK Management
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
    . /etc/device.properties
fi

if [ -f /etc/rdm/downloadUtils.sh ]; then
    . /etc/rdm/downloadUtils.sh
fi

if [ -f /etc/rdm/loggerUtils.sh ]; then
    . /etc/rdm/loggerUtils.sh
fi

if [ -f /lib/rdk/bundleUtils.sh ]; then
    . /lib/rdk/bundleUtils.sh
    LOG_FILE="/opt/logs/rdm_status.log"
fi

RDM_APP_PATH="/media/apps"
DEFAULT_RDM_MANIFEST="/etc/rdm/rdm-manifest.json"
DEFAULT_MANIFEST_VERSION=$(grep "manifest_version" ${DEFAULT_RDM_MANIFEST} | awk '{print $2}' | tr -d '"')
RDM_MANIFEST_PATH="${RDM_APP_PATH}/rdm/manifests"
persistent_manifest_version=""
APP_DATA_FILE="/tmp/.rdm-apps-data/"

DECOUPLED_RFC_ENABLED="$(tr181 Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.RDMDecoupledVersionManagement.Enable 2>&1 > /dev/null)"

######## MAIN #######

# Set default RDM_MANIFEST location
RDM_MANIFEST="$DEFAULT_RDM_MANIFEST"
download_manifest=0

if [ -n "$DECOUPLED_RFC_ENABLED" -a "$DECOUPLED_RFC_ENABLED" = "true" ]; then

    log_msg "RDM Decoupled Version Management feature is enabled"

    # Get default manifest branch & version from /etc/rdm/rdm-manifest.json
    default_MfstBranch="${DEFAULT_MANIFEST_VERSION%-v*}"
    default_MfstVersion="${DEFAULT_MANIFEST_VERSION#*-v}"

    if [ -z "$default_MfstBranch" -o -z "$default_MfstVersion" ]; then
        log_msg "Manifest version ($DEFAULT_MANIFEST_VERSION) from $RDM_MANIFEST is invalid"
        exit 1
    fi

    # Check for manifest version override in "/opt/rdmManifestVersion.conf for non prod builds  when xconf is empty"
    if [ -s "/opt/rdmManifestVersion.conf" ] && [ ! -s "/tmp/.xconfRdmCatalogueVersion" ] && [ $BUILD_TYPE != "prod" ]; then
        log_msg "Found an override manifest version in /opt/rdmManifestVersion.conf"
        override_manifest_version=$(cat "/opt/rdmManifestVersion.conf")

        # check whether manifest version inside override is valid
        echo "$override_manifest_version" | grep -q "^$default_MfstBranch-v*.*"
        if [ $? -eq 0 ]; then
            log_msg "Overriden manifest version : $override_manifest_version"
            PERSISTENT_RDM_MANIFEST="${DEVICE_MODEL}_rdm-manifest_${override_manifest_version}.json"
            RDM_MANIFEST="${RDM_MANIFEST_PATH}/${PERSISTENT_RDM_MANIFEST}"
            download_manifest=1
        else
            log_msg "Device configured with an invalid overriden manifest version : $override_manifest_version"
        fi

    # Check the manifest version from xconf
    elif [ -s "/tmp/.xconfRdmCatalogueVersion" ]; then
        # Get the manifest version from xconf and check whether it is valid
        xconf_manifest_version=$(cat "/tmp/.xconfRdmCatalogueVersion")
        log_msg "Manifest Version from Xconf: $xconf_manifest_version"

        # Check whether the manifest version received from xconf belongs to the firmware currently running in the box
        echo "$xconf_manifest_version" | grep -q "^$default_MfstBranch-v*.*"

        if [ $? -eq 0 ]; then
            log_msg "Manifest branch from xconf and in rootfs are same. Comparing the versions... "
            xconf_version="${xconf_manifest_version#*-v}"

            persistent_manifest_version=$(getInstalledRdmManifestVersion)
            persistent_version="${persistent_manifest_version#*-v}"
            if [ "$persistent_manifest_version" != "$DEFAULT_MANIFEST_VERSION" ]; then
                log_msg "Found the latest manifest version inside $RDM_MANIFEST_PATH for the firmware currently running in device : $persistent_manifest_version"
            else
                log_msg "No latest version found in $RDM_MANIFEST_PATH for the catalogue currently running in the device"
            fi

            latest_manifest_version=$(getLatestVersion $default_MfstVersion $xconf_version $persistent_version)
            if [ "$latest_manifest_version" != "$default_MfstVersion" ]; then
                PERSISTENT_RDM_MANIFEST="${DEVICE_MODEL}_rdm-manifest_${default_MfstBranch}-v${latest_manifest_version}.json"
                RDM_MANIFEST="${RDM_MANIFEST_PATH}/${PERSISTENT_RDM_MANIFEST}"
                download_manifest=1
            elif [ "$latest_manifest_version" = "$default_MfstVersion" ]; then
                log_msg "RDM manifest version received from xconf is already available in rootfs. Hence parsing $RDM_MANIFEST"
            fi
        else
            log_msg "Manifest version received from xconf does not belongs to the firmware available in the device and it is invalid. Hence parsing $RDM_MANIFEST"
        fi
    else
        log_msg "RDM manifest version not received from XCONF. Hence parsing $RDM_MANIFEST"
    fi
else
    log_msg "RDM Decoupled Version Management feature is disabled"
fi

if [ "$download_manifest" -eq "1" ]; then

    # Download RDM catalogue
    DOWNLOAD_MANIFEST="${PERSISTENT_RDM_MANIFEST%.*}"

    # Check whether the cloud manifest is already available
    [ ! -d "$RDM_MANIFEST_PATH" ] && mkdir -p "$RDM_MANIFEST_PATH"
    if [ -f $RDM_MANIFEST ]; then
        log_msg "$RDM_MANIFEST already downloaded on secondary storage. So skip the download and validate the manifest"
    fi

    time sh /etc/rdm/downloadMgr.sh "manifests" "$RDM_APP_PATH/rdm" "openssl" "tar" "$DOWNLOAD_MANIFEST"

    if [ $? -ne 0 ]; then
        log_msg "Cloud manifest download failed"
        exit 1
    else
        log_msg "$RDM_MANIFEST successfully downloaded"
    fi
fi

log_msg "RDM Manifest = $RDM_MANIFEST"

num_rdm_packages=$(getJSONArraySize "$RDM_MANIFEST" "/packages")

if [ $? -ne 0 -o -z "$num_rdm_packages" ]; then
    log_msg "Unable to get the RDM Manifest json array size. Exiting"
    exit 1
fi

log_msg "Number of packages found in $RDM_MANIFEST is $num_rdm_packages"

mkdir -p "$APP_DATA_FILE"
idx=0
while [ "$idx" -lt "$num_rdm_packages" ];
do
    DOWNLOAD_APP_NAME=$(getJSONValue "$RDM_MANIFEST" "/packages/$idx/app_name")
    DOWNLOAD_APP_ONDEMAND=$(getJSONValue "$RDM_MANIFEST" "/packages/$idx/dwld_on_demand")
    DOWNLOAD_METHOD_CONTROLLER=$(getJSONValue "$RDM_MANIFEST" "/packages/$idx/dwld_method_controller")
    IS_VERSIONED=$(getJSONValue "$RDM_MANIFEST" "/packages/$idx/is_versioned")
    DOWNLOAD_PKG_TYPE=$(getJSONValue "$RDM_MANIFEST" "/packages/$idx/pkg_type")
    if [ "$IS_VERSIONED" = "true" ]; then
        nversions=$(getJSONArraySize "$RDM_MANIFEST" "/packages/$idx/packages")
	vidx=0
	DOWNLOAD_PKG_VERSION=""
        DOWNLOAD_PKG_NAME=""
	while [ "$vidx" -lt "$nversions" ];
	do
            pkg_ver=$(getJSONValue "$RDM_MANIFEST" "/packages/$idx/packages/$vidx/pkg_version")
            pkg_size=$(getJSONValue "$RDM_MANIFEST" "/packages/$idx/packages/$vidx/app_size")
            pkg_name=$(getJSONValue "$RDM_MANIFEST" "/packages/$idx/packages/$vidx/pkg_name")
	    PKG_VERSION="$pkg_ver $DOWNLOAD_PKG_VERSION "
	    APP_SIZE="$pkg_size $DOWNLOAD_PKG_SIZE "
            PKG_NAME="$pkg_name $DOWNLOAD_PKG_NAME "
	    DOWNLOAD_PKG_VERSION=$(echo "$PKG_VERSION" | xargs)
	    DOWNLOAD_APP_SIZE=$(echo "$APP_SIZE" | xargs)
	    DOWNLOAD_PKG_NAME=$(echo "$PKG_NAME" | xargs)
	    vidx=$(expr $vidx + 1)
	done
    else
	    DOWNLOAD_PKG_NAME=$(getJSONValue "$RDM_MANIFEST" "/packages/$idx/pkg_name")
            DOWNLOAD_PKG_VERSION=$(getJSONValue "$RDM_MANIFEST" "/packages/$idx/pkg_version")
            DOWNLOAD_APP_SIZE=$(getJSONValue "$RDM_MANIFEST" "/packages/$idx/app_size")
    fi

    echo -e "DOWNLOAD_APP_NAME=\"$DOWNLOAD_APP_NAME\"\nDOWNLOAD_APP_ONDEMAND=\"$DOWNLOAD_APP_ONDEMAND\"\nDOWNLOAD_METHOD_CONTROLLER=\"$DOWNLOAD_METHOD_CONTROLLER\"\nDOWNLOAD_PKG_TYPE=\"$DOWNLOAD_PKG_TYPE\"\nIS_VERSIONED=\"$IS_VERSIONED\"\nDOWNLOAD_PKG_NAME=\"$DOWNLOAD_PKG_NAME\"\nDOWNLOAD_PKG_VERSION=\"$DOWNLOAD_PKG_VERSION\"\nDOWNLOAD_APP_SIZE=\"$DOWNLOAD_APP_SIZE\"" > ${APP_DATA_FILE}/${DOWNLOAD_APP_NAME}.conf

    idx=`expr $idx + 1`
done
