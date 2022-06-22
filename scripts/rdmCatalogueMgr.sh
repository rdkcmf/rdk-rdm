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

if [ -f /etc/rdm/rdmIarmEvents.sh ]; then
    . /etc/rdm/rdmIarmEvents.sh
fi

if [ -f /etc/rdm/loggerUtils.sh ]; then
    . /etc/rdm/loggerUtils.sh
fi

RDM_APP_PATH="/media/apps"
DEFAULT_MANIFEST_PATH="/etc/rdm"
DEFAULT_MANIFEST_FILENAME="rdm-manifest.json"
DEFAULT_RDM_MANIFEST="$DEFAULT_MANIFEST_PATH/$DEFAULT_MANIFEST_FILENAME"
PERSISTENT_MANIFEST_PATH="${RDM_APP_PATH}/rdm/manifests"
PERSISTENT_MANIFEST_FILENAME="${DEVICE_MODEL}_${DEVICE_BRANCH}_${DEFAULT_MANIFEST_FILENAME}"
PERSISTENT_RDM_MANIFEST="$PERSISTENT_MANIFEST_PATH/$PERSISTENT_MANIFEST_FILENAME"
RDM_PKGS_DATA="/tmp/.rdm-pkgs-data.json"
APP_DATA_FILE="/tmp/.rdm-apps-data/"

DECOUPLED_RFC_ENABLED="$(tr181 Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.RDMDecoupledVersionManagement.Enable 2>&1 > /dev/null)"

updatePkgStatus()
{
        APP_INST_STATUS="$1"
        pkg_info="pkg_name:manifests\npkg_version:$manifest_version\npkg_inst_status:$APP_INST_STATUS\npkg_inst_path:$PERSISTENT_MANIFEST_PATH"
        broadcastRDMPkgStatus "$pkg_info"
}

getRDMPackagesData()
{
    JSONFILE="$1"
    fwversion="$2"

    nbuilds=$(getJSONArraySize "$JSONFILE" "/builds")
    idx=0
    while [ $idx -lt $nbuilds ]
    do
        build_names=$(getJSONValue "$JSONFILE" "/builds/$idx/build_name")
        ret="$?"
        if [ $ret -eq 0 ]; then
                if (echo "$build_names" | grep -q "$fwversion"); then
                        rdm_data=$(getJSONValue "$JSONFILE" "/builds/$idx/rdm_packages")
                        if [ $? -eq 0 ]; then
                                echo $rdm_data
                                return 0
                        else
                                log_msg "Error in fetching RDM data for $fwversion from the RDM catalogue"
                                return 1
                        fi
                fi
        fi
        idx=$(expr $idx + 1)
    done
}

######## MAIN #######

# Set default RDM_MANIFEST location
RDM_MANIFEST="$DEFAULT_RDM_MANIFEST"
download_manifest=0

if [ -n "$DECOUPLED_RFC_ENABLED" -a "$DECOUPLED_RFC_ENABLED" = "true" ]; then

    log_msg "RDM Decoupled Version Management feature is enabled"

    xconf_ManifestVer="false"
    if [ -s "/tmp/.xconfRdmCatalogueVersion" ]; then
            rdmCatalogueVersion=$(cat "/tmp/.xconfRdmCatalogueVersion")
            log_msg "Manifest Version from Xconf: $rdmCatalogueVersion"
            # Parse the device branch from rdmCatalogueVersion
            x_branch=$(echo $rdmCatalogueVersion | awk -F "-" '{print $1}')
            # Get minimum version from rdmCatalogueVersion
            x_minVersion=$(echo $rdmCatalogueVersion | awk -F "-" '{print $2}')
            if [ -n "$x_branch" -a "$x_branch" = "$DEVICE_BRANCH" ]; then
                if [ -n "$x_minVersion" ]; then
                    xconf_ManifestVer="true"
                else
                    log_msg "RDM catalogue version received from XCONF is not a valid version. Exiting"
                    exit 1
                fi
	    else
                    log_msg "RDM catalogue version received from XCONF does not belong to $DEVICE_BRANCH. Exiting"
	            exit 1
            fi
    else
            log_msg "RDM catalogue version not received from XCONF. Hence parsing $RDM_MANIFEST"
    fi

    if [ "$xconf_ManifestVer" = "true" ]; then

        download_manifest=1

        if [ -s "/opt/rdmManifest.conf" ] && [ $BUILD_TYPE != "prod" ]; then
                log_msg "Found an override manifest in /opt/rdmManifest.conf"
	        PERSISTENT_MANIFEST_FILENAME=$(cat "/opt/rdmManifest.conf")
		manifest_format=${DEVICE_MODEL}_${DEVICE_BRANCH}_rdm-manifest_
		echo $PERSISTENT_MANIFEST_FILENAME | grep -q "^$manifest_format.*.json"
		if [ $? -eq 0 ]; then
                        PERSISTENT_RDM_MANIFEST="$PERSISTENT_MANIFEST_PATH/$PERSISTENT_MANIFEST_FILENAME"
	        else
			log_msg "Override file (/opt/rdmManifest.conf) contains an invalid manifest name. Exiting"
		        exit 1
	        fi
        fi

        defaultManifestVer="false"
        if [ -f "$DEFAULT_RDM_MANIFEST" ]; then
                default_ManifestVersion=$(getJSONValue "$DEFAULT_RDM_MANIFEST" "manifest_version")
                log_msg "Manifest Version from $DEFAULT_RDM_MANIFEST: $default_ManifestVersion"
                d_minVersion=$(echo $default_ManifestVersion | awk -F "-" '{print $2}')
                if [ -n "$d_minVersion" ]; then
                        defaultManifestVer="true"
                fi
        fi

        persistentManifestVer="false"
        if [ -f "$PERSISTENT_RDM_MANIFEST" ]; then
                persistent_ManifestVersion=$(getJSONValue "$PERSISTENT_RDM_MANIFEST" "manifest_version")
                log_msg "Manifest Version from $PERSISTENT_RDM_MANIFEST: $persistent_ManifestVersion"
                p_minVersion=$(echo $persistent_ManifestVersion | awk -F "-" '{print $2}')
                if [ -n "$p_minVersion" ]; then
                        persistentManifestVer="true"
                fi
        else
	        log_msg "RDM caltalogue was not available in $PERSISTENT_MANIFEST_PATH"
        fi

        if [ "$defaultManifestVer" = "true" ] && [ "$persistentManifestVer" = "true" ]; then
                if [ "$p_minVersion" -ge "$x_minVersion" ] && [ "$p_minVersion" -ge "$d_minVersion" ]; then
                        log_msg "CPE already having the latest RDM catalogue in $PERSISTENT_RDM_MANIFEST"
                        RDM_MANIFEST="$PERSISTENT_RDM_MANIFEST"
	                download_manifest=0
	        elif [ "$d_minVersion" -ge "$x_minVersion" ]; then
                        log_msg "CPE already having the latest RDM catalogue in $DEFAULT_RDM_MANIFEST"
                        download_manifest=0
	        fi
        elif [ "$defaultManifestVer" = "true" ]; then
                if [ "$d_minVersion" -ge "$x_minVersion" ]; then
                        log_msg "CPE already having the latest RDM catalogue in $DEFAULT_RDM_MANIFEST"
	                download_manifest=0
	        fi
        fi
    fi
else
	log_msg "RDM Decoupled Version Management feature is disabled"
fi


if [ "$download_manifest" -eq "1" ]; then

    # Download RDM catalogue
    DOWNLOAD_MANIFEST=$(echo $PERSISTENT_MANIFEST_FILENAME | sed s/".json"//)
    RDM_MANIFEST="${PERSISTENT_RDM_MANIFEST}"

    #Remove the cloud manifest if it is aleady available
    [ ! -d "$PERSISTENT_RDM_PATH" ] && mkdir -p "$PERSISTENT_RDM_PATH"
    [ -f "$RDM_MANIFEST" ] && rm -f "$RDM_MANIFEST"

    time sh /etc/rdm/downloadMgr.sh "manifests" "$RDM_APP_PATH/rdm" "openssl" "tar" "$DOWNLOAD_MANIFEST"

    if [ $? -ne 0 ]; then
        log_msg "Cloud manifest download failed"
	updatePkgStatus "$RDM_PKG_DOWNLOAD_ERROR"
	exit 1
    fi
fi

log_msg "RDM Manifest = $RDM_MANIFEST"

fw_version=$(downloadApp_getFWVersion)
rdm_pkgs_data=$(getRDMPackagesData "$RDM_MANIFEST" "$fw_version")
if [ $? -ne 0 -o -z "$rdm_pkgs_data" ]; then
    log_msg "RDM packages data for $fw_version is not found in RDM manifest. Exiting"
    exit 1
fi

echo $rdm_pkgs_data > $RDM_PKGS_DATA
num_rdm_packages=$(getJSONArraySize "$RDM_PKGS_DATA" "/")

if [ $? -ne 0 -o -z "$num_rdm_packages" ]; then
    log_msg "Unable to get the RDM Manifest json array size. Exiting"
    exit 1
fi

log_msg "Number of packages found in $RDM_MANIFEST is $num_rdm_packages"

mkdir -p "$APP_DATA_FILE"

idx=0
while [ "$idx" -lt "$num_rdm_packages" ];
do
    DOWNLOAD_APP_NAME=$(getJSONValue "$RDM_PKGS_DATA" "/$idx/app_name")
    DOWNLOAD_APP_ONDEMAND=$(getJSONValue "$RDM_PKGS_DATA" "/$idx/dwld_on_demand")
    DOWNLOAD_METHOD_CONTROLLER=$(getJSONValue "$RDM_PKGS_DATA" "/$idx/dwld_method_controller")
    IS_VERSIONED=$(getJSONValue "$RDM_PKGS_DATA" "/$idx/is_versioned")

    if [ "$IS_VERSIONED" = "true" ]; then
        nversions=$(getJSONArraySize "$RDM_PKGS_DATA" "/$idx/packages")
	vidx=0
	DOWNLOAD_PKG_VERSION=""
	DOWNLOAD_APP_SIZE=""
	while [ "$vidx" -lt "$nversions" ];
	do
            pkg_ver=$(getJSONValue "$RDM_PKGS_DATA" "/$idx/packages/$vidx/pkg_version")
            pkg_size=$(getJSONValue "$RDM_PKGS_DATA" "/$idx/packages/$vidx/pkg_size")
	    PKG_VERSION="$pkg_ver $DOWNLOAD_PKG_VERSION "
	    APP_SIZE="$pkg_size $DOWNLOAD_PKG_SIZE "
	    DOWNLOAD_PKG_VERSION=$(echo "$PKG_VERSION" | xargs)
	    DOWNLOAD_APP_SIZE=$(echo "$APP_SIZE" | xargs)
	    DOWNLOAD_PKG_NAME=""
	    vidx=$(expr $vidx + 1)
	done
    else
	    DOWNLOAD_PKG_NAME=$(getJSONValue "$RDM_PKGS_DATA" "/$idx/pkg_name")
            DOWNLOAD_PKG_VERSION=$(getJSONValue "$RDM_PKGS_DATA" "/$idx/pkg_version")
            DOWNLOAD_APP_SIZE=$(getJSONValue "$RDM_PKGS_DATA" "/$idx/pkg_size")
    fi

    echo -e "DOWNLOAD_APP_NAME=\"$DOWNLOAD_APP_NAME\"\nDOWNLOAD_APP_ONDEMAND=\"$DOWNLOAD_APP_ONDEMAND\"\nDOWNLOAD_METHOD_CONTROLLER=\"$DOWNLOAD_METHOD_CONTROLLER\"\nIS_VERSIONED=\"$IS_VERSIONED\"\nDOWNLOAD_PKG_NAME=\"$DOWNLOAD_PKG_NAME\"\nDOWNLOAD_PKG_VERSION=\"$DOWNLOAD_PKG_VERSION\"\nDOWNLOAD_APP_SIZE=\"$DOWNLOAD_APP_SIZE\"" > ${APP_DATA_FILE}/${DOWNLOAD_APP_NAME}.conf

    idx=`expr $idx + 1`
done
