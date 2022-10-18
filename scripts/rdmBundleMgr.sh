#!/bin/sh
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2021 RDK Management
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

if [ -f /etc/rdm/downloadUtils.sh ]; then
		source /etc/rdm/downloadUtils.sh
fi

if [ -f /etc/rdm/rdmBundleUtils.sh ]; then
        source /etc/rdm/rdmBundleUtils.sh
fi

if [ -f /etc/rdm/rdmIarmEvents.sh ]; then
        source /etc/rdm/rdmIarmEvents.sh
fi

DIRECT_BLOCK_FILENAME="${DIRECT_BLOCK_FILENAME}_rdmbdl"
CB_BLOCK_FILENAME="${CB_BLOCK_FILENAME}_rdmbdl"
FORCE_DIRECT_ONCE="${FORCE_DIRECT_ONCE}_rdmbdl"

TMP_DWLD_DIR="/tmp"
MOUNT_DWLD_DIR="/media/apps"
RDM_DWLD_DIR="/rdm/downloads"
RDM_SSR_LOCATION="/tmp/.xconfssrdownloadurl"

APP_NAME=""
APP_VERSION=""
APP_HOME_DIR=""
APP_SIGNED_TAR_FILE=""
APP_PACKAGE_FILE=""
APP_SIGN_FILE=""
APP_PADDING_FILE="pkg_padding"
APP_MANIFEST_FILE="pkg_cpemanifest"
APP_METADATA_FILE="package.json"
APP_CPE_METADATA_FILE=""

RFC_DOWNLOAD_LOCATION=""
RDM_DOWNLOAD_LOCATION=""
RDM_BUNDLE_LIST=""

log()
{
	log_msg "[BUNDLE] $@"
}


downloadApp()
{
		# Below parameters have to be set for applicationDownload() to process
		DOWNLOAD_APP_MODULE="$1"
		DOWNLOAD_LOCATION="$APP_DWLD_DIR"
		HTTP_CODE="$APP_DWLD_DIR/http_code"

		log "Downloading $APP_SIGNED_TAR_FILE to $DOWNLOAD_LOCATION"

        [ -d "$APP_DWLD_DIR" ] && rm -rf $APP_DWLD_DIR
        mkdir -p $APP_DWLD_DIR

		applicationDownload "$RDM_DOWNLOAD_LOCATION/$APP_SIGNED_TAR_FILE" "bundle"
        return $?
}


extractApp()
{
        log "Extracting $APP_SIGNED_TAR_FILE & $APP_PACKAGE_FILE to $APP_DWLD_DIR"

        extractBundle "$APP_DWLD_DIR/$APP_SIGNED_TAR_FILE" $APP_DWLD_DIR
        if [ $? -ne 0 ]; then
                return 1
        fi

        sanityCheckBundle $APP_DWLD_DIR
        if [ $? -ne 0 ]; then
                return 1
        fi

        extractBundle "$APP_DWLD_DIR/$APP_PACKAGE_FILE" $APP_DWLD_DIR
        if [ $? -ne 0 ]; then
                return 1
        fi

        return 0
}


installApp()
{
        app=$1

        PWD=$(pwd)
        cd $APP_DWLD_DIR


        if [ -f "$APP_METADATA_FILE" ]; then
                package_list=$(getPkgMetadata $APP_METADATA_FILE $PKG_METADATA_LIST | sed -e 's/^..//' -e 's/..$//' | tr "\"," " " | xargs)
                package_size=$(getPkgMetadata $APP_METADATA_FILE $PKG_METADATA_SIZE )
        else
                log "$APP_METADATA_FILE missing for $app"
                return 1
        fi

		# Get app installation path
		if [ -n "$package_size" ]; then
			log "Package size for $pkg_name is $package_size"
			log "Fetching app installation path based on the size"

			sh /etc/rdm/getRdmDwldPath.sh "$pkg_name" "$package_size"
			if [ $? -eq 0 ]; then
				NVM_APP_DWLD_DIR="${MOUNT_DWLD_DIR}${RDM_DWLD_DIR}"
				[ -d "${NVM_APP_DWLD_DIR}/$pkg_name" ] && rm -rf "${NVM_APP_DWLD_DIR}/$pkg_name"
				mkdir -p "${NVM_APP_DWLD_DIR}"
				mv "${APP_DWLD_DIR}" "${NVM_APP_DWLD_DIR}"
				APP_DWLD_DIR="${NVM_APP_DWLD_DIR}/$pkg_name"
				APP_HOME_DIR="${MOUNT_DWLD_DIR}/$pkg_name"
				cd $APP_DWLD_DIR
			fi
		else
			log "Missing package size"
			return 1
		fi

        log "Installing $app to $APP_HOME_DIR"
        [ -d "$APP_HOME_DIR" ] && rm -rf "${APP_HOME_DIR}/*"
        mkdir -p $APP_HOME_DIR

        if [ ! -d "$APP_HOME_DIR" ]; then
				log "Failure in creating $APP_HOME_DIR"
                return 1
        fi

        if [ $? -eq 0 -a -n "$package_list" ]; then
                log "Package contents fetched. Listing it - $package_list"
                for tarfile in $package_list
                do
                        if [ -f "$tarfile" ]; then
                                log "$tarfile found in package"
                                extractBundle $tarfile $APP_HOME_DIR
                                if [ $? -ne 0 ]; then
                                        cd ${PWD}
                                        return 1
                                fi
                        else
                                log "$tarfile not found in package"
                        fi
                done
        else
                log "Missing package contents"
                return 1
        fi

        cd ${PWD}

        return 0
}


verifyAppSignature()
{
        log "Calling /etc/rdm/opensslVerifier.sh for signature verification"
        sh /etc/rdm/opensslVerifier.sh "${APP_DWLD_DIR}" "${APP_PACKAGE_FILE}" "${APP_SIGN_FILE}" "kms" "$APP_HOME_DIR" "1"
        return $?
}


postVerifyInstall()
{
		log "Fetching install script from package metadata"
		script=$(getPkgMetadata "${APP_DWLD_DIR}/${APP_METADATA_FILE}" $PKG_METADATA_INSTALL)

		if [ -z "$script" ]; then
			log "No install script found"
			return 0
		else
			script="${APP_HOME_DIR}/${script}"
        	log "Executing install script $script with arguments $APP_HOME_DIR"
            sh $script "$APP_HOME_DIR" >> $LOG_FILE 2>&1
        	return $?
		fi
}


updatePkgStatus()
{
        APP_INST_STATUS="$1"
        pkg_info="pkg_name:$APP_NAME\npkg_version:$APP_VERSION\npkg_inst_status:$APP_INST_STATUS\npkg_inst_path:$APP_HOME_DIR"
        broadcastRDMPkgStatus "$pkg_info"
}


updatePackage()
{
        pkg_name=$1
        pkg_ver=$2

        APP_SIGNED_TAR_FILE="${pkg_name}_${pkg_ver}-signed.tar"

        APP_DWLD_DIR="${TMP_DWLD_DIR}${RDM_DWLD_DIR}/$pkg_name"
		APP_HOME_DIR="${TMP_DWLD_DIR}/$pkg_name"

        APP_PACKAGE_FILE="${pkg_name}_${pkg_ver}.tar"
        APP_SIGN_FILE="${pkg_name}_${pkg_ver}.sig"

        log "Updating ${pkg_name} package to latest version v${pkg_ver}"

		downloadApp $pkg_name
        if [ $? -ne 0 ]; then
				log "Download failed for ${pkg_name} package"
				updatePkgStatus "$RDM_PKG_DOWNLOAD_ERROR"
                rm -rf ${APP_DWLD_DIR}
                return 1
        fi
        log "Download successful for ${pkg_name} package"

        extractApp
        if [ $? -ne 0 ]; then
				log "Extraction failed for ${pkg_name} package"
				updatePkgStatus "$RDM_PKG_EXTRACT_ERROR"
                rm -rf ${APP_DWLD_DIR}
                return 1
        fi
        log "Extraction successful for ${pkg_name} package"

        installApp $pkg_name
        if [ $? -ne 0 ]; then
				log "Installation failed for ${pkg_name} package"
				updatePkgStatus "$RDM_PKG_EXTRACT_ERROR"
                rm -rf ${APP_DWLD_DIR}
                rm -rf ${APP_HOME_DIR}
                return 1
        fi
        log "Installation successful for ${pkg_name} package"

        verifyAppSignature
        if [ $? -ne 0 ]; then
                log "Signature verification failed for ${pkg_name} package"
				updatePkgStatus "$RDM_PKG_VALIDATE_ERROR"
                rm -rf ${APP_DWLD_DIR}
                rm -rf ${APP_HOME_DIR}
                return 1
        fi
        log "Signature verification successful for ${pkg_name} package"

        postVerifyInstall
        if [ $? -ne 0 ]; then
                log "Post-Installation failed for ${pkg_name} package"
				updatePkgStatus "$RDM_PKG_POSTINSTALL_ERROR"
                rm -rf ${APP_DWLD_DIR}
                rm -rf ${APP_HOME_DIR}
                return 1
        fi
        log "Post-Installation successful for ${pkg_name} package"
}


############################ MAIN APPLICATION ############################

RDM_BUNDLE_LIST="$1"
RDM_DOWNLOAD_LOCATION="$2"

RDM_DOWNLOAD_LOCATION=$(getDownloadUrl)
if [ -z $RDM_DOWNLOAD_LOCATION ]; then
    log_msg "RDM download url is not available in both $RDM_SSR_LOCATION and RFC parameter. Exiting"
    updatePkgStatus "$RDM_PKG_INVALID_INPUT"
    exit 1
fi

if [ -z "$RDM_BUNDLE_LIST" ]; then
    log "RDM Bundle list empty. Exiting"
    updatePkgStatus "$RDM_PKG_INVALID_INPUT"
    exit 1
fi

log "RDM Bundle list: $RDM_BUNDLE_LIST"
log "RDM Download URL: $RDM_DOWNLOAD_LOCATION"

failCount=0

# Remove any leading and trailing whitespace and store it
RDM_BUNDLE_LIST="$(echo $RDM_BUNDLE_LIST | xargs | tr ',' ' ')"

# Loop throught the list of packages and its version
# Expected input is of the format - "ABun:AVer BBun:Bver"

for bund_vers in $RDM_BUNDLE_LIST
do
        if [ -n "$bund_vers" ]; then
                cloud_bundle_name=$(echo $bund_vers | awk -F":" '{print $1}')
                cloud_bundle_ver=$(echo $bund_vers | awk -F":" '{print $2}')
                APP_NAME="$cloud_bundle_name"
                APP_VERSION="$cloud_bundle_ver"
                if [ -z "$cloud_bundle_name" -o -z "$cloud_bundle_ver" ]; then
                        log "Invalid input - $bund_vers. Package name or Package version missing"
                        updatePkgStatus "$RDM_PKG_INVALID_INPUT"
                        continue
                fi

                log "Package name: $cloud_bundle_name and Package version: $cloud_bundle_ver"

                # Check if the package is already installed. If so compare the version
                if [ -f "${BUNDLE_METADATA_PATH}/${cloud_bundle_name}_package.json" ]; then
                        log "Metadata for ${cloud_bundle_name} package found in ${BUNDLE_METADATA_PATH}"
                        APP_CPE_METADATA_FILE="${BUNDLE_METADATA_PATH}/${cloud_bundle_name}_package.json"
                elif [ -f "/etc/certs/${cloud_bundle_name}_package.json" ]; then
                        log "Metadata for ${cloud_bundle_name} package found in /etc/certs"
                        APP_CPE_METADATA_FILE="/etc/certs/${cloud_bundle_name}_package.json"
                else
                        log "Metadata for ${cloud_bundle_name} package not found"
                fi

                if [ -n "$APP_CPE_METADATA_FILE" ]; then
                        cpe_bundle_ver=$(getPkgMetadata $APP_CPE_METADATA_FILE $PKG_METADATA_VER)
                        if [ -n "$cpe_bundle_ver" ]; then
                                log "Found ${cloud_bundle_name} package of version ${cpe_bundle_ver} already installed in CPE"
                                if [ "x$cloud_bundle_ver" != "x$cpe_bundle_ver" ]; then
                                        log "CPE package version ("$cpe_bundle_ver") and Requested package version ("$cloud_bundle_ver") are different for ${cloud_bundle_name}"
                                else
                                        log "CPE package version ("$cpe_bundle_ver") and Requested package version ("$cloud_bundle_ver") are same for ${cloud_bundle_name}. Validate the package"
                                        verifyAppSignature
                                        if [ "$?" -eq "0" ]; then
                                                log "Signature verification successful for ${cloud_bundle_name} package version ${cloud_bundle_ver}"
                                                updatePkgStatus "$RDM_PKG_INSTALL_COMPLETE"
                                                continue
                                        else
                                                log "Signature verification failed for ${cloud_bundle_name} package version ${cloud_bundle_ver}"
                                                rm -rf ${APP_DWLD_DIR}
                                                rm -rf ${APP_HOME_DIR}
                                        fi
                                fi

                        else
                                log "Could not fetch version for ${cloud_bundle_name} package. Hence invalidating it"
                        fi
                else
                        log "${cloud_bundle_name} package not installed already in CPE"
                fi

                log "Installing ${cloud_bundle_name} package v${cloud_bundle_ver}"

                updatePackage ${cloud_bundle_name} ${cloud_bundle_ver}
                if [ $? -ne 0 ]; then
                        log "${cloud_bundle_name} package installation failed"
                        updatePkgStatus "$RDM_PKG_INSTALL_ERROR"
                        failCount=`expr $failCount + 1`
                else
                        log "${cloud_bundle_name} package installed successfully"
                        updatePkgStatus "$RDM_PKG_INSTALL_COMPLETE"
                fi
        fi
done

exit $failCount
