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
				APP_HOME_DIR="${MOUNT_DWLD_DIR}/${pkg_name}/v${pkg_ver}/package"
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


uninstallApp()
{
		version="$1"
		[ -z "$version" ] && return 1

		pkg_dir="${MOUNT_DWLD_DIR}/${APP_NAME}/v${version}"

		if [ -d "$pkg_dir" ]; then
			log "Removing $pkg_dir"
			rm -rf "${pkg_dir}"
		fi

		return $?
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

APP_NAME="$1"
VERSION_LIST="$2"

RDM_DOWNLOAD_LOCATION=$(getDownloadUrl)
if [ -z $RDM_DOWNLOAD_LOCATION ]; then
    log_msg "RDM download url is not available in both $RDM_SSR_LOCATION and RFC parameter. Exiting"
    exit 1
fi

# Expected input is of the format - "AppName" "1.0 2.0 3.0 4.0 5.0"
if [ -z "$VERSION_LIST" -o -z "$APP_NAME" ]; then
        log "Invalid input. Package name or Package version missing"
	updatePkgStatus "$RDM_PKG_INVALID_INPUT"
        exit 1
fi

log "RDM versioned package: $APP_NAME, version list: $VERSION_LIST"

# Remove any leading and trailing whitespace and store it
version_list="$(echo $VERSION_LIST | xargs)"

n_versions=$(echo $version_list | wc -w)
log "Number of versions passed through input: $n_versions"

# If number of versions passed through input is greater than two,
# then prune the older versions & install only the latest two versions

if [ $n_versions -gt 2 ]; then
	log "Prune the older versions from input"
	while [ $n_versions -gt 2 ];
        do
                old_ver=$(getOlderVersion $version_list)
                version_list=${version_list//${old_ver}/}
                n_versions=$(echo $version_list | wc -w)
        done
        version_list=$(echo $version_list | xargs)

	log "Latest two versions from input are $version_list"
fi

for ver in $version_list
do
        APP_VERSION=$ver
        if [ -d "${MOUNT_DWLD_DIR}/$APP_NAME" ]; then
            APP_CPE_METADATA_FILE="$(find ${MOUNT_DWLD_DIR}/${APP_NAME} -maxdepth 2 -name "*_package.json" | sort | uniq | xargs)"
        else
            log "Metadata for ${APP_NAME} package not found"
        fi

        if [ -n "${APP_CPE_METADATA_FILE}" ]; then
            installed_vlist=$(getInstalledVersions "$APP_CPE_METADATA_FILE")
            installed_verCount=$(echo $installed_vlist | wc -w)
            if [[ "$installed_vlist" =~ .*"$APP_VERSION".* ]]; then
                log "Requested package version ("$APP_VERSION") for ${APP_NAME} package already installed in CPE. No update required"
                continue
            elif [ $installed_verCount -eq 2 ]; then
                verList="$installed_vlist $APP_VERSION"
                old_ver=$(getOlderVersion $verList)
                if [ "$old_ver" = "$APP_VERSION" ]; then
                    log "Requested package version ("$APP_VERSION") for ${APP_NAME} package is older. CPE is already installed with latest versions ($installed_vlist). Hence No update required"
		    continue
                else
                    log "${APP_NAME} package of version ${APP_VERSION} not installed already in CPE"
		    log "Installing ${APP_NAME} package v${APP_VERSION}"
		    updatePackage ${APP_NAME} ${APP_VERSION}
                fi
            else
                log "${APP_NAME} package of version ${APP_VERSION} not installed already in CPE"
                log "Installing ${APP_NAME} package v${APP_VERSION}"
		updatePackage ${APP_NAME} ${APP_VERSION}
            fi
        else
            log "Installing ${APP_NAME} package v${APP_VERSION}"
            updatePackage ${APP_NAME} ${APP_VERSION}
        fi

        if [ $? -ne 0 ]; then
            log "${APP_NAME} package of version ${APP_VERSION} installation failed"
            updatePkgStatus "$RDM_PKG_INSTALL_ERROR"
	    exit 1
        else
            log "${APP_NAME} package of version ${APP_VERSION} installed successfully"
            updatePkgStatus "$RDM_PKG_INSTALL_COMPLETE"
        fi
done


# Ensure box is installed with latest two versions
APP_CPE_METADATA_FILE="$(find ${MOUNT_DWLD_DIR}/${APP_NAME} -maxdepth 2 -name "*_package.json" | sort | uniq | xargs)"
if [ -n "${APP_CPE_METADATA_FILE}" ]; then
        installedVersions=$(getInstalledVersions "$APP_CPE_METADATA_FILE")
        n_versions=$(echo $installedVersions | wc -w)
        while [ $n_versions -gt 2 ];
        do
            old_ver=$(getOlderVersion $installedVersions)
            log "uninstalling older version $old_ver of $APP_NAME"
            uninstallApp "$old_ver"
            installedVersions=${installedVersions//${old_ver}/}
            n_versions=$(echo $installedVersions | wc -w)
        done

        installedVersions=$(echo "$installedVersions" | xargs)
        log "Versions available in CPE for ${APP_NAME}: $installedVersions"
fi
