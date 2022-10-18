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

if [ -f /etc/device.properties ]; then
        . /etc/device.properties
fi

if [ -f /etc/rdm/downloadUtils.sh ]; then
        source /etc/rdm/downloadUtils.sh
fi

if [ -f /etc/rdm/rdmBundleUtils.sh ]; then
        source /etc/rdm/rdmBundleUtils.sh
fi

if [ -f /etc/rdm/rdmIarmEvents.sh ]; then
        source /etc/rdm/rdmIarmEvents.sh
fi

DIRECT_BLOCK_FILENAME="${DIRECT_BLOCK_FILENAME}_rdmdedl"
CB_BLOCK_FILENAME="${CB_BLOCK_FILENAME}_rdmdedl"
FORCE_DIRECT_ONCE="${FORCE_DIRECT_ONCE}_rdmdedl"

TMP_DWLD_DIR="/tmp"
MOUNT_DWLD_DIR="/media/apps"
RDM_DWLD_DIR="/rdm/downloads"
RDM_SSR_LOCATION="/tmp/.xconfssrdownloadurl"
APP_DATA_FILE="/tmp/.rdm-apps-data/"

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

MAX_APP_VERSIONS_ALLOWED="2"

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
				[ -d "${NVM_APP_DWLD_DIR}/$pkg_name/v${pkg_ver}" ] && rm -rf "${NVM_APP_DWLD_DIR}/$pkg_name/v${pkg_ver}"
				mkdir -p "${NVM_APP_DWLD_DIR}/$pkg_name"
				mv "${APP_DWLD_DIR}" "${NVM_APP_DWLD_DIR}/$pkg_name"
				APP_DWLD_DIR="${NVM_APP_DWLD_DIR}/$pkg_name/v${pkg_ver}"
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
		app_dir=$(dirname $APP_HOME_DIR)
		if [ -f $APP_HOME_DIR/etc/apps/*.json ]; then
			log "Copying metadata to $app_dir"
			cp $APP_HOME_DIR/etc/apps/*.json $app_dir
		fi
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
        app="$1"
        version="$2"

        [ -z "$app" -o -z "$version" ] && return 1

        pkg_home_dir="${MOUNT_DWLD_DIR}/${app}/v${version}"
        pkg_dwld_dir="${MOUNT_DWLD_DIR}${RDM_DWLD_DIR}/${app}/v${version}"

        if [ -d "$pkg_dwld_dir" ]; then
            log "Cleaning up $pkg_dwld_dir"
            rm -rf "${pkg_dwld_dir}"
        fi

        if [ -d "$pkg_home_dir" ]; then
            log "Cleaning up $pkg_home_dir"
            rm -rf "${pkg_home_dir}"
        fi

        return 0
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

        APP_MANIFEST_VERSION=$(cat ${APP_DATA_FILE}/${pkg_name}_${pkg_ver})
        DOWNLOAD_PKG_NAME="${DEVICE_MODEL}_${pkg_name}_${APP_MANIFEST_VERSION}"
        APP_SIGNED_TAR_FILE="${DOWNLOAD_PKG_NAME}-signed.tar"

        APP_DWLD_DIR="${TMP_DWLD_DIR}${RDM_DWLD_DIR}/$pkg_name/v${pkg_ver}"
        APP_HOME_DIR="${TMP_DWLD_DIR}/$pkg_name/v${pkg_ver}/package"

        APP_PACKAGE_FILE="${DOWNLOAD_PKG_NAME}.tar"
        APP_SIGN_FILE="${DOWNLOAD_PKG_NAME}.sig"

        log "Updating ${pkg_name} package to latest version v${pkg_ver}"

        downloadApp $pkg_name
        if [ $? -ne 0 ]; then
                log "Download failed for ${pkg_name} package"
                updatePkgStatus "$RDM_PKG_DOWNLOAD_ERROR"
                uninstallApp "${pkg_name}" "${pkg_ver}"
                if [ $? -eq 0]; then
                    log "Uninstalled ${pkg_name} package version ${pkg_ver}"
                    updatePkgStatus "$RDM_PKG_UNINSTALL"
                fi
                return 1
        fi
        log "Download successful for ${pkg_name} package"

        extractApp
        if [ $? -ne 0 ]; then
                log "Extraction failed for ${pkg_name} package"
                updatePkgStatus "$RDM_PKG_EXTRACT_ERROR"
                uninstallApp "${pkg_name}" "${pkg_ver}"
                if [ $? -eq 0 ]; then
                    log "Uninstalled ${pkg_name} package version ${pkg_ver}"
                    updatePkgStatus "$RDM_PKG_UNINSTALL"
                fi
                return 1
        fi
        log "Extraction successful for ${pkg_name} package"

        installApp $pkg_name
        if [ $? -ne 0 ]; then
                log "Installation failed for ${pkg_name} package"
                updatePkgStatus "$RDM_PKG_EXTRACT_ERROR"
                uninstallApp "${pkg_name}" "${pkg_ver}"
                if [ $? -eq 0 ]; then
                    log "Uninstalled ${pkg_name} package version ${pkg_ver}"
                    updatePkgStatus "$RDM_PKG_UNINSTALL"
                fi
                return 1
        fi
        log "Installation successful for ${pkg_name} package"

        verifyAppSignature
        if [ $? -ne 0 ]; then
                log "Signature verification failed for ${pkg_name} package"
                updatePkgStatus "$RDM_PKG_VALIDATE_ERROR"
                uninstallApp "${pkg_name}" "${pkg_ver}"
                if [ $? -eq 0 ]; then
                    log "Uninstalled ${pkg_name} package version ${pkg_ver}"
                    updatePkgStatus "$RDM_PKG_UNINSTALL"
                fi
                return 1
        fi
        log "Signature verification successful for ${pkg_name} package"

        postVerifyInstall
        if [ $? -ne 0 ]; then
                log "Post-Installation failed for ${pkg_name} package"
                updatePkgStatus "$RDM_PKG_POSTINSTALL_ERROR"
                uninstallApp "${pkg_name}" "${pkg_ver}"
                if [ $? -eq 0 ]; then
                    log "Uninstalled ${pkg_name} package version ${pkg_ver}"
                    updatePkgStatus "$RDM_PKG_UNINSTALL"
                fi
                return 1
        fi
        log "Post-Installation successful for ${pkg_name} package"
}


############################ MAIN APPLICATION ############################

APP_NAME="$1"
pkg_ver_list="$2"

VERSION_LIST=""
for ver in $pkg_ver_list; do
    pkgVer="${ver#*-v}"
    echo "$ver" > ${APP_DATA_FILE}/${APP_NAME}_${pkgVer}
    VERSION_LIST="$pkgVer $VERSION_LIST"
done

RDM_DOWNLOAD_LOCATION=$(getDownloadUrl)
if [ -z $RDM_DOWNLOAD_LOCATION ]; then
    log_msg "RDM download url is not available in both $RDM_SSR_LOCATION and RFC parameter. Exiting"
    updatePkgStatus "$RDM_PKG_INVALID_INPUT"
    exit 1
fi

# Expected input is of the format - "AppName" "1.0 2.0 3.0 4.0 5.0"
if [ -z "$VERSION_LIST" -o -z "$APP_NAME" ]; then
    log "Invalid input. Package name or Package version missing"
    updatePkgStatus "$RDM_PKG_INVALID_INPUT"
    exit 1
fi

log "Input package : $APP_NAME, Input version(s) : $pkg_ver_list"


# Remove any leading and trailing whitespace and store it
input_version_list="$(echo $VERSION_LIST | xargs)"


# Prune input version list to contain only latest max allowed versions
n_input_versions="$(echo $input_version_list | wc -w)"
if [ "$n_input_versions" -gt "$MAX_APP_VERSIONS_ALLOWED" ]; then
        while [ "$n_input_versions" -gt "$MAX_APP_VERSIONS_ALLOWED" ];
        do
                old_ver="$(getOldestVersion $input_version_list)"
                input_version_list="${input_version_list//${old_ver}/}"
                n_input_versions="$(echo $input_version_list | wc -w)"
        done
        input_version_list="$(echo $input_version_list | xargs)"
        log "Latest two versions in the input list are ($input_version_list)"
fi


# Before proceeding, uninstall older versions if more than max allowed versions of the app is installed
APP_CPE_METADATA_FILE="$(find ${MOUNT_DWLD_DIR}/${APP_NAME} -maxdepth 2 -name "*_package.json" | sort | uniq | xargs)"
if [ -n "${APP_CPE_METADATA_FILE}" ]; then
        installed_version_list="$(getInstalledVersions "$APP_CPE_METADATA_FILE")"
        if [ -n "$installed_version_list" ]; then
                n_installed_versions="$(echo $installed_version_list | wc -w)"
                while [ "$n_installed_versions" -gt "$MAX_APP_VERSIONS_ALLOWED" ];
                do
                    old_ver="$(getOldestVersion $installed_version_list)"
                    log "Uninstalling older version $old_ver of $APP_NAME package"
                    uninstallApp "${APP_NAME}" "$old_ver"
                    if [ $? -eq 0 ]; then
                            log "${APP_NAME} package version ${APP_VERSION} uninstalled successfully"
                    else
                            log "${APP_NAME} package version ${APP_VERSION} could not be uninstalled"
                    fi
                    installed_version_list="${installed_version_list//${old_ver}/}"
                    n_installed_versions="$(echo $installed_version_list | wc -w)"
                done
                installed_version_list="$(echo "$installed_version_list" | xargs)"
                log "Installed versions of ${APP_NAME} package are ($installed_version_list)"
        fi
fi


install_list=""
uninstall_list=""

# Prepare install_list
for APP_VERSION in $input_version_list;
do
        APP_DWLD_DIR="${MOUNT_DWLD_DIR}${RDM_DWLD_DIR}/${APP_NAME}/v${APP_VERSION}"
        APP_HOME_DIR="${MOUNT_DWLD_DIR}/${APP_NAME}/v${APP_VERSION}/package"
        APP_MANIFEST_VERSION=$(cat ${APP_DATA_FILE}/${APP_NAME}_${APP_VERSION})
        DOWNLOAD_PKG_NAME="${DEVICE_MODEL}_${APP_NAME}_${APP_MANIFEST_VERSION}"
        APP_PACKAGE_FILE="${DOWNLOAD_PKG_NAME}.tar"
        APP_SIGN_FILE="${DOWNLOAD_PKG_NAME}.sig"

        if (echo "$installed_version_list" | grep -qw "${APP_VERSION}"); then
                log "${APP_NAME} package version ${APP_VERSION} already installed"
                verifyAppSignature
                if [ "$?" -eq "0" ]; then
                        log "Signature verification successful for ${APP_NAME} package version ${APP_VERSION}"
                        updatePkgStatus "$RDM_PKG_INSTALL_COMPLETE"
                else
                        log "Signature verification failed for ${APP_NAME} package version ${APP_VERSION}"
                        uninstallApp "${APP_NAME}" "${APP_VERSION}"
                        log "${APP_NAME} package version ${APP_VERSION} uninstalled successfully"
                        installed_version_list="${installed_version_list//${APP_VERSION}/}"
                        install_list="$install_list ${APP_VERSION}"
                fi
        else
                log "${APP_NAME} package version ${APP_VERSION} not already installed. Checking if it is latest"
                if [ "${APP_VERSION}" = "$(getLatestVersion $installed_version_list ${APP_VERSION})" ]; then
                        log "${APP_NAME} package version ${APP_VERSION} is the latest. Hence installing it"
                        install_list="$install_list ${APP_VERSION}"
                else
                        log "${APP_NAME} package version ${APP_VERSION} is not the latest. Hence not installing it"
                fi
        fi
done

install_list="$(sortVersions $install_list)"
[ -n "$install_list" ] && log "List of package versions to be installed is ($install_list)"

# Prepare uninstall list
if [ -n "$install_list" ]; then
        n_install_versions="$(echo $install_list | wc -w)"
        n_installed_versions="$(echo $installed_version_list | wc -w)"
        if [ "$n_installed_versions" -gt "$n_install_versions" ]; then
                uninstall_list="$(sortVersions $installed_version_list | tr ' ' '\n' | head -n$(expr $n_installed_versions - $n_install_versions))"
        elif [ "$n_install_versions" -eq "$MAX_APP_VERSIONS_ALLOWED" ]; then
                uninstall_list="$(sortVersions $installed_version_list)"
        fi
fi
[ -n "uninstall_list" ] && log "List of package versions to be uninstalled is ($uninstall_list)"

n_uninstall_versions="$(echo $uninstall_list | wc -w)"
uninstall_list_idx=1

for APP_VERSION in $install_list
do
        log "Installing ${APP_NAME} package v${APP_VERSION}"
        updatePackage ${APP_NAME} ${APP_VERSION}

        if [ $? -ne 0 ]; then
            log "${APP_NAME} package version ${APP_VERSION} installation failed"
            updatePkgStatus "$RDM_PKG_INSTALL_ERROR"
        else
            log "${APP_NAME} package version ${APP_VERSION} installed successfully"
            updatePkgStatus "$RDM_PKG_INSTALL_COMPLETE"
            if [ "$uninstall_list_idx" -le "$n_uninstall_versions" ]; then
                uninstall_version="$(echo $uninstall_list | cut -d" " -f$uninstall_list_idx)"
                uninstallApp "${APP_NAME}" "$uninstall_version"
                if [ "$?" -eq "0" ]; then
                    log "${APP_NAME} package version ${uninstall_version} uninstalled successfully"
                    uninstall_list_idx="$(expr $uninstall_list_idx + 1)"
                fi
            fi
        fi
done

