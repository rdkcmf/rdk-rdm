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
        source /etc/device.properties
fi

if [ "$DEVICE_TYPE" = "broadband" ]; then
        BUNDLE_METADATA_PATH="/nvram/etc/certs"
else
        BUNDLE_METADATA_PATH="/media/apps/etc/certs"
fi

VERSION_SORT_TMPDIR="/tmp/.version-sort"
JSONQUERY="/usr/bin/jsonquery"
PKG_METADATA_NAME="name"
PKG_METADATA_VER="version"
PKG_METADATA_LIST="contents"
PKG_METADATA_SIZE="size"
PKG_METADATA_INSTALL="installScript"
RDM_APP_PATH="/media/apps"

sortVersions()
{
    ret=""

    mkdir -p ${VERSION_SORT_TMPDIR}

    for ver in "$@"; do
        touch "${VERSION_SORT_TMPDIR}/$ver"
    done

    ret="$(ls -v ${VERSION_SORT_TMPDIR} | xargs)"

    rm -rf ${VERSION_SORT_TMPDIR}

    echo "$ret"
}


getOldestVersion()
{
    [ "$#" -lt 1 ] && return

    sortedList="$(sortVersions $@)"

    old_ver="$(echo $sortedList | tr ' ' '\n' | head -n1)"

    echo "$old_ver"
}


getLatestVersion()
{
    [ "$#" -lt 1 ] && return

    sortedList="$(sortVersions $@)"

    latest_ver="$(echo $sortedList | tr ' ' '\n' | tail -n1)"

    echo "$latest_ver"
}


getInstalledVersions()
{
    APP_CPE_METADATA_FILE=$1

    installed_vlist=""
    for metadata_file in $APP_CPE_METADATA_FILE
    do
        vlist=$(getJSONValue "$metadata_file" "version")
        installed_vlist="$vlist $installed_vlist"
    done

    installedVersions=$(echo "$installed_vlist" | xargs)
    echo $installedVersions
}

getPkgMetadata()
{
        data=$($JSONQUERY -f $1 -p $2)
        if [ $? -eq 0 ]; then
                echo "$data"
        else
                log "getPkgMetadata() failed to fetch $2"
                echo ""
        fi
}

getInstalledPackages()
{
    pkgList=""
    PWD=$(pwd)
    cd $RDM_APP_PATH
    dir_list=$(ls -d */ | tr -d "/")
    for app in $dir_list; do
        APP_MANIFEST=$RDM_APP_PATH/$app/${app}_cpemanifest
        if [ -f "$APP_MANIFEST" ]; then
            pkgList="$app $pkgList"
        else
            APP_CPE_METADATA_FILE="$(find ${RDM_APP_PATH}/${app} -maxdepth 2 -name "*_package.json" | sort | uniq | xargs)"
            if [ -f "$APP_CPE_METADATA_FILE" ]; then
                pkgList="$app $pkgList"
            fi
        fi
    done
    cd $PWD
    installedPackages=$(echo $pkgList | xargs)
    echo "$installedPackages"
}

## sanityCheck(bundleExtractDir)
### Sanity check whether all required file (padding file, signature file, manifest file)
### are available in the bundle
###
### Arguments:
### bundleExtractDir - Path where signed bundle is extracted
###
### Return value:
### Type - numeric
### 1 - Failure, 0 - Success
sanityCheckBundle()
{
        bundleExtractDir=$1
        app_dir=$(dirname $bundleExtractDir)
        app_name=$(basename $app_dir)
        log "Sanity check contents of $app_name at $bundleExtractDir"

        if [ -d "$bundleExtractDir" ]; then
                if [ -f "$bundleExtractDir/$APP_PADDING_FILE" -a -f "$bundleExtractDir/$APP_MANIFEST_FILE" -a -f "$bundleExtractDir/$APP_PACKAGE_FILE" -a -f "$bundleExtractDir/$APP_SIGN_FILE" ]; then
                        log "Sanity check completed"
                        return 0
                fi
        fi
        log "Sanity check failed. Missing critical files"
        return 1
}


### extractBundle(pathToBundle, pathToExtract)
### Extracts bundle at pathToBundle to pathToExtract
###
### Arguments:
### pathToBundle - Path to the bundle tar file
### pathToExtract - Path to extract the bundle
###
### Return value:
### Type - numeric
### 1 - Failure, 0 - Success
extractBundle()
{
        pathToBundle=$1
        pathToExtract=$2

        if [ -n "$pathToBundle" -a -n "$pathToExtract" -a -f "$pathToBundle" ]; then
                log "Extracting $pathToBundle to $pathToExtract"
                mkdir -p $pathToExtract
                tar -xvf $pathToBundle -C $pathToExtract 2>&1
                if [ $? -ne 0 ]; then
                        log "Extraction Failed..! Clearing $pathToExtract"
                        rm -rf $pathToExtract/*
                        return 1
                fi
                log "$(basename $pathToBundle) extraction completed"
                return 0
        else
                log "Invalid input"
                return 1
        fi
}

