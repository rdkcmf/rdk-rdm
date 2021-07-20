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

JSONQUERY="/usr/bin/jsonquery"
PKG_METADATA_NAME="name"
PKG_METADATA_VER="version"
PKG_METADATA_LIST="contents"
PKG_METADATA_SIZE="size"
PKG_METADATA_INSTALL="installScript"

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
        app_name=$(basename $bundleExtractDir)
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

