#!/bin/bash
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

# Ticket https://ccp.sys.comcast.net/browse/RDK-21096
# Script generats config file for signing package
# in the format required by RDK App Manager


# Input Arguement

# Destination Path: Specify the destination path for the config file
# Display Name: Application Display name in App Manager GUI
# Cmd Name: Name which XRE server uses in applicationmanager to create any app. For our purpose we can keep same name as that of (a). This is optional
# Binary to start App: Full path of binary/script to start the App. App Manager will invoke this script to start the Application
# Application Type: It can be either pxscene, web apps, native.
# App version: Application Version number. This is optional

DEST_PATH=$1
DISPLAY_NAME=$2
CMD_NAME=$3
APP_LAUNCHER=$4
APP_TYPE=$5
APP_VERSION=$6

usage()
{
    echo "----------------------USAGE--------------------------------"
    echo "USAGE: $0 <DEST_PATH> <DISPLAY_NAME> <CMD_NAME> <APP_LANCHER> <APP_TYPE> <APP_VERSION>"
    echo "<DEST_PATH> : Specify the destination path for the config file"
    echo "<DISPLAY_NAME> : Application Display name in App Manager GUI "
    echo "<CMD_NAME> : Name which XRE server uses in applicationmanager to create any app"
    echo "<APP_LAUNCHER>  : Path to file/binary/script to launch/trigger the app"
    echo "<APP_TYPE> :  It can be either pxscene, web apps, native"
    echo "<APP_VERSION>        : Version of application (optional) "
    echo "----------------------------------------------------------"
}

if [ ! "$DEST_PATH" -o ! "$DISPLAY_NAME" -o ! "$CMD_NAME" -o ! "$APP_LAUNCHER" -o ! "$APP_TYPE" ];then
     echo "Wrong Inputs: [Path: $DEST_PATH, Name: $DISPLAY_NAME, CMD: $CMD_NAME, Launcher: $APP_LAUNCHER, APP_TYPE: $APP_TYPE ]"
     usage
     exit 1
else
     echo "Inputs: [Path: $DEST_PATH, Name: $DISPLAY_NAME, CMD: $CMD_NAME, Launcher: $APP_LAUNCHER, APP_TYPE: $APP_TYPE ]"
fi

# Create config file
confFile="${DEST_PATH}/appmanagerregistry.conf"
echo "{\"applications\":" > $confFile
echo " [" >> $confFile
echo "  {" >> $confFile
echo "   \"displayName\" : \"${DISPLAY_NAME}\"," >> $confFile
echo "   \"cmdName\" : \"${CMD_NAME}\"," >> $confFile
echo "   \"uri\" : \"${APP_LAUNCHER}\"," >> $confFile

# Make app version entry if provided
if [ "$APP_VERSION" != "" ]; then
    echo "   \"applicationType\" : \"${APP_TYPE}\"," >> $confFile
    echo "   \"version\" : \"${APP_VERSION}\" " >> $confFile
else
    echo "   \"applicationType\" : \"${APP_TYPE}\" " >> $confFile
fi

echo "  }" >> $confFile
echo " ]" >> $confFile
echo "}" >> $confFile
