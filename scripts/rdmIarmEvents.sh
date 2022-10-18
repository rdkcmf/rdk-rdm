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

. /etc/include.properties

# RDM IARM status event
IARM_BUS_RDMMGR_EVENTNAME_APP_INSTALLATION_STATUS="RDMAppStatusEvent"
IARM_BUS_RDMMGR_EVENT_APP_INSTALLATION_STATUS=1

# RDM IARM status enums
RDM_PKG_INSTALL_COMPLETE=0
RDM_PKG_INSTALL_ERROR=1
RDM_PKG_DOWNLOAD_COMPLETE=2
RDM_PKG_DOWNLOAD_ERROR=3
RDM_PKG_EXTRACT_COMPLETE=4
RDM_PKG_EXTRACT_ERROR=5
RDM_PKG_VALIDATE_COMPLETE=6
RDM_PKG_VALIDATE_ERROR=7
RDM_PKG_POSTINSTALL_COMPLETE=8
RDM_PKG_POSTINSTALL_ERROR=9
RDM_PKG_UNINSTALL=10
RDM_PKG_INVALID_INPUT=11

broadcastRDMPkgStatus()
{
        PKG_INFO="$1"
        if type IARM_event_sender &> /dev/null; then
            IARM_event_sender "$IARM_BUS_RDMMGR_EVENTNAME_APP_INSTALLATION_STATUS" "$IARM_BUS_RDMMGR_EVENT_APP_INSTALLATION_STATUS" "$(echo -e $PKG_INFO)" >> ${LOG_PATH}/rdm_status.log 2>&1
        fi
}
