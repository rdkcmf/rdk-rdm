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

if [ -f /etc/include.properties ];then
     . /etc/include.properties
fi

if [ -f /etc/device.properties ];then
     . /etc/device.properties
fi

if [ "$LOG_PATH" ];then
     LOG_FILE="$LOG_PATH/rdm_status.log"
else
     if [ -d /var/log ];then
          if [ -f /var/log/rdm_status.log ];then
               rm -rf /var/log/rdm_status.log
          fi
          LOG_FILE=/var/log/rdm_status.log
     else
          LOG_FILE=/dev/null
     fi
fi

log_msg() {
  #get current dateandtime
  DateTime=`date "+%m%d%y-%H:%M:%S:%N"`
  STR=""
  PID=$$

  #check if parameter non zero size
  if [ -n "$1" ];
  then
    STR="$1"
  else
    DONE=false
    until $DONE ;do
    read IN || DONE=true
    STR=$STR$IN
    done
  fi

  #print log message
  echo "[$DateTime] [pid=$PID] $STR" >>$LOG_FILE
}
