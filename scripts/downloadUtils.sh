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
LOG_FILE=""

log_msg() {
  #get current dateandtime
  DateTime=`date "+%m%d%y-%H:%M:%S:%N"`
  STR=""
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
  # echo "[$DateTime] [pid=$$] $STR" >>$LOG_FILE
  echo "[$DateTime] [pid=$$] $STR"
}

get_core_value()
{
    core=""
    if [ -f /tmp/cpu_info ];then
         core=`cat /tmp/cpu_info`
    fi
    if [ ! "$core" ];then
           processor=`cat /proc/cpuinfo | grep Atom| wc -l`
           if [ $processor ] && [ $processor -gt 0 ] ;then
                  core="ATOM"
           fi
           processor=`cat /proc/cpuinfo | grep ARM| wc -l`
           if [ $processor ] && [ $processor -gt 0 ] ;then
                  core="ARM"
           fi
           echo $core > /tmp/cpu_info
    fi
    echo $core
}

