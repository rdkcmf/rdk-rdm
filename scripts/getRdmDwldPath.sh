#!/bin/sh

if [ -f /etc/rdm/loggerUtils.sh ];then
    . /etc/rdm/loggerUtils.sh
fi

DOWNLOAD_APP_MODULE="$1"
APP_MOUNT_PATH="/media/apps"
TMP_MOUNT_PATH="/tmp"
APPLN_HOME_PATH="/media/apps/$DOWNLOAD_APP_MODULE"
APPLN_TMP_HOME_PATH="/tmp/$DOWNLOAD_APP_MODULE"

if [ -n "$2" ]; then
	DOWNLOAD_APP_SIZE="$2"
else
	DOWNLOAD_APP_SIZE=`/usr/bin/jsonquery -f /etc/rdm/rdm-manifest.json  --path=//packages/$DOWNLOAD_APP_MODULE/app_size`
fi
log_msg "Meta-data: package size: $DOWNLOAD_APP_SIZE"


mount_tmpfs_for_app()
{
    sizeVal=$DOWNLOAD_APP_SIZE
    scale=`echo "${sizeVal#"${sizeVal%?}"}"`
    value=`echo ${sizeVal%?}`

    floatNum="${value//[^.]}"
    if [ $floatNum ];then
        factor=1024
        case $scale in
            "G"|"g")
                log_msg "App Size is in GigaBytes"
                t=$(echo $factor $value | awk '{printf "%4.3f\n",$1*$2}')
                tx=`echo $t | cut -d '.' -f1`
                t=`expr $tx + 1`
                FINAL_DOWNLOAD_APP_SIZE=${t}M
                log_msg "App Size converted from $DOWNLOAD_APP_SIZE to $FINAL_DOWNLOAD_APP_SIZE"
                ;;
            "M"|"m")
                log_msg "App Size is in MegaBytes"
                t=$(echo $factor $value | awk '{printf "%4.3f\n",$1*$2}')
                tx=`echo $t | cut -d '.' -f1`
                t=`expr $tx + 1`
                FINAL_DOWNLOAD_APP_SIZE=${t}K
                log_msg "App Size converted from $DOWNLOAD_APP_SIZE to $FINAL_DOWNLOAD_APP_SIZE"
                ;;
            "K"|"k")
                log_msg "App Size is in KiloBytes"
                t=$(echo $factor $value | awk '{printf "%4.3f\n",$1*$2}')
                tx=`echo $t | cut -d '.' -f1`
                t=`expr $tx + 1`
                FINAL_DOWNLOAD_APP_SIZE=${t}B
                log_msg "App Size converted from $DOWNLOAD_APP_SIZE to $FINAL_DOWNLOAD_APP_SIZE"
                ;;
            "*")
                log_msg "Wrong Measurement Unit for App Size (nB/nK/nM/nG)"
                ;;
        esac
    else
        FINAL_DOWNLOAD_APP_SIZE=$value$scale
        log_msg "App Size is $FINAL_DOWNLOAD_APP_SIZE"
    fi

    if [ -d $APPLN_TMP_HOME_PATH ];then rm -rf $APPLN_TMP_HOME_PATH/* ; else mkdir $APPLN_TMP_HOME_PATH ; fi
    mountFlag=`mount | grep $APPLN_TMP_HOME_PATH`
    if [ "$mountFlag" ];then umount $APPLN_TMP_HOME_PATH ; fi
    mount -t tmpfs -o size=$FINAL_DOWNLOAD_APP_SIZE -o mode=544 tmpfs $APPLN_TMP_HOME_PATH

    log_msg "Mounted tmpfs on $APPLN_TMP_HOME_PATH"

}


if [ "$DEVICE_TYPE" = "broadband" ]; then
		mount_tmpfs_for_app
		exit 1
fi

#Space reserved on app partition for firmware download(in MB)
RDM_SCRATCHPAD_MAX_FW_SIZE=80
RDM_SCRATCHPAD_FREE_MARGIN=5

# Determine App size in KB's and MB's
scale=`echo "${DOWNLOAD_APP_SIZE#"${DOWNLOAD_APP_SIZE%?}"}"`
value=`echo ${DOWNLOAD_APP_SIZE%?}`
value=${value%.*} # Truncate fractional part

if [ "x$scale" == "xK" -o "x$scale" == "xk" ]; then
    DOWNLOAD_APP_SIZE_KB=$value
    # convert into MB's
    value=$((value/1024))
    DOWNLOAD_APP_SIZE_MB=${value%.*} # Truncate fractional part
else
    DOWNLOAD_APP_SIZE_KB=$((value * 1024))
    DOWNLOAD_APP_SIZE_MB=$value
fi

# Varify if sufficient free space available on secondary storage for downloadable APP
# Determine free Space in app partition in 1K-blocks
RDM_SCRATCHPAD_FREE_SPACE=`df -k $APP_MOUNT_PATH |  grep -v File | awk '{print $4 }'`

#Convert the available space into MB's
RDM_SCRATCHPAD_FREE_SPACE="$(($RDM_SCRATCHPAD_FREE_SPACE / 1024))"
log_msg "Free Space in $APP_MOUNT_PATH = $RDM_SCRATCHPAD_FREE_SPACE MB"

RDM_AVAILABE_SPACE_FOR_APPS="$(($RDM_SCRATCHPAD_FREE_SPACE - $RDM_SCRATCHPAD_MAX_FW_SIZE - $RDM_SCRATCHPAD_FREE_MARGIN))"
log_msg "Availabble Space in $APP_MOUNT_PATH for app Download = $RDM_AVAILABE_SPACE_FOR_APPS MB"

if [[ "$RDM_AVAILABE_SPACE_FOR_APPS" -gt "$DOWNLOAD_APP_SIZE_MB" ]]; then
    log_msg "Secondary storage scratchpad will be used for App download"
    exit 0
else
    log_msg "Not enough space available for App download on $APP_MOUNT_PATH. $TMP_MOUNT_PATH will be used for App download"
	mount_tmpfs_for_app
    exit 1
fi
