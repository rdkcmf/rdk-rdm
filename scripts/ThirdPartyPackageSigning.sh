#!/bin/bash

# Assigned with dummy data
APP_NAME=""
APP_VERSION="DUMMY_VERSION"
# need to add changes to update with real values
# for rel number and arch name
RELEASE_NUM="DUMMY_REL"
ARCH_NAME="DUMMY_ARCH"

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
  echo "[$DateTime] [pid=$$] $STR" 
}

usage()
{
    log_msg "----------------------USAGE--------------------------------"
    log_msg "USAGE: $0 -a <appln name> -k <signing key> -c <ca certificate> -p <package path> "
    log_msg " < appln name >: Name of the Application "
    log_msg " <signing key>: Signing Key (ext *.key) to sing the package "
    log_msg "               Use -k option to provide Signing key"
    log_msg " <ca cert>  : CA Certified Verification Certificate (ext *.crt)"
    log_msg "             Use -c to provide certificate"
    log_msg " <package path/directory>: Application tar file which needs to be signed"
    log_msg "                 Use option -p to provide package"
    log_msg "----------------------------------------------------------"
    exit 0
}

localDir=`pwd`
WORK_PATH=${localDir}/tmp_work/
if [ ! -d $WORK_PATH ];then
      log_msg "[INFO] Generating the work path: $$WORK_PATH"
      mkdir -p $WORK_PATH
else
      rm -rf $WORK_PATH/*
fi


# Reading Arguement
while getopts ":k:c:p:a:" opt; do
    case $opt in
    a)
      APP_NAME=("$OPTARG")
      log_msg "[INFO] Application Name is [$APP_NAME]"
    ;;
    k)
      SIGNING_KEY=("$OPTARG")
      log_msg "[INFO] Key is [$SIGNING_KEY]"
    ;;
    c)
      CA_CERT=("$OPTARG")
      log_msg "[INFO] CA Certs is [$CA_CERT]"
    ;;
    p)
      PACKAGE_PATH=("$OPTARG")
      log_msg "[INFO] Application Path is [$PACKAGE_PATH]"
    ;;
    *)
      log_msg "[ERROR] Invalid Input Arguement !!"
      usage 
      exit 0
    ;;
    esac
done

# Verify the input arguement
if [ ! "$APP_NAME" ]; then
    log_msg "[ERROR] Required Application Name, Exiting Without Execution"
    usage
    exit 0
fi

# Verify the input arguement
if [ ! -f "$SIGNING_KEY" ]; then
    log_msg "[ERROR] Required Signing Key, Exiting Without Execution"
    exit 0
fi

if [ ! -f "$CA_CERT" ]; then
     log_msg "[ERROR] Required Verification Certificate Exiting Without Execution"
     exit 0
fi

if [ ! -d ${PACKAGE_PATH} ]; then
    log_msg "[ERROR] Required Application Folder Path to package"
    exit 0
fi

# Validate RSA Signing Key
openssl rsa -modulus -noout -in "${SIGNING_KEY}"
if [ $? -ne 0 ] ; then
    log_msg "[ERROR] RSA Siging key is invalid"
    exit 0
else
    #creating local copy for signing
    cp "${SIGNING_KEY}" ${WORK_PATH}
    SIGNING_KEY=`echo "${SIGNING_KEY}" | xargs basename`
fi

# Validate CA Certificate
openssl x509 -modulus -noout -in "${CA_CERT}"
if [ $? -ne 0 ] ; then
    log_msg "[ERROR]  CA Certificate is invalid"
    exit 0
else
    #creating localo copy for packaging
    cp "${CA_CERT}" ${WORK_PATH}
    CA_CERT=`echo "${CA_CERT}" | xargs basename`
fi

# Assumption, valid {tar/ipk} packaged file shall be provided 
# by 3rd party App developer for signing, along with application
# meta data in a config file as per format given
#
# Script subjected to modify if above assumption does not meet

if [ -d ${PACKAGE_PATH} ];then
     tar -cvf $WORK_PATH/$APP_NAME.tar ${PACKAGE_PATH}/
fi

cd $WORK_PATH

# Verify if package file exists
if [[ (! -f "./$APP_NAME.tar") ]]; then
        log_msg "[ERROR] Package file $APP_NAME.tar does not exists"
        exit 1
fi
log_msg "[INFO] Signing for $APP_NAME.tar"

PACKAGED_TAR=$APP_NAME.tar
# Signing the tar file using openssl
openssl dgst -sha256 -sign ./${SIGNING_KEY} -out ./${APP_NAME}.sig ./${PACKAGED_TAR}
if [ $? -ne 0 ]; then
        log_msg "[ERROR] Package ${APP_NAME}"
        log_msg "[ERROR] Signature Signing Failed"
        exit 0
else
        log_msg "[INFO] Package ${APP_NAME}"
        log_msg "[INFO] Successfully Completed the package Signing"
fi

# Packaging all required component to create final tarball
finalTarFile="$APP_NAME"-signed.tar
tar -cvf "${finalTarFile}" "${APP_NAME}.sig" "${PACKAGED_TAR}" "${CA_CERT}" 

if [ $? -ne 0 ]; then
        log_msg "[ERROR] Error in Signed tar file creation for package ${APP_NAME}" 
        exit 0
else
        log_msg "[INFO] Successfully created Final Tar ball $finalTarFile"
        # Cleanup tarball for signed package and app config file
        rm -rf "${APP_NAME}.sig" "${PACKAGED_TAR}"
fi
# Removing Signing key & CA Certificate
rm -rf "${CA_CERT}" "${SIGNING_KEY}"
cd -

