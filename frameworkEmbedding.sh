#!/bin/sh

# Copied from MOKit instructions
# http://mokit.sf.net/
#
# rewrite install_name in the framework
# note we do not bother to change the debug or profile variants since those are never directly linked against at static link time.

GPGME_FRAMEWORK_VERSION=1.0.2

chmod u+w "${TARGET_BUILD_DIR}/${PRODUCT_NAME}.${WRAPPER_EXTENSION}/Contents/Frameworks/GPGME.framework/Versions/${GPGME_FRAMEWORK_VERSION}/GPGME"
install_name_tool -id "@executable_path/../Frameworks/GPGME.framework/Versions/${GPGME_FRAMEWORK_VERSION}/GPGME" "${TARGET_BUILD_DIR}/${PRODUCT_NAME}.${WRAPPER_EXTENSION}/Contents/Frameworks/GPGME.framework/Versions/${GPGME_FRAMEWORK_VERSION}/GPGME"

# rewrite install_name in the app
install_name_tool -change "/Library/Frameworks/GPGME.framework/Versions/${GPGME_FRAMEWORK_VERSION}/GPGME" "@executable_path/../Frameworks/GPGME.framework/Versions/${GPGME_FRAMEWORK_VERSION}/GPGME" "${TARGET_BUILD_DIR}/${PRODUCT_NAME}.${WRAPPER_EXTENSION}/Contents/MacOS/${PRODUCT_NAME}"
