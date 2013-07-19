#!/bin/bash

#
# duo_configure.sh
#
# Copyright (c) 2013 Duo Security
# All rights reserved, all wrongs reversed.
#

# This script should be run from the OpenSSH source directory

####### USER CONFIGURATION ########

# Fill these in with the correct values for your integration and system
IKEY="my_ikey"
SKEY="my_skey"
APIHOST="my_api_host"

# These are the default options, and can be changed if necessary
FAILOPEN="1"
DUO_HTTP_PROXY="NULL"

# Fill this in with the path to libduo
LIBDUO="../libduo"

# Replace to change the install directory (e.g. /usr, /opt, etc.)
PREFIX="/opt"

######## END CONFIGURATION #########

echo "IKEY = $IKEY"
echo "SKEY = $SKEY"
echo "APIHOST = $APIHOST"
echo "FAILOPEN = $FAILOPEN"
echo "PROXY = $DUO_HTTP_PROXY"
echo "Install Prefix: $PREFIX"
echo "Path to libduo: $LIBDUO"
echo "Are these settings correct? [y/n]: "
read confirm

if [[ $confirm != 'y' && $confirm != 'Y' ]]; then
	echo "Aborting..."
	exit -1
fi

# Set CFLAGS
CFLAGS="-DDUO_APIHOST=\\\"$APIHOST\\\" -DDUO_IKEY=\\\"$IKEY\\\" -DDUO_SKEY=\\\"$SKEY\\\" -DDUO_FAILOPEN=$FAILOPEN "

if [[ $DUO_HTTP_PROXY == "NULL" ]]; then
	CFLAGS="$CFLAGS -DDUO_PROXY=$DUO_HTTP_PROXY"
else
	CFLAGS="$CFLAGS -DDUO_PROXY=\\\"$DUO_HTTP_PROXY\\\""
fi
export CFLAGS

# Construct the configure command
CONFIGURE="./configure --prefix=$PREFIX --with-duo=$LIBDUO"

# To the skies!
$CONFIGURE
