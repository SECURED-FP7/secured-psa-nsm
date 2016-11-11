#!/bin/bash
#
# status.sh
#   Created:    1/02/2016
#   Author:     jju / VTT Technical Research Centre of Finland Ltd., 2016
#
#   Description:
#       Script that returns the current status of the Bro PSA.
#
# This script is called by the PSA API when the PSA's runtime status is
# requested.
#
# Return value:
# 1: alive
# 2: not alive
#

#if [ -z "$PSA_HOME" ]; then
#    echo "error: 'PSA_HOME' is not set." >&2
#    exit 1
#fi

#if [ ! -d "$PSA_HOME" ]; then
#    echo "error: 'PSA_HOME' is not a valid directory." >&2
#    exit 1
#fi

BROCTL=/opt/bro/bin/broctl
LINE=`$BROCTL status 2>&1 | grep "running"`

if [ "$?" -eq 0 ] ; then
    echo 1
    exit 1
fi

echo 0
exit 0
