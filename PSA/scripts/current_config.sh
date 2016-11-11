#!/bin/bash
#
# status.sh
#   Description:
#       This script return the current configuration.
#
# This script is called by the PSA API when the PSA's current runtime configuration is requested.
#
# Return value:
# Current configuration
#

PSA_HOME=/home/psa/pythonScript

if [ -z "$PSA_HOME" ]; then
    echo "error: 'PSA_HOME' is not set." >&2
    exit 1
fi

if [ ! -d "$PSA_HOME" ]; then
    echo "error: 'PSA_HOME' is not a valid directory." >&2
    exit 1
fi

#PSA_HOME=/home/admini/SECURED/
#PSA_HOME=/home/psa/pythonScript

COMMAND_OUTPUT="$(cat $PSA_HOME/psaConfigs/psaconf)"
printf '%s\n' "${COMMAND_OUTPUT[@]}"
exit 1;
