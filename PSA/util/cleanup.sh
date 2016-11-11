#!/bin/bash
#
# File:    cleanup.sh
# Created: 28/01/2016
# Author:  jju / VTT Technical Research Centre of Finland Ltd., 2016
#
# Description:
#
# A simple script to cleanup the development directory
#

# All paths should be relative!

# subdirectiories to clean. All directories listed are cleaned
# from generic temporary files, such as .pyc and *~
subdirs="modules, json, psaConfig, test, scripts"

# Specific temporary files that should be removed, e.g. log
# files.
tmpfiles="GUNICORN.log, PSA.log, psaConfigs/bro.log pylint.out"

echo "rm -f ./*.pyc ./*~"
rm -f ./*.pyc ./*~

dirs=(${subdirs//,/ })
for dir in "${dirs[@]}"
do
   if [ -n "$dir" -a -d "$dir" ]; then
       echo "rm -f ./$dir/*.pyc ./$dir/*~"
       rm -f ./$dir/*.pyc ./$dir/*~
   fi
done

files=(${tmpfiles//,/ })
for file in "${files[@]}"
do
   echo "rm -f ./$file"
   rm -f ./$file
done

exit 0
