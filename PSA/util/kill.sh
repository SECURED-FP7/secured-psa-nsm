#!/bin/sh

PIDS=`ps aux | grep guni | grep python  | sed 's/^[^ \t]*[ \t]*\([0-9]*\).*/\1/g' | tr '\n' ' '`

kill -s 9 $PIDS
