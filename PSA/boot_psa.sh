#!/bin/bash

if [ -z "$PSA_HOME" ]; then
    echo "error: 'PSA_HOME' is not set." >&2
    exit 1
fi

if [ ! -d "$PSA_HOME" ]; then
    echo "error: 'PSA_HOME' is not a valid directory." >&2
    exit 1
fi

ip=$(ifconfig eth0 | grep "inet addr" | awk '{print $2}' | cut -d: -f2)
gunicorn -k gevent -b $ip:8080 --log-file $PSA_HOME/GUNICORN.log --log-level debug psaEE:app &
