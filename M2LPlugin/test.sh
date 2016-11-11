#!/bin/sh

java -cp ./lib/javax.json-1.0.4.jar:./lib/mspl_class.jar:./lib/commons-codec-1.9.jar:./target/M2LPluginBro-0.1.jar eu.securedfp7.m2lservice.plugin.Tester $1 $2
