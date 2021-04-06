#! /bin/bash

TARGET_OPT=""
if [ -n "$1" ]; then
	TARGET_OPT="target=$1"
fi

TCB_OPT=""
if [ -n "$2" ]; then
	TCB_OPT=",tcb=$2"
fi

FILTER_OPT=""
if [ -n "$3" ]; then
	FILTER_OPT=",filter=$3"
fi

./ra_verifier.py -g 'lsm+selinux' -s infoflow:rules -v -a "run-time,$TARGET_OPT$TCB_OPT$FILTER_OPT,draw_graph=True"
if [ "$4" = "www" ]; then
	cp graph-run-time-0.png /var/www/html/
fi
