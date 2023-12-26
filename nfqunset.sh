#!/bin/bash

/sbin/iptables -F
/sbin/modprobe -r nfnetlink_queue
