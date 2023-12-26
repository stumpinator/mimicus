#!/bin/bash
/sbin/modprobe nfnetlink_queue
/sbin/iptables -F
/sbin/iptables -A OUTPUT -j NFQUEUE --queue-bypass --queue-num 0
