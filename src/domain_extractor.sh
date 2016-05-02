#!/bin/bash

find $1 -name "*.pcap.gz" | xargs -n 1 tshark -T fields -e ip.src -e dns.qry.name -Y "dns.flags.response eq 0" -r | awk '$2>0 {print $2}'
