#!/bin/bash
PAYLOAD="$1"
exec 3<>/dev/tcp/0.cloud.chals.io/23023
printf '%s\n' "$PAYLOAD" >&3
timeout 3 cat <&3
