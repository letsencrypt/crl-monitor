#!/bin/bash
set -eux

SCRIPT_PATH=${0%/*}
cd "$SCRIPT_PATH"

./run_local_dynamo.sh &
dynamopid=$!
trap 'kill $dynamopid' EXIT

sleep 1 # Let dynamodb start

./create_table.sh

go test -tags integration .
