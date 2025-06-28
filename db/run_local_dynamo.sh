#!/bin/bash

set -eu

SCRIPT_PATH=${0%/*}
cd "$SCRIPT_PATH" || exit

# Fetch the local DynamoDB if there isn't one here already
if ! [ -d dynamodb_local ]; then
  mkdir dynamodb_local
  curl -sSL https://s3.us-west-2.amazonaws.com/dynamodb-local/dynamodb_local_latest.tar.gz \
    | tar -xzf - -C dynamodb_local
else
  echo "using existing DynamoDBLocal.jar"
fi

exec java -Djava.library.path=./dynamodb_local/DynamoDBLocal_lib -jar ./dynamodb_local/DynamoDBLocal.jar -sharedDb -inMemory