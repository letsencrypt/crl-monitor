#!/bin/bash

set -eux

# Fetch the local DynamoDB if there isn't one here already
if ! [ -d dynamodb_local ]; then
  mkdir dynamodb_local
  curl -sSL https://s3.us-west-2.amazonaws.com/dynamodb-local/dynamodb_local_latest.tar.gz \
    | tar -xzf - -C dynamodb_local
else
  echo "using existing DynamoDBLocal.jar"
fi

java -Djava.library.path=./dynamodb_local/DynamoDBLocal_lib -jar ./dynamodb_local/DynamoDBLocal.jar -inMemory &
dynamopid=$!

go test -tags integration .

kill $dynamopid
