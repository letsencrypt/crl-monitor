#!/bin/bash

set -eux

#
#  Check all of Let's Encrypt CRL shards

check() {
  for SHARD in $(seq 0 127); do
    S3_CRL_OBJECT=$1/$SHARD.crl \
    S3_CRL_BUCKET=$2 \
    BOULDER_BASE_URL=$3 \
     go run cmd/checker/checker.go
  done
}

# TODO: r3/e1 might be backwards
R3STG="4169287449788112"
E1STG="58367272336442518"
R3PROD="20506757847264211"
E1PROD="67430855296768143"

STGBUCKET="le-crl-stg"
PRODBUCKET="le-crl-prod"

export DYNAMO_ENDPOINT="http://localhost:8000"
export DYNAMO_TABLE="unseen-certificates"

STGURL="https://acme-staging-v02.api.letsencrypt.org/acme/cert"
PRODURL="https://acme-v02.api.letsencrypt.org/acme/cert"

export BOULDER_MAX_FETCH=500
export ISSUER_PATHS="checker/testdata/r3.pem:checker/testdata/e1.pem:checker/testdata/stg-e1.pem:checker/testdata/stg-r3.pem"

./db/run_local_dynamo.sh &
dynamopid=$!
trap 'kill $dynamopid' EXIT

check $R3STG $STGBUCKET $STGURL
check $E1STG $STGBUCKET $STGURL
check $R3PROD $PRODBUCKET $PRODURL
check $E1PROD $PRODBUCKET $PRODURL
