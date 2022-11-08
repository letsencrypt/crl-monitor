#!/bin/sh
#
aws dynamodb \
	--endpoint-url "http://localhost:8000" \
       	create-table --table-name "unseen-certificates" \
       	--attribute-definitions AttributeName=SN,AttributeType=B \
        --key-schema AttributeName=SN,KeyType=HASH \
	--provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1 \
	--table-class STANDARD \

