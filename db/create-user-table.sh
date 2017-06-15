#!/bin/bash

# Change the endpoint-url, region, and profile to match yours
# These settings will work for US West (Oregon)
# profile is from ~/.aws/credentials
aws dynamodb create-table --cli-input-json file://./user-table.json \
--endpoint-url "http://dynamodb.us-west-2.amazonaws.com" \
--region "us-west-2" \
--profile default
