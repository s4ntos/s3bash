#!/bin/sh

# keep track of the last executed command
trap 'last_command=$current_command; current_command=$BASH_COMMAND' DEBUG
# echo an error message before exiting
trap 'echo "\"${last_command}\" command filed with exit code $?."' EXIT
set -e

role=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
role_credentials=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/${role}")
AWS_ACCESS_KEY_ID=$(echo "${role_credentials}" | cut -d, -f 3 | tr -d \"| awk -F: '{ print $2 }')
AWS_SECRET_ACCESS_KEY=$(echo "${role_credentials}" | cut -d, -f 4 | tr -d \"| awk -F: '{ print $2 }')
AWS_SECURITY_TOKEN=$(echo "${role_credentials}" | cut -d, -f 5 | tr -d \"| awk -F: '{ print $2 }')

usage="Usage: $0 file bucket:dir (e.g $0 file.txt bucket:destination/folder/)"
fileName=${1:?"Error: ${usage}"}
destination=${2:?"Error: ${usage}"}

s3Bucket=$(echo $destination | cut -d: -f 1)
destinatonKey=$(echo $destination | cut -d: -f 2)

yyyymmdd=$(date +%Y%m%d)
region="eu-central-1"
endpoint="${s3Bucket}.s3.${region}.amazonaws.com"
contentLength=$(cat ${fileName} | wc -c)
contentHash=$(openssl sha -sha256 -hex ${fileName} | sed 's/.* //')
b64=$(openssl md5 -binary "$fileName" | openssl base64)
acl="bucket-owner-full-control"
date=$(date -u +%Y%m%dT%H%M%SZ)
expdate_s=$(date --date '1 month' -u +%Y-%m-%dT%H:%M:%SZ)

echo "Uploading ${fileName} to s3://${s3Bucket}/${destinatonKey}${fileName} in ${region}"

policy=$(cat <<POLICY | openssl base64 | tr -d \\n
{ "expiration": "${expdate_s}T12:00:00.000Z",
  "conditions": [
    {"acl": "$acl" },
    {"bucket": "$s3Bucket" },
    ["starts-with", "\$key", ""],
    {"x-amz-date": "$date" },
    {"content-md5": "$b64" },
    {"x-amz-credential": "${AWS_ACCESS_KEY_ID}/${yyyymmdd}/${region}/s3/aws4_request" },
    {"x-amz-security-token": "${AWS_SECURITY_TOKEN}" },
    {"x-amz-algorithm": "AWS4-HMAC-SHA256" }
  ]
}
POLICY
)

# calculate the signing key
DateKey=$(echo -n "${yyyymmdd}" | openssl sha -sha256 -hex -hmac "AWS4${AWS_SECRET_ACCESS_KEY}" | sed 's/.* //')
DateRegionKey=$(echo -n "${region}" | openssl sha -sha256 -hex -mac HMAC -macopt hexkey:${DateKey} | sed 's/.* //')
DateRegionServiceKey=$(echo -n "s3" | openssl sha -sha256 -hex -mac HMAC -macopt hexkey:${DateRegionKey} | sed 's/.* //')
SigningKey=$(echo -n "aws4_request" | openssl sha -sha256 -hex -mac HMAC -macopt hexkey:${DateRegionServiceKey} | sed 's/.* //')
# then, once more a HMAC for the signature
signature=$(echo -en ${policy} | openssl sha -sha256 -hex -mac HMAC -macopt hexkey:${SigningKey} | sed 's/.* //')

key_and_sig_args="-F X-Amz-Credential=${AWS_ACCESS_KEY_ID}/${yyyymmdd}/${region}/s3/aws4_request -F X-Amz-Algorithm=AWS4-HMAC-SHA256 -F X-Amz-Signature=$signature -F X-Amz-Date=${date}"

curl -s  \
-F "key=${destinatonKey}${fileName}" \
-F "acl=$acl" \
-F "X-Amz-Credential=${AWS_ACCESS_KEY_ID}/${yyyymmdd}/${region}/s3/aws4_request" \
-F "X-Amz-Algorithm=AWS4-HMAC-SHA256" \
-F "X-Amz-Signature=${signature}" \
-F "X-Amz-Date=${date}" \
-F "content-md5=${b64}" \
-F "Policy=$policy" \
-F "X-Amz-Security-Token=${AWS_SECURITY_TOKEN}" \
-F "file=@$fileName" \
https://${endpoint}/
