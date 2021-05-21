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
# functions
function get_hmac_sha256 {
  if [ $# -le 1 ]; then
    echo "error: get_hmac_sha256 needs args"
    echo "usage:"
    echo "  get_hmac_sha256 key:<key> <data>"
    exit 1
  fi

  key="$1"
  data="$2"

  echo -n "$data" |  openssl dgst -sha256 -mac HMAC -macopt "$key" | awk '{print $2}'
}


usage="Usage: $0 bucket:dir/file (e.g $0 bucket:destination/folder/file.txt)"
Key=${1:?"Error: ${usage}"}

s3Bucket=$(echo ${Key} | cut -d: -f 1)
object=$(echo ${Key} | cut -d: -f 2)
fileName=$(basename ${object})

# s3 account info
region="eu-central-1"
endpoint="${s3Bucket}.s3.${region}.amazonaws.com"
service="s3"


# date, timestamp, hashes, etc.
yyyymmdd=$(date +%Y%m%d)
date=$(date -u +%Y%m%dT%H%M%SZ)
empty_hash=$(openssl dgst -sha256 /dev/null | awk '{print $2}')
http_req="GET"


echo "Downloading ${fileName} to s3://${s3Bucket}/${object} in ${region}"

# build canonical request
cr_str="${http_req}
/${object}

host:$endpoint
x-amz-content-sha256:$empty_hash
x-amz-date:${date}
x-amz-security-token:${AWS_SECURITY_TOKEN}

host;x-amz-content-sha256;x-amz-date;x-amz-security-token
${empty_hash}"

cr_hash=`echo -n "${cr_str}" | openssl dgst -sha256 | awk '{print $2}'`

# build string to sign
sts="AWS4-HMAC-SHA256
${date}
${yyyymmdd}/${region}/${service}/aws4_request
$cr_hash"

# signing key from date keys
DateKey=$(get_hmac_sha256 key:"AWS4${AWS_SECRET_ACCESS_KEY}" ${yyyymmdd})
DateRegionKey=$(get_hmac_sha256 hexkey:${DateKey} ${region})
DateRegionServiceKey=$(get_hmac_sha256 hexkey:${DateRegionKey} ${service})
SigningKey=$(get_hmac_sha256 hexkey:${DateRegionServiceKey} "aws4_request")
req_signature=$(get_hmac_sha256 hexkey:${SigningKey} "${sts}")

auth_hdr="Authorization: AWS4-HMAC-SHA256 Credential=${AWS_ACCESS_KEY_ID}/${yyyymmdd}/${region}/s3/aws4_request, \
          SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, \
          Signature=${req_signature}"

curl -s \
  -o ${fileName} \
  -H "${auth_hdr}" \
  -H "x-amz-content-sha256: ${empty_hash}" \
  -H "x-amz-date: ${date}" \
  -H "x-amz-security-token: ${AWS_SECURITY_TOKEN}" \
  "https://${endpoint}/${object}"
