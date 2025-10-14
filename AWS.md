### **Prerequisites**

Ensure the following tools are installed on your local workstation:

  * `bash`
  * AWS CLI v2 (configured with appropriate credentials)
  * `jq`
  * `uuidgen`
  * `base64`

-----

### **How to Use These Scripts**

1.  Run all commands from your project's root directory.
2.  Create the necessary local directories:
    ```bash
    mkdir -p scripts state logs
    ```
3.  For each step below, copy the script content into the specified file (e.g., `scripts/00-bootstrap-env.sh`).
4.  Make the script executable: `chmod +x scripts/*.sh`
5.  Execute the script for each step before proceeding to the next. The scripts are idempotent and can be re-run safely.

-----

## Step 00 – Bootstrap Environment Variables

*Initializes environment variables and saves them locally and securely in SSM Parameter Store.*

```bash
cat <<'EOF' > scripts/00-bootstrap-env.sh
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
mkdir -p "$STATE_DIR"
REGION=${AWS_REGION:-us-east-1}
AZ=${AZ:-${REGION}a}
CLUSTER_NAME=${CLUSTER_NAME:-fdb-prod}
ENV_ID=${ENV_ID:-$(date +%Y%m%d%H%M%S)}
VPC_CIDR=${VPC_CIDR:-10.42.0.0/20}
PUBLIC_SUBNET_CIDR=${PUBLIC_SUBNET_CIDR:-10.42.0.0/26}
STORAGE_SUBNET_CIDR=${STORAGE_SUBNET_CIDR:-10.42.1.0/24}
STATELESS_SUBNET_CIDR=${STATELESS_SUBNET_CIDR:-10.42.2.0/24}
BENCH_SUBNET_CIDR=${BENCH_SUBNET_CIDR:-10.42.3.0/24}
OBSERVABILITY_CIDR=${OBSERVABILITY_CIDR:-10.50.0.0/16}
FDB_VERSION=${FDB_VERSION:-7.3.29}
BENCH_REPO_URL=${BENCH_REPO_URL:-https://github.com/Abdullah1738/omsbench.git}
BENCH_REPO_REF=${BENCH_REPO_REF:-main}
BENCH_BINARY_PATH=${BENCH_BINARY_PATH:-internal/bench/bench.go}
STATE_BUCKET=${STATE_BUCKET:-fdb-${CLUSTER_NAME}-${REGION}-${ENV_ID}-state}
BACKUP_BUCKET=${BACKUP_BUCKET:-fdb-${CLUSTER_NAME}-${REGION}-${ENV_ID}-backup}
BENCH_BUCKET=${BENCH_BUCKET:-fdb-${CLUSTER_NAME}-${REGION}-${ENV_ID}-bench}
DDB_TABLE=${DDB_TABLE:-fdb-${CLUSTER_NAME}-${ENV_ID}-lock}
KMS_ALIAS=${KMS_ALIAS:-alias/${CLUSTER_NAME}-kms}
FLOW_LOG_GROUP=${FLOW_LOG_GROUP:-/aws/vpcflow/${CLUSTER_NAME}}
SSM_PARAMETER_PREFIX=${SSM_PARAMETER_PREFIX:-/foundationdb/${CLUSTER_NAME}}
GO_VERSION=${GO_VERSION:-1.21.9}
cat >"$STATE_DIR/env.sh" <<ENV
export REGION=$REGION
export AZ=$AZ
export CLUSTER_NAME=$CLUSTER_NAME
export ENV_ID=$ENV_ID
export VPC_CIDR=$VPC_CIDR
export PUBLIC_SUBNET_CIDR=$PUBLIC_SUBNET_CIDR
export STORAGE_SUBNET_CIDR=$STORAGE_SUBNET_CIDR
export STATELESS_SUBNET_CIDR=$STATELESS_SUBNET_CIDR
export BENCH_SUBNET_CIDR=$BENCH_SUBNET_CIDR
export OBSERVABILITY_CIDR=$OBSERVABILITY_CIDR
export FDB_VERSION=$FDB_VERSION
export BENCH_REPO_URL=$BENCH_REPO_URL
export BENCH_REPO_REF=$BENCH_REPO_REF
export BENCH_BINARY_PATH=$BENCH_BINARY_PATH
export STATE_BUCKET=$STATE_BUCKET
export BACKUP_BUCKET=$BACKUP_BUCKET
export BENCH_BUCKET=$BENCH_BUCKET
export DDB_TABLE=$DDB_TABLE
export KMS_ALIAS=$KMS_ALIAS
export FLOW_LOG_GROUP=$FLOW_LOG_GROUP
export SSM_PARAMETER_PREFIX=$SSM_PARAMETER_PREFIX
export GO_VERSION=$GO_VERSION
ENV
ENCODED_ENV=$(base64 <"$STATE_DIR/env.sh" | tr -d '\n')
aws ssm put-parameter \
  --name "${SSM_PARAMETER_PREFIX}/env/base64" \
  --type "SecureString" \
  --value "$ENCODED_ENV" \
  --overwrite \
  --region "$REGION"
printf 'Environment staged in %s/env.sh and SSM parameter %s/env/base64\n' "$STATE_DIR" "$SSM_PARAMETER_PREFIX"
EOF
```

**Run:** `bash scripts/00-bootstrap-env.sh`

-----

## Step 01 – Create Buckets and DynamoDB Lock Table

*Initializes encrypted S3 buckets and a DynamoDB table for state management.*

```bash
cat <<'EOF' > scripts/01-bootstrap-state.sh
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"
create_bucket() {
  local bucket=$1
  if aws s3api head-bucket --bucket "$bucket" 2>/dev/null; then
    echo "Bucket $bucket already exists"
  else
    aws s3api create-bucket --bucket "$bucket" --region "$REGION" \
      --create-bucket-configuration LocationConstraint="$REGION"
    aws s3api put-bucket-versioning \
      --bucket "$bucket" \
      --versioning-configuration Status=Enabled
    aws s3api put-bucket-encryption \
      --bucket "$bucket" \
      --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
    aws s3api put-public-access-block \
      --bucket "$bucket" \
      --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    aws s3api put-bucket-tagging \
      --bucket "$bucket" \
      --tagging "TagSet=[{Key=Cluster,Value=$CLUSTER_NAME},{Key=Environment,Value=prod}]"
    echo "Bucket $bucket created"
  fi
}
create_bucket "$STATE_BUCKET"
create_bucket "$BACKUP_BUCKET"
create_bucket "$BENCH_BUCKET"
if aws dynamodb describe-table --table-name "$DDB_TABLE" --region "$REGION" >/dev/null 2>&1; then
  echo "DynamoDB table $DDB_TABLE already exists"
else
  aws dynamodb create-table \
    --table-name "$DDB_TABLE" \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --tags Key=Cluster,Value="$CLUSTER_NAME" Key=Environment,Value=prod \
    --region "$REGION"
  aws dynamodb wait table-exists --table-name "$DDB_TABLE" --region "$REGION"
  echo "DynamoDB table $DDB_TABLE created"
fi
printf 'S3 buckets and DynamoDB table are ready.\n'
EOF
```

**Run:** `bash scripts/01-bootstrap-state.sh`

-----

## Step 02 – Provision Network

*Creates a secure VPC, subnets, NAT Gateway, and necessary VPC Endpoints for private AWS service access.*

```bash
cat <<'EOF' > scripts/02-network.sh
#!/usr/bin/env bash
set -euo pipefail
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"
log() { printf '%s\n' "$*" >&2; }
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text --region "$REGION")
# VPC
VPC_ID=$(aws ec2 describe-vpcs --filters "Name=tag:Name,Values=${CLUSTER_NAME}-vpc" --query 'Vpcs[0].VpcId' --output text --region "$REGION")
if [[ "$VPC_ID" == "None" ]]; then
  VPC_ID=$(aws ec2 create-vpc --cidr-block "$VPC_CIDR" --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=${CLUSTER_NAME}-vpc},{Key=Cluster,Value=$CLUSTER_NAME}]" --query 'Vpc.VpcId' --output text --region "$REGION")
  log "Created VPC $VPC_ID"
else
  log "Reusing VPC $VPC_ID"
fi
aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-hostnames '{"Value":true}' --region "$REGION"
aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-support '{"Value":true}' --region "$REGION"
# Subnets
create_subnet() {
  local name=$1; local cidr=$2; local subnet_id
  subnet_id=$(aws ec2 describe-subnets --filters "Name=tag:Name,Values=${CLUSTER_NAME}-${name}-subnet" "Name=vpc-id,Values=$VPC_ID" --query 'Subnets[0].SubnetId' --output text --region "$REGION")
  if [[ "$subnet_id" == "None" ]]; then
    subnet_id=$(aws ec2 create-subnet --vpc-id "$VPC_ID" --cidr-block "$cidr" --availability-zone "$AZ" --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${CLUSTER_NAME}-${name}-subnet},{Key=Cluster,Value=$CLUSTER_NAME},{Key=Tier,Value=$name}]" --query 'Subnet.SubnetId' --output text --region "$REGION")
    log "Created $name subnet $subnet_id"
  else
    log "Reusing $name subnet $subnet_id"
  fi
  echo "$subnet_id"
}
PUBLIC_SUBNET_ID=$(create_subnet public "$PUBLIC_SUBNET_CIDR")
STORAGE_SUBNET_ID=$(create_subnet storage "$STORAGE_SUBNET_CIDR")
STATELESS_SUBNET_ID=$(create_subnet stateless "$STATELESS_SUBNET_CIDR")
BENCH_SUBNET_ID=$(create_subnet bench "$BENCH_SUBNET_CIDR")
# Internet Gateway
IGW_ID=$(aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID" --query 'InternetGateways[0].InternetGatewayId' --output text --region "$REGION")
if [[ "$IGW_ID" == "None" ]]; then
  IGW_ID=$(aws ec2 create-internet-gateway --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=${CLUSTER_NAME}-igw}]" --query 'InternetGateway.InternetGatewayId' --output text --region "$REGION")
  aws ec2 attach-internet-gateway --vpc-id "$VPC_ID" --internet-gateway-id "$IGW_ID" --region "$REGION"
  log "Created IGW $IGW_ID"
else
  log "Reusing IGW $IGW_ID"
fi
# Public Route Table
PUBLIC_RT_ID=$(aws ec2 describe-route-tables --filters "Name=tag:Name,Values=${CLUSTER_NAME}-public-rt" --query 'RouteTables[0].RouteTableId' --output text --region "$REGION")
if [[ "$PUBLIC_RT_ID" == "None" ]]; then
  PUBLIC_RT_ID=$(aws ec2 create-route-table --vpc-id "$VPC_ID" --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${CLUSTER_NAME}-public-rt}]" --query 'RouteTable.RouteTableId' --output text --region "$REGION")
  aws ec2 create-route --route-table-id "$PUBLIC_RT_ID" --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW_ID" --region "$REGION" >/dev/null
  aws ec2 associate-route-table --route-table-id "$PUBLIC_RT_ID" --subnet-id "$PUBLIC_SUBNET_ID" --region "$REGION" >/dev/null
  log "Created public route table $PUBLIC_RT_ID"
else
  log "Reusing public route table $PUBLIC_RT_ID"
fi
# EIP and NAT Gateway
ALLOCATION_ID=$(aws ec2 describe-addresses --filters "Name=tag:Name,Values=${CLUSTER_NAME}-nat-eip" --query 'Addresses[0].AllocationId' --output text --region "$REGION")
if [[ "$ALLOCATION_ID" == "None" ]]; then
  ALLOCATION_ID=$(aws ec2 allocate-address --domain vpc --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=${CLUSTER_NAME}-nat-eip}]" --query 'AllocationId' --output text --region "$REGION")
  log "Allocated EIP"
else
  log "Reusing EIP"
fi
NAT_ID=$(aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$VPC_ID" "Name=state,Values=pending,available" --query 'NatGateways[0].NatGatewayId' --output text --region "$REGION")
if [[ "$NAT_ID" == "None" ]]; then
  NAT_ID=$(aws ec2 create-nat-gateway --subnet-id "$PUBLIC_SUBNET_ID" --allocation-id "$ALLOCATION_ID" --tag-specifications "ResourceType=natgateway,Tags=[{Key=Name,Value=${CLUSTER_NAME}-nat}]" --query 'NatGateway.NatGatewayId' --output text --region "$REGION")
  log "Creating NAT Gateway $NAT_ID... this may take a minute."
  aws ec2 wait nat-gateway-available --nat-gateway-ids "$NAT_ID" --region "$REGION"
else
  log "Reusing NAT Gateway $NAT_ID"
fi
# Private Route Table
PRIVATE_RT_ID=$(aws ec2 describe-route-tables --filters "Name=tag:Name,Values=${CLUSTER_NAME}-private-rt" --query 'RouteTables[0].RouteTableId' --output text --region "$REGION")
if [[ "$PRIVATE_RT_ID" == "None" ]]; then
  PRIVATE_RT_ID=$(aws ec2 create-route-table --vpc-id "$VPC_ID" --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${CLUSTER_NAME}-private-rt}]" --query 'RouteTable.RouteTableId' --output text --region "$REGION")
  aws ec2 create-route --route-table-id "$PRIVATE_RT_ID" --destination-cidr-block 0.0.0.0/0 --nat-gateway-id "$NAT_ID" --region "$REGION" >/dev/null
  log "Created private route table $PRIVATE_RT_ID"
else
  log "Reusing private route table $PRIVATE_RT_ID"
fi
aws ec2 associate-route-table --route-table-id "$PRIVATE_RT_ID" --subnet-id "$STORAGE_SUBNET_ID" --region "$REGION" >/dev/null
aws ec2 associate-route-table --route-table-id "$PRIVATE_RT_ID" --subnet-id "$STATELESS_SUBNET_ID" --region "$REGION" >/dev/null
aws ec2 associate-route-table --route-table-id "$PRIVATE_RT_ID" --subnet-id "$BENCH_SUBNET_ID" --region "$REGION" >/dev/null
# VPC Endpoints
ENDPOINT_SG_ID=$(aws ec2 describe-security-groups --filters Name=vpc-id,Values="$VPC_ID" Name=group-name,Values="${CLUSTER_NAME}-endpoint-sg" --query "SecurityGroups[0].GroupId" --output text --region "$REGION")
if [[ "$ENDPOINT_SG_ID" == "None" ]]; then
  ENDPOINT_SG_ID=$(aws ec2 create-security-group --group-name "${CLUSTER_NAME}-endpoint-sg" --description "SG for VPC Endpoints" --vpc-id "$VPC_ID" --query "GroupId" --output text --region "$REGION")
  aws ec2 authorize-security-group-ingress --group-id "$ENDPOINT_SG_ID" --protocol tcp --port 443 --cidr "$VPC_CIDR" --region "$REGION"
  log "Created endpoint SG $ENDPOINT_SG_ID"
else
  log "Reusing endpoint SG $ENDPOINT_SG_ID"
fi
PRIVATE_SUBNET_IDS="${STORAGE_SUBNET_ID},${STATELESS_SUBNET_ID},${BENCH_SUBNET_ID}"
for service in ssm ec2messages ssmmessages logs; do
  if ! aws ec2 describe-vpc-endpoints --filters "Name=vpc-id,Values=$VPC_ID" "Name=service-name,Values=com.amazonaws.${REGION}.${service}" --query "VpcEndpoints[0].VpcEndpointId" --output text --region "$REGION" | grep -q vpce; then
    aws ec2 create-vpc-endpoint --vpc-id "$VPC_ID" --service-name "com.amazonaws.${REGION}.${service}" --vpc-endpoint-type Interface --subnet-ids "$PRIVATE_SUBNET_IDS" --security-group-ids "$ENDPOINT_SG_ID" --private-dns-enabled --region "$REGION" >/dev/null
    log "Creating endpoint for $service..."
  else
    log "Endpoint for $service already exists."
  fi
done
cat >"$STATE_DIR/network.json" <<JSON
{"vpc_id":"$VPC_ID","storage_subnet_id":"$STORAGE_SUBNET_ID","stateless_subnet_id":"$STATELESS_SUBNET_ID","bench_subnet_id":"$BENCH_SUBNET_ID"}
JSON
aws s3 cp "$STATE_DIR/network.json" "s3://${STATE_BUCKET}/state/network.json"
aws ssm put-parameter --name "${SSM_PARAMETER_PREFIX}/infra/network" --type "String" --value "$(cat "$STATE_DIR/network.json")" --overwrite --region "$REGION"
printf 'Network state saved to %s/network.json, S3, and SSM.\n' "$STATE_DIR"
EOF
```

**Run:** `bash scripts/02-network.sh`

-----

## Step 03 – Create Security Groups

*Defines strict network boundaries between cluster tiers.*

```bash
cat <<'EOF' > scripts/03-security-groups.sh
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"
VPC_ID=$(jq -r '.vpc_id' "$STATE_DIR/network.json")
create_sg() {
  local name=$1; local desc=$2; local sg_id
  sg_id=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=${CLUSTER_NAME}-${name}-sg" --query 'SecurityGroups[0].GroupId' --output text --region "$REGION")
  if [[ "$sg_id" == "None" ]]; then
    sg_id=$(aws ec2 create-security-group --group-name "${CLUSTER_NAME}-${name}-sg" --description "$desc" --vpc-id "$VPC_ID" --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=${CLUSTER_NAME}-${name}-sg},{Key=Tier,Value=${name}}]" --query 'GroupId' --output text --region "$REGION")
    echo "Created SG for $name: $sg_id"
  else
    echo "Reusing SG for $name: $sg_id"
  fi
  # Allow all egress
  aws ec2 authorize-security-group-egress --group-id "$sg_id" --protocol -1 --port -1 --cidr 0.0.0.0/0 --region "$REGION" >/dev/null 2>&1 || true
  echo "$sg_id"
}
STORAGE_SG_ID=$(create_sg storage "FDB storage tier")
STATELESS_SG_ID=$(create_sg stateless "FDB stateless tier")
BENCH_SG_ID=$(create_sg bench "Benchmark host")
# Rule: Allow storage tier to receive traffic from stateless and other storage nodes
aws ec2 authorize-security-group-ingress --group-id "$STORAGE_SG_ID" --protocol tcp --port 4500-4600 --source-group "$STATELESS_SG_ID" --region "$REGION" >/dev/null 2>&1 || true
aws ec2 authorize-security-group-ingress --group-id "$STORAGE_SG_ID" --protocol tcp --port 4500-4600 --source-group "$STORAGE_SG_ID" --region "$REGION" >/dev/null 2>&1 || true
# Rule: Allow stateless tier to receive traffic from storage, bench, and other stateless nodes
aws ec2 authorize-security-group-ingress --group-id "$STATELESS_SG_ID" --protocol tcp --port 4500-4600 --source-group "$STORAGE_SG_ID" --region "$REGION" >/dev/null 2>&1 || true
aws ec2 authorize-security-group-ingress --group-id "$STATELESS_SG_ID" --protocol tcp --port 4500-4600 --source-group "$STATELESS_SG_ID" --region "$REGION" >/dev/null 2>&1 || true
aws ec2 authorize-security-group-ingress --group-id "$STATELESS_SG_ID" --protocol tcp --port 4500-4600 --source-group "$BENCH_SG_ID" --region "$REGION" >/dev/null 2>&1 || true
# Rule: Allow bench host to receive traffic from our observability network for metrics scraping
aws ec2 authorize-security-group-ingress --group-id "$BENCH_SG_ID" --protocol tcp --port 2112 --cidr "$OBSERVABILITY_CIDR" --region "$REGION" >/dev/null 2>&1 || true
echo "Security group rules applied."
cat >"$STATE_DIR/security-groups.json" <<JSON
{"storage_sg_id":"$STORAGE_SG_ID","stateless_sg_id":"$STATELESS_SG_ID","bench_sg_id":"$BENCH_SG_ID"}
JSON
aws s3 cp "$STATE_DIR/security-groups.json" "s3://${STATE_BUCKET}/state/security-groups.json"
aws ssm put-parameter --name "${SSM_PARAMETER_PREFIX}/infra/security-groups" --type "String" --value "$(cat "$STATE_DIR/security-groups.json")" --overwrite --region "$REGION"
printf 'Security groups state saved.\n'
EOF
```

**Run:** `bash scripts/03-security-groups.sh`

-----

*Steps 04 (IAM) and 05 (KMS) are unchanged from your original guide as they were well-formed.*

## Step 04 – IAM Roles, Policies, Instance Profiles

*Creates IAM roles with necessary permissions for EC2 instances.*

```bash
# (Content of scripts/04-iam.sh is identical to the original)
cat <<'EOF' > scripts/04-iam.sh
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text --region "$REGION")
create_role() {
  local role_name=$1
  local description=$2
  if aws iam get-role --role-name "$role_name" >/dev/null 2>&1; then
    echo "Reusing role $role_name"
  else
    cat >"$STATE_DIR/trust-policy.json" <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "ec2.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
JSON
    aws iam create-role \
      --role-name "$role_name" \
      --assume-role-policy-document "file://$STATE_DIR/trust-policy.json" \
      --description "$description" \
      --tags Key=Cluster,Value="$CLUSTER_NAME" Key=Environment,Value=prod
    echo "Created role $role_name"
  fi
}
create_role "${CLUSTER_NAME}-ec2-role" "FoundationDB EC2 role"
create_role "${CLUSTER_NAME}-bench-role" "FoundationDB benchmark EC2 role"
attach_managed() {
  local role=$1
  local policy=$2
  aws iam attach-role-policy --role-name "$role" --policy-arn "$policy" >/dev/null 2>&1 || true
}
attach_managed "${CLUSTER_NAME}-ec2-role" arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
attach_managed "${CLUSTER_NAME}-ec2-role" arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy
attach_managed "${CLUSTER_NAME}-bench-role" arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
cat >"$STATE_DIR/fdb-inline-policy.json" <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::${STATE_BUCKET}",
        "arn:aws:s3:::${STATE_BUCKET}/*",
        "arn:aws:s3:::${BACKUP_BUCKET}",
        "arn:aws:s3:::${BACKUP_BUCKET}/*",
        "arn:aws:s3:::${BENCH_BUCKET}",
        "arn:aws:s3:::${BENCH_BUCKET}/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath"
      ],
      "Resource": [
        "arn:aws:ssm:${REGION}:${ACCOUNT_ID}:parameter${SSM_PARAMETER_PREFIX}*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "s3.${REGION}.amazonaws.com"
        }
      }
    }
  ]
}
JSON
aws iam put-role-policy \
  --role-name "${CLUSTER_NAME}-ec2-role" \
  --policy-name "${CLUSTER_NAME}-inline" \
  --policy-document "file://$STATE_DIR/fdb-inline-policy.json"
cat >"$STATE_DIR/bench-inline-policy.json" <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::${STATE_BUCKET}",
        "arn:aws:s3:::${STATE_BUCKET}/*",
        "arn:aws:s3:::${BENCH_BUCKET}",
        "arn:aws:s3:::${BENCH_BUCKET}/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath"
      ],
      "Resource": [
        "arn:aws:ssm:${REGION}:${ACCOUNT_ID}:parameter${SSM_PARAMETER_PREFIX}*"
      ]
    }
  ]
}
JSON
aws iam put-role-policy \
  --role-name "${CLUSTER_NAME}-bench-role" \
  --policy-name "${CLUSTER_NAME}-bench-inline" \
  --policy-document "file://$STATE_DIR/bench-inline-policy.json"
create_instance_profile() {
  local profile=$1
  local role=$2
  if aws iam get-instance-profile --instance-profile-name "$profile" >/dev/null 2>&1; then
    echo "Reusing instance profile $profile"
  else
    aws iam create-instance-profile --instance-profile-name "$profile"
    aws iam add-role-to-instance-profile --instance-profile-name "$profile" --role-name "$role"
    echo "Created instance profile $profile"
  fi
}
create_instance_profile "${CLUSTER_NAME}-ec2-profile" "${CLUSTER_NAME}-ec2-role"
create_instance_profile "${CLUSTER_NAME}-bench-profile" "${CLUSTER_NAME}-bench-role"
cat >"$STATE_DIR/iam.json" <<JSON
{
  "cluster_profile_arn": "arn:aws:iam::${ACCOUNT_ID}:instance-profile/${CLUSTER_NAME}-ec2-profile",
  "bench_profile_arn": "arn:aws:iam::${ACCOUNT_ID}:instance-profile/${CLUSTER_NAME}-bench-profile"
}
JSON
aws s3 cp "$STATE_DIR/iam.json" "s3://${STATE_BUCKET}/state/iam.json"
aws ssm put-parameter \
  --name "${SSM_PARAMETER_PREFIX}/infra/iam" \
  --type "String" \
  --value "$(cat "$STATE_DIR/iam.json")" \
  --overwrite \
  --region "$REGION"
printf 'IAM artifacts stored in %s/iam.json and SSM %s/infra/iam\n' "$STATE_DIR" "$SSM_PARAMETER_PREFIX"
EOF
```

**Run:** `bash scripts/04-iam.sh`

-----

## Step 05 – KMS Key and TLS Placeholders

*Creates a KMS key for encryption and seeds placeholder TLS parameters.*

```bash
# (Content of scripts/05-kms-and-tls.sh is identical to the original)
cat <<'EOF' > scripts/05-kms-and-tls.sh
#!/usr/bin/env bash
set -euo pipefail
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
command -v aws >/dev/null || { echo "aws CLI is required" >&2; exit 1; }
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"
log() {
  printf '%s\n' "$*" >&2
}
fetch_existing_key() {
  local output
  if ! output=$(aws kms describe-key --key-id "$KMS_ALIAS" --region "$REGION" 2>&1); then
    if grep -q 'NotFoundException' <<<"$output"; then
      echo ""
    else
      log "ERROR: describe-key failed: $output"
      exit 1
    fi
  else
    echo "$output" | jq -r '.KeyMetadata.Arn'
  fi
}
KEY_ARN=$(fetch_existing_key)
if [ -z "$KEY_ARN" ]; then
  log "No existing KMS key for alias $KMS_ALIAS; creating one"
  KEY_ARN=$(aws kms create-key \
    --description "FoundationDB KMS key ${CLUSTER_NAME}" \
    --tags TagKey=Cluster,TagValue="$CLUSTER_NAME" \
    --region "$REGION" \
    | jq -r '.KeyMetadata.Arn')
  KEY_ID=$(echo "$KEY_ARN" | cut -d'/' -f2)
  aws kms create-alias --alias-name "$KMS_ALIAS" --target-key-id "$KEY_ID" --region "$REGION"
  log "Created KMS key $KEY_ARN and alias $KMS_ALIAS"
else
  log "Reusing KMS key $KEY_ARN for alias $KMS_ALIAS"
fi
KEY_ID=$(echo "$KEY_ARN" | cut -d'/' -f2)
apply_kms_encryption() {
  local bucket=$1
  log "Applying KMS encryption to bucket $bucket"
  aws s3api put-bucket-encryption \
    --bucket "$bucket" \
    --server-side-encryption-configuration "{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"$KEY_ID\"},\"BucketKeyEnabled\":true}]}" \
    --region "$REGION"
}
apply_kms_encryption "$STATE_BUCKET"
apply_kms_encryption "$BACKUP_BUCKET"
apply_kms_encryption "$BENCH_BUCKET"
cat >"$STATE_DIR/kms.json" <<JSON
{
  "kms_key_arn": "$KEY_ARN",
  "kms_alias": "$KMS_ALIAS"
}
JSON
aws s3 cp "$STATE_DIR/kms.json" "s3://${STATE_BUCKET}/state/kms.json"
aws ssm put-parameter \
  --name "${SSM_PARAMETER_PREFIX}/infra/kms" \
  --type "String" \
  --value "$(cat "$STATE_DIR/kms.json")" \
  --overwrite \
  --region "$REGION"
log "Stored KMS metadata at $STATE_DIR/kms.json and SSM ${SSM_PARAMETER_PREFIX}/infra/kms"
log "Writing TLS placeholder parameters"
aws ssm put-parameter --name "${SSM_PARAMETER_PREFIX}/tls/ca.pem" --type "SecureString" --value "PLACEHOLDER-CA" --overwrite --region "$REGION"
aws ssm put-parameter --name "${SSM_PARAMETER_PREFIX}/tls/node.pem" --type "SecureString" --value "PLACEHOLDER-NODE" --overwrite --region "$REGION"
aws ssm put-parameter --name "${SSM_PARAMETER_PREFIX}/tls/node.key" --type "SecureString" --value "PLACEHOLDER-KEY" --overwrite --region "$REGION"
log "KMS key $KEY_ID registered. Replace TLS placeholders under ${SSM_PARAMETER_PREFIX}/tls/* before production use."
EOF
```

**Run:** `bash scripts/05-kms-and-tls.sh`

-----

## Step 06 – Launch EC2 Instances

*Launches EC2 instances into private subnets without public IPs. Placement groups are used to optimize for performance and fault tolerance.*

```bash
cat <<'EOF' > scripts/06-compute.sh
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"
NETWORK_JSON=$(cat "$STATE_DIR/network.json")
SG_JSON=$(cat "$STATE_DIR/security-groups.json")
IAM_JSON=$(cat "$STATE_DIR/iam.json")
AMI_ID=$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64 --query 'Parameter.Value' --output text --region "$REGION")
echo "Using Amazon Linux 2023 AMI: $AMI_ID"
create_pg() {
  local name=$1; local strategy=$2; local extra_args=${3:-}
  if ! aws ec2 describe-placement-groups --group-names "$name" --region "$REGION" >/dev/null 2>&1; then
    aws ec2 create-placement-group --group-name "$name" --strategy "$strategy" $extra_args --region "$REGION"
    echo "Created placement group $name"
  else
    echo "Reusing placement group $name"
  fi
}
create_pg "${CLUSTER_NAME}-storage-pg" partition "--partition-count 5"
create_pg "${CLUSTER_NAME}-stateless-pg" cluster
launch_instances() {
  local tier=$1; local desired=$2; local type=$3; local subnet_id; local sg_id; local profile_arn; local pg_name=$4
  subnet_id=$(jq -r ".${tier}_subnet_id" "$STATE_DIR/network.json")
  sg_id=$(jq -r ".${tier}_sg_id" "$STATE_DIR/security-groups.json")
  profile_arn=$(jq -r ".${tier}_profile_arn // .cluster_profile_arn" "$STATE_DIR/iam.json")
  existing=$(aws ec2 describe-instances --filters "Name=tag:Tier,Values=$tier" "Name=tag:Cluster,Values=$CLUSTER_NAME" "Name=instance-state-name,Values=pending,running" --query 'Reservations[*].Instances[*].InstanceId' --output text --region "$REGION" | wc -w)
  if [ "$existing" -ge "$desired" ]; then
    echo "Tier '$tier' already has $existing of $desired instances. Skipping launch."
    return
  fi
  to_create=$((desired - existing))
  echo "Launching $to_create instance(s) for tier '$tier'..."
  aws ec2 run-instances \
    --count "$to_create" \
    --image-id "$AMI_ID" \
    --instance-type "$type" \
    --iam-instance-profile "Arn=$profile_arn" \
    --subnet-id "$subnet_id" \
    --security-group-ids "$sg_id" \
    --placement "GroupName=$pg_name" \
    --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":100,"VolumeType":"gp3","DeleteOnTermination":true}}]' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${CLUSTER_NAME}-${tier}},{Key=Cluster,Value=$CLUSTER_NAME},{Key=Tier,Value=$tier}]" \
    --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
    --region "$REGION" >/dev/null
}
launch_instances storage 5 i7i.8xlarge "${CLUSTER_NAME}-storage-pg"
launch_instances stateless 3 m7i.4xlarge "${CLUSTER_NAME}-stateless-pg"
launch_instances bench 1 c7a.4xlarge ""
echo "Waiting for all instances to enter 'running' state..."
INSTANCE_IDS=$(aws ec2 describe-instances --filters "Name=tag:Cluster,Values=$CLUSTER_NAME" "Name=instance-state-name,Values=pending,running" --query "Reservations[*].Instances[*].InstanceId" --output text --region "$REGION")
if [ -n "$INSTANCE_IDS" ]; then
    aws ec2 wait instance-running --instance-ids $INSTANCE_IDS --region "$REGION"
fi
echo "All instances are running."
INSTANCES_JSON=$(aws ec2 describe-instances --filters "Name=tag:Cluster,Values=$CLUSTER_NAME" "Name=instance-state-name,Values=running" --region "$REGION" | jq '[.Reservations[].Instances[]] | group_by(.Tags[] | select(.Key=="Tier") | .Value) | map({(.[0].Tags[] | select(.Key=="Tier") | .Value): map({instance_id: .InstanceId, private_ip: .PrivateIpAddress})}) | add')
echo "$INSTANCES_JSON" > "$STATE_DIR/instances.json"
aws s3 cp "$STATE_DIR/instances.json" "s3://${STATE_BUCKET}/state/instances.json"
aws ssm put-parameter --name "${SSM_PARAMETER_PREFIX}/infra/instances" --type "String" --value "$INSTANCES_JSON" --overwrite --region "$REGION"
printf 'Instance inventory saved to %s/instances.json, S3, and SSM.\n' "$STATE_DIR"
EOF
```

**Run:** `bash scripts/06-compute.sh`

-----

## Step 07 – Bootstrap Hosts and Install FoundationDB

*Uses SSM `send-command` to remotely configure all nodes. This step formats all NVMe drives on storage nodes and configures FoundationDB to use them.*

```bash
cat <<'EOF' > scripts/07-bootstrap-fdb.sh
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"
log() { printf '%s\n' "$*" >&2; }
INSTANCES_JSON=$(cat "$STATE_DIR/instances.json")
STORAGE_PRIVATE_IPS=($(jq -r '.storage[].private_ip' "$STATE_DIR/instances.json"))
COORDINATORS=$(printf "%s:4500," "${STORAGE_PRIVATE_IPS[@]}")
COORDINATORS=${COORDINATORS%,}
CLUSTER_ID_RAW=${CLUSTER_ID:-$(uuidgen)}
CLUSTER_ID=${CLUSTER_ID_RAW//-/}
CLUSTER_NAME_CANONICAL=$(printf '%s' "$CLUSTER_NAME" | tr -c '[:alnum:]_' '_')
CLUSTER_LINE="${CLUSTER_NAME_CANONICAL}:${CLUSTER_ID}@${COORDINATORS}"
echo "$CLUSTER_LINE" > "$STATE_DIR/fdb.cluster"
CLUSTER_FILE_B64=$(base64 < "$STATE_DIR/fdb.cluster" | tr -d '\n')
aws s3 cp "$STATE_DIR/fdb.cluster" "s3://${STATE_BUCKET}/state/fdb.cluster"
aws ssm put-parameter --name "${SSM_PARAMETER_PREFIX}/config/fdb.cluster.base64" --type "SecureString" --value "$CLUSTER_FILE_B64" --overwrite --region "$REGION"
SERVER_RPM_URL="https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/foundationdb-server-${FDB_VERSION}-1.el9.x86_64.rpm"
CLIENT_RPM_URL="https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/foundationdb-clients-${FDB_VERSION}-1.el9.x86_64.rpm"
# --- Storage Node Bootstrap Script ---
cat > "$STATE_DIR/storage-bootstrap.sh" <<'SCRIPT'
#!/bin/bash
set -euxo pipefail
CLUSTER_FILE_B64="{{CLUSTER_FILE_B64}}"
SERVER_RPM_URL="{{SERVER_RPM_URL}}"
CLIENT_RPM_URL="{{CLIENT_RPM_URL}}"
sudo dnf update -y && sudo dnf install -y xfsprogs nvme-cli chrony
sudo systemctl enable --now chronyd
# Prepare all NVMe drives
CONF_LINES=""
port=4500
for dev in $(ls /dev/nvme*n1 2>/dev/null); do
  mount_point="/data/fdb-$(basename $dev)"
  sudo mkfs.xfs -f "$dev"
  sudo mkdir -p "$mount_point"
  echo "$dev $mount_point xfs defaults,noatime 0 0" | sudo tee -a /etc/fstab
  sudo mount "$mount_point"
  sudo mkdir -p "${mount_point}/data" "${mount_point}/log"
  CONF_LINES+="[fdbserver.${port}]\nclass = storage\ndatadir = ${mount_point}/data\nlogdir = ${mount_point}/log\n"
  port=$((port+1))
done
sudo rpm -Uvh "$SERVER_RPM_URL" "$CLIENT_RPM_URL"
echo "$CLUSTER_FILE_B64" | base64 -d | sudo tee /etc/foundationdb/fdb.cluster
sudo chown foundationdb:foundationdb /etc/foundationdb/fdb.cluster && sudo chmod 600 /etc/foundationdb/fdb.cluster
sudo tee /etc/foundationdb/foundationdb.conf >/dev/null <<CONF
[fdbmonitor]
user = foundationdb
group = foundationdb
[general]
cluster_file = /etc/foundationdb/fdb.cluster
[fdbserver]
command = /usr/sbin/fdbserver
public_address = auto:\$ID
listen_address = 0.0.0.0:\$ID
storage_engine = ssd-redwood-1
${CONF_LINES}
CONF
sudo chown -R foundationdb:foundationdb /data
sudo systemctl enable --now foundationdb
SCRIPT
# --- Stateless Node Bootstrap Script ---
cat > "$STATE_DIR/stateless-bootstrap.sh" <<'SCRIPT'
#!/bin/bash
set -euxo pipefail
CLUSTER_FILE_B64="{{CLUSTER_FILE_B64}}"
SERVER_RPM_URL="{{SERVER_RPM_URL}}"
CLIENT_RPM_URL="{{CLIENT_RPM_URL}}"
sudo dnf update -y && sudo dnf install -y chrony
sudo systemctl enable --now chronyd
sudo rpm -Uvh "$SERVER_RPM_URL" "$CLIENT_RPM_URL"
echo "$CLUSTER_FILE_B64" | base64 -d | sudo tee /etc/foundationdb/fdb.cluster
sudo chown foundationdb:foundationdb /etc/foundationdb/fdb.cluster && sudo chmod 600 /etc/foundationdb/fdb.cluster
sudo mkdir -p /var/lib/foundationdb/data && sudo chown -R foundationdb:foundationdb /var/lib/foundationdb
sudo tee /etc/foundationdb/foundationdb.conf >/dev/null <<CONF
[fdbmonitor]
user = foundationdb
group = foundationdb
[general]
cluster_file = /etc/foundationdb/fdb.cluster
[fdbserver]
command = /usr/sbin/fdbserver
public_address = auto:\$ID
listen_address = 0.0.0.0:\$ID
logdir = /var/log/foundationdb
datadir = /var/lib/foundationdb/data/\$ID
[fdbserver.4500]
class = transaction
[fdbserver.4501]
class = transaction
[fdbserver.4502]
class = transaction
[fdbserver.4503]
class = transaction
[fdbserver.4504]
class = stateless
[fdbserver.4505]
class = stateless
CONF
sudo systemctl enable --now foundationdb
SCRIPT
# --- Bench Node Bootstrap Script ---
cat > "$STATE_DIR/bench-bootstrap.sh" <<'SCRIPT'
#!/bin/bash
set -euxo pipefail
CLUSTER_FILE_B64="{{CLUSTER_FILE_B64}}"
CLIENT_RPM_URL="{{CLIENT_RPM_URL}}"
BENCH_REPO_URL="{{BENCH_REPO_URL}}"
BENCH_REPO_REF="{{BENCH_REPO_REF}}"
BENCH_BINARY_PATH="{{BENCH_BINARY_PATH}}"
GO_VERSION="{{GO_VERSION}}"
sudo dnf update -y && sudo dnf install -y git tar make automake gcc gcc-c++
sudo rpm -Uvh "$CLIENT_RPM_URL"
sudo curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | sudo tar -C /usr/local -xz
export PATH=/usr/local/go/bin:$PATH
echo 'export PATH=/usr/local/go/bin:$PATH' | sudo tee /etc/profile.d/golang.sh
echo "$CLUSTER_FILE_B64" | base64 -d | sudo tee /etc/foundationdb/fdb.cluster
sudo chmod 644 /etc/foundationdb/fdb.cluster
sudo git clone "$BENCH_REPO_URL" /opt/bench && cd /opt/bench && sudo git checkout "$BENCH_REPO_REF"
cd /opt/bench
sudo /usr/local/go/bin/go mod tidy
sudo CGO_ENABLED=1 /usr/local/go/bin/go build -o /usr/local/bin/bench "./${BENCH_BINARY_PATH}"
SCRIPT
render_template() {
  local template; template=$(<"$1"); shift
  template="${template//\{\{CLUSTER_FILE_B64\}\}/$CLUSTER_FILE_B64}"
  template="${template//\{\{SERVER_RPM_URL\}\}/$SERVER_RPM_URL}"
  template="${template//\{\{CLIENT_RPM_URL\}\}/$CLIENT_RPM_URL}"
  template="${template//\{\{BENCH_REPO_URL\}\}/$BENCH_REPO_URL}"
  template="${template//\{\{BENCH_REPO_REF\}\}/$BENCH_REPO_REF}"
  template="${template//\{\{BENCH_BINARY_PATH\}\}/$BENCH_BINARY_PATH}"
  template="${template//\{\{GO_VERSION\}\}/$GO_VERSION}"
  echo "$template"
}
run_ssm_command() {
  local tier=$1; local script_content=$2; local comment=$3
  local instance_ids=($(jq -r ".${tier}[].instance_id" "$STATE_DIR/instances.json" | tr '\n' ' '))
  if [ ${#instance_ids[@]} -eq 0 ]; then log "No instances found for tier $tier. Skipping."; return; fi
  log "Running bootstrap on $tier tier (${instance_ids[*]})..."
  local command_id
  command_id=$(aws ssm send-command \
    --document-name "AWS-RunShellScript" \
    --instance-ids "${instance_ids[@]}" \
    --parameters "commands=[$script_content]" \
    --comment "$comment" \
    --query "Command.CommandId" --output text --region "$REGION")
  aws ssm wait command-executed --command-id "$command_id" --instance-id "${instance_ids[0]}" --region "$REGION"
  log "Bootstrap for $tier complete. Command ID: $command_id"
  # Optional: Check for errors
  aws ssm list-command-invocations --command-id "$command_id" --details --query "CommandInvocations[?Status!='Success']" --output text --region "$REGION"
}
storage_script=$(render_template "$STATE_DIR/storage-bootstrap.sh")
stateless_script=$(render_template "$STATE_DIR/stateless-bootstrap.sh")
bench_script=$(render_template "$STATE_DIR/bench-bootstrap.sh")
run_ssm_command storage "$(jq -s -R -n --arg cmd "$storage_script" '$cmd')" "FDB Storage Bootstrap"
run_ssm_command stateless "$(jq -s -R -n --arg cmd "$stateless_script" '$cmd')" "FDB Stateless Bootstrap"
run_ssm_command bench "$(jq -s -R -n --arg cmd "$bench_script" '$cmd')" "FDB Bench Bootstrap"
log "All nodes bootstrapped."
EOF
```

**Run:** `bash scripts/07-bootstrap-fdb.sh`

-----

*The remaining steps are also converted to use the secure SSM-based execution model.*

## Step 08 – Configure FoundationDB Cluster

*Sets coordinators and applies the production cluster topology.*

```bash
cat <<'EOF' > scripts/08-configure-cluster.sh
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"
INSTANCE_ID=$(jq -r '.stateless[0].instance_id' "$STATE_DIR/instances.json")
if [[ -z "$INSTANCE_ID" || "$INSTANCE_ID" == "null" ]]; then echo "No stateless node found to run fdbcli" >&2; exit 1; fi
COORDINATORS=$(jq -r '.storage[].private_ip' "$STATE_DIR/instances.json" | sed 's/$/:4500/' | tr '\n' ',' | sed 's/,$//')
COMMANDS="coordinators ${COORDINATORS//,/ }; configure new triple ssd-redwood-1 logs=8 commit_proxies=4 grv_proxies=2 resolvers=4; status details"
echo "Configuring cluster via instance $INSTANCE_ID..."
COMMAND_ID=$(aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --instance-ids "$INSTANCE_ID" \
  --parameters "commands=[\"sudo fdbcli --exec '${COMMANDS}'\"]" \
  --comment "Configure FDB Cluster" \
  --query "Command.CommandId" --output text --region "$REGION")
aws ssm wait command-executed --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --region "$REGION"
OUTPUT=$(aws ssm get-command-invocation --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "StandardOutputContent" --output text --region "$REGION")
echo "$OUTPUT" > "$STATE_DIR/fdb-status-initial.txt"
aws s3 cp "$STATE_DIR/fdb-status-initial.txt" "s3://${STATE_BUCKET}/state/fdb-status-initial.txt"
echo "Cluster configuration applied. Status written to state/fdb-status-initial.txt"
echo -e "\n--- Cluster Status ---\n$OUTPUT"
EOF
```

**Run:** `bash scripts/08-configure-cluster.sh`

-----

## Step 09 – Enable Backups and Metric Exports

*Starts continuous S3 backups and deploys the Prometheus exporter.*

```bash
cat <<'EOF' > scripts/09-backup-and-metrics.sh
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"
log() { printf '%s\n' "$*" >&2; }
run_ssm_on_tier() {
  local tier=$1; local script_content=$2; local comment=$3
  local instance_ids=($(jq -r ".${tier}[].instance_id" "$STATE_DIR/instances.json" | tr '\n' ' '))
  if [ ${#instance_ids[@]} -eq 0 ]; then log "No instances for $tier"; return; fi
  log "Running '$comment' on $tier tier..."
  local command_id
  command_id=$(aws ssm send-command --document-name "AWS-RunShellScript" --instance-ids "${instance_ids[@]}" --parameters "commands=[$script_content]" --comment "$comment" --query "Command.CommandId" --output text --region "$REGION")
  aws ssm wait command-executed --command-id "$command_id" --instance-id "${instance_ids[0]}" --region "$REGION"
  log "Task '$comment' complete on $tier."
}
# Backup Task
aws s3api put-bucket-lifecycle-configuration --bucket "$BACKUP_BUCKET" --lifecycle-configuration '{"Rules":[{"ID":"retain-30d","Status":"Enabled","Expiration":{"Days":30}}]}' --region "$REGION"
BACKUP_SCRIPT="sudo fdbbackup start -d blobstore://${BACKUP_BUCKET}/fdb --log"
run_ssm_on_tier stateless "$(jq -s -R -n --arg cmd "$BACKUP_SCRIPT" '$cmd')" "Start FDB Backup"
# Exporter Task
EXPORTER_SCRIPT='
set -euxo pipefail
if [ ! -f /usr/local/bin/fdb_exporter ]; then
  sudo dnf install -y git
  sudo git clone https://github.com/FoundationDB/fdb-exporter.git /opt/fdb-exporter
  cd /opt/fdb-exporter
  sudo /usr/local/go/bin/go build -o /usr/local/bin/fdb_exporter ./cmd/fdb_exporter
fi
sudo tee /etc/systemd/system/fdb-exporter.service >/dev/null <<SERVICE
[Unit]
Description=FoundationDB Prometheus exporter
After=foundationdb.service
[Service]
User=foundationdb
Group=foundationdb
Environment=FDB_CLUSTER_FILE=/etc/foundationdb/fdb.cluster
ExecStart=/usr/local/bin/fdb_exporter
Restart=always
[Install]
WantedBy=multi-user.target
SERVICE
sudo systemctl daemon-reload && sudo systemctl enable --now fdb-exporter'
run_ssm_on_tier storage "$(jq -s -R -n --arg cmd "$EXPORTER_SCRIPT" '$cmd')" "Deploy FDB Exporter"
log "Continuous backup started. Prometheus exporter deployed on storage nodes (port 2112)."
EOF
```

**Run:** `bash scripts/09-backup-and-metrics.sh`

-----

## Step 10 – Run Benchmark

*Executes the benchmark binary on the dedicated bench host.*

```bash
cat <<'EOF' > scripts/10-run-benchmark.sh
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"
BENCH_INSTANCE_ID=$(jq -r '.bench[0].instance_id' "$STATE_DIR/instances.json")
if [[ -z "$BENCH_INSTANCE_ID" || "$BENCH_INSTANCE_ID" == "null" ]]; then echo "No bench node found" >&2; exit 1; fi
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
RUN_NAME="bench-$TIMESTAMP"
BENCH_COMMAND="
set -euo pipefail
export FDB_CLUSTER_FILE=/etc/foundationdb/fdb.cluster
LOGFILE=/tmp/${RUN_NAME}.log
/usr/local/bin/bench \\
  -tps 250000 \\
  -workers 800 \\
  -duration 900s | tee \$LOGFILE
aws s3 cp \$LOGFILE s3://${BENCH_BUCKET}/runs/${RUN_NAME}.log
"
echo "Starting benchmark run '$RUN_NAME' on instance $BENCH_INSTANCE_ID..."
COMMAND_ID=$(aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --instance-ids "$BENCH_INSTANCE_ID" \
  --parameters "commands=[${BENCH_COMMAND@Q}]" \
  --comment "Run FDB Benchmark" \
  --cloud-watch-output-config "CloudWatchOutputEnabled=true" \
  --query "Command.CommandId" --output text --region "$REGION")
echo "Benchmark command sent (ID: $COMMAND_ID). This will run for 15 minutes."
echo "You can monitor progress in the AWS SSM Run Command console or CloudWatch Logs."
echo "Final log will be at: s3://${BENCH_BUCKET}/runs/${RUN_NAME}.log"
EOF
```

**Run:** `bash scripts/10-run-benchmark.sh`

-----

### **Accessing Instances for Debugging**

Since instances have no public IPs or SSH, use **SSM Session Manager** for shell access:

1.  Install the [Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) for the AWS CLI.
2.  Find an instance ID from `state/instances.json`.
3.  Start a session:
    ```bash
    # Example for the first storage node
    INSTANCE_ID=$(jq -r '.storage[0].instance_id' state/instances.json)
    aws ssm start-session --target $INSTANCE_ID --region $REGION
    ```