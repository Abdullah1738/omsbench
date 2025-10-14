# FoundationDB Production Deployment on AWS (Scripted)

These automation scripts provision a production-grade FoundationDB 7.3.69 cluster that can sustain hundreds of thousands of TPS using the Redwood storage engine, which is now recommended for high-performance deployments.citeturn0search0turn0search1 The plan fits within 224 vCPUs by using i7i.8xlarge storage nodes (32 vCPUs each), m7i.4xlarge stateless nodes (16 vCPUs each), and a c7a.4xlarge benchmark host (16 vCPUs).citeturn1search0turn2search0turn3search0 FoundationDB 7.3.69 remains the current stable release as of 14 Oct 2025.citeturn12search0

> **Scope**  
> - One AWS Region / single AZ (low latency, controlled failure domain).  
> - Five storage nodes, three stateless nodes, one benchmark node → 224 vCPUs total.  
> - State checkpoints saved to both the local `state/` directory and AWS Systems Manager Parameter Store for fast resume.  
> - Benchmark host runs `internal/bench/bench.go` co-located with the cluster.

---

## How to Use These Scripts

- Requirements on the operator workstation: `bash`, AWS CLI v2, `jq`, `uuidgen`, and `base64`.  
- Run everything from the repository root (`/Users/ardud/go-learn`).  
- Create helper directories once:
  ```bash
  mkdir -p scripts state logs
  ```
- Make scripts executable after generating them:
  ```bash
  chmod +x scripts/*.sh
  ```
- Unless specified, scripts are idempotent. Re-running them reconciles missing pieces.

Each step below introduces a shell script (created with a `cat` heredoc). Generate the file, mark it executable, then run it before moving to the next step.

---

## Step 00 – Bootstrap Environment Variables

Creates canonical environment files (`state/env.sh`, `state/env.json`) and pushes a base64 copy to Parameter Store for disaster recovery.

```bash
cat <<'EOF' > scripts/00-bootstrap-env.sh
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
mkdir -p "$STATE_DIR"

REGION=${REGION:-us-east-1}
AZ=${AZ:-us-east-1a}
CLUSTER_NAME=${CLUSTER_NAME:-foundationdb-prod}
ENV_ID=${ENV_ID:-$(date +%Y%m%d%H%M%S)}
VPC_CIDR=${VPC_CIDR:-10.42.0.0/20}
PUBLIC_SUBNET_CIDR=${PUBLIC_SUBNET_CIDR:-10.42.0.0/26}
STORAGE_SUBNET_CIDR=${STORAGE_SUBNET_CIDR:-10.42.0.64/26}
STATELESS_SUBNET_CIDR=${STATELESS_SUBNET_CIDR:-10.42.0.128/26}
BENCH_SUBNET_CIDR=${BENCH_SUBNET_CIDR:-10.42.0.192/26}
OBSERVABILITY_CIDR=${OBSERVABILITY_CIDR:-10.50.0.0/16}
FDB_VERSION=${FDB_VERSION:-7.3.69}
BENCH_NAMESPACE=${BENCH_NAMESPACE:-omsbench/prod}
BENCH_REPO_URL=${BENCH_REPO_URL:-https://github.com/your-org/go-learn.git}
BENCH_REPO_REF=${BENCH_REPO_REF:-main}
STATE_BUCKET=${STATE_BUCKET:-fdb-${CLUSTER_NAME}-${REGION}-${ENV_ID}-state}
BACKUP_BUCKET=${BACKUP_BUCKET:-fdb-${CLUSTER_NAME}-${REGION}-${ENV_ID}-backup}
BENCH_BUCKET=${BENCH_BUCKET:-fdb-${CLUSTER_NAME}-${REGION}-${ENV_ID}-bench}
DDB_TABLE=${DDB_TABLE:-fdb-${CLUSTER_NAME}-${ENV_ID}-lock}
KMS_ALIAS=${KMS_ALIAS:-alias/${CLUSTER_NAME}-kms}
FLOW_LOG_GROUP=${FLOW_LOG_GROUP:-/aws/vpcflow/${CLUSTER_NAME}}
SSM_PARAMETER_PREFIX=${SSM_PARAMETER_PREFIX:-/foundationdb/${CLUSTER_NAME}}
GO_VERSION=${GO_VERSION:-1.23.2}

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
export BENCH_NAMESPACE=$BENCH_NAMESPACE
export BENCH_REPO_URL=$BENCH_REPO_URL
export BENCH_REPO_REF=$BENCH_REPO_REF
export STATE_BUCKET=$STATE_BUCKET
export BACKUP_BUCKET=$BACKUP_BUCKET
export BENCH_BUCKET=$BENCH_BUCKET
export DDB_TABLE=$DDB_TABLE
export KMS_ALIAS=$KMS_ALIAS
export FLOW_LOG_GROUP=$FLOW_LOG_GROUP
export SSM_PARAMETER_PREFIX=$SSM_PARAMETER_PREFIX
export GO_VERSION=$GO_VERSION
ENV

cat >"$STATE_DIR/env.json" <<JSON
{
  "region": "$REGION",
  "az": "$AZ",
  "cluster_name": "$CLUSTER_NAME",
  "env_id": "$ENV_ID",
  "state_bucket": "$STATE_BUCKET",
  "backup_bucket": "$BACKUP_BUCKET",
  "bench_bucket": "$BENCH_BUCKET",
  "ddb_table": "$DDB_TABLE",
  "kms_alias": "$KMS_ALIAS",
  "fdb_version": "$FDB_VERSION",
  "bench_namespace": "$BENCH_NAMESPACE",
  "bench_repo_url": "$BENCH_REPO_URL",
  "bench_repo_ref": "$BENCH_REPO_REF",
  "go_version": "$GO_VERSION"
}
JSON

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

Run: `bash scripts/00-bootstrap-env.sh`  
Checkpoint artifacts: `state/env.sh`, `state/env.json`, SSM `${SSM_PARAMETER_PREFIX}/env/base64`.

---

## Step 01 – Create Buckets and DynamoDB Lock Table

Initialises versioned S3 buckets (state, backups, benchmark artifacts) with server-side encryption and a DynamoDB table for locking.

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
    if [ "$REGION" = "us-east-1" ]; then
      aws s3api create-bucket --bucket "$bucket" --region "$REGION"
    else
      aws s3api create-bucket --bucket "$bucket" --region "$REGION" \
        --create-bucket-configuration LocationConstraint="$REGION"
    fi
    aws s3api put-bucket-versioning \
      --bucket "$bucket" \
      --versioning-configuration Status=Enabled
    aws s3api put-bucket-encryption \
      --bucket "$bucket" \
      --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
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

cat >"$STATE_DIR/storage.json" <<JSON
{
  "state_bucket": "$STATE_BUCKET",
  "backup_bucket": "$BACKUP_BUCKET",
  "bench_bucket": "$BENCH_BUCKET",
  "ddb_table": "$DDB_TABLE"
}
JSON

aws s3 cp "$STATE_DIR/storage.json" "s3://${STATE_BUCKET}/state/storage.json"
aws ssm put-parameter \
  --name "${SSM_PARAMETER_PREFIX}/infra/storage" \
  --type "String" \
  --value "$(cat "$STATE_DIR/storage.json")" \
  --overwrite \
  --region "$REGION"

printf 'State stored in %s/storage.json, S3 (state/storage.json), and SSM %s/infra/storage\n' "$STATE_DIR" "$SSM_PARAMETER_PREFIX"
EOF
```

Run: `bash scripts/01-bootstrap-state.sh`  
Checkpoint artifacts: `state/storage.json`, `s3://$STATE_BUCKET/state/storage.json`, SSM `${SSM_PARAMETER_PREFIX}/infra/storage`.

---

## Step 02 – Provision VPC, Subnets, NAT, Endpoints, Flow Logs

Creates a single-AZ VPC with dedicated subnets, NAT gateway, interface endpoints for SSM, and CloudWatch VPC flow logs.

> Tip: If you already have a VPC that matches the target CIDR, export `EXISTING_VPC_ID=<vpc-id>` before running the script to reuse it and avoid hitting AWS VPC quota limits.

```bash
cat <<'EOF' > scripts/02-network.sh
#!/usr/bin/env bash
set -euo pipefail

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"

log() {
  printf '%s\n' "$*" >&2
}

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text --region "$REGION")

get_or_create_vpc() {
  local vpc_id
  if [ -n "${EXISTING_VPC_ID:-}" ]; then
    vpc_id="$EXISTING_VPC_ID"
    aws ec2 describe-vpcs --vpc-ids "$vpc_id" --region "$REGION" >/dev/null
    log "Using existing VPC $vpc_id from \$EXISTING_VPC_ID"
  else
    vpc_id=$(aws ec2 describe-vpcs \
      --filters "Name=tag:Cluster,Values=$CLUSTER_NAME" \
                "Name=cidr,Values=$VPC_CIDR" \
      --region "$REGION" \
      | jq -r '.Vpcs[0].VpcId // empty')
    if [ -z "$vpc_id" ]; then
      if ! output=$(aws ec2 create-vpc \
        --cidr-block "$VPC_CIDR" \
        --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=${CLUSTER_NAME}-vpc},{Key=Cluster,Value=$CLUSTER_NAME},{Key=Environment,Value=prod}]" \
        --region "$REGION"); then
        log "ERROR: failed to create VPC (quota likely exceeded). Delete an unused VPC or set EXISTING_VPC_ID to reuse a pre-created VPC, then rerun."
        exit 1
      fi
      vpc_id=$(echo "$output" | jq -r '.Vpc.VpcId')
      log "Created VPC $vpc_id"
    else
      log "Reusing VPC $vpc_id"
    fi
  fi
  aws ec2 modify-vpc-attribute --vpc-id "$vpc_id" --enable-dns-hostnames '{"Value":true}' --region "$REGION"
  aws ec2 modify-vpc-attribute --vpc-id "$vpc_id" --enable-dns-support '{"Value":true}' --region "$REGION"
  echo "$vpc_id"
}

get_or_create_subnet() {
  local name=$1
  local cidr=$2
  local map_public=$3
  local vpc_id=$4
  local subnet_id
  subnet_id=$(aws ec2 describe-subnets \
    --filters "Name=tag:Name,Values=${CLUSTER_NAME}-${name}" \
              "Name=vpc-id,Values=$vpc_id" \
    --region "$REGION" \
    | jq -r '.Subnets[0].SubnetId // empty')
  if [ -z "$subnet_id" ]; then
    subnet_id=$(aws ec2 create-subnet \
      --vpc-id "$vpc_id" \
      --cidr-block "$cidr" \
      --availability-zone "$AZ" \
      --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${CLUSTER_NAME}-${name}},{Key=Cluster,Value=$CLUSTER_NAME},{Key=Tier,Value=$name},{Key=Environment,Value=prod}]" \
      --region "$REGION" \
      | jq -r '.Subnet.SubnetId')
    if [ "$map_public" = "true" ]; then
      aws ec2 modify-subnet-attribute --subnet-id "$subnet_id" --map-public-ip-on-launch --region "$REGION"
    fi
    log "Created subnet $subnet_id for $name"
  else
    log "Reusing subnet $subnet_id for $name"
  fi
  echo "$subnet_id"
}

VPC_ID=$(get_or_create_vpc)
PUBLIC_SUBNET_ID=$(get_or_create_subnet public "$PUBLIC_SUBNET_CIDR" true "$VPC_ID")
STORAGE_SUBNET_ID=$(get_or_create_subnet storage "$STORAGE_SUBNET_CIDR" false "$VPC_ID")
STATELESS_SUBNET_ID=$(get_or_create_subnet stateless "$STATELESS_SUBNET_CIDR" false "$VPC_ID")
BENCH_SUBNET_ID=$(get_or_create_subnet bench "$BENCH_SUBNET_CIDR" false "$VPC_ID")

IGW_ID=$(aws ec2 describe-internet-gateways \
  --filters "Name=attachment.vpc-id,Values=$VPC_ID" \
  --region "$REGION" \
  | jq -r '.InternetGateways[0].InternetGatewayId // empty')
if [ -z "$IGW_ID" ]; then
  IGW_ID=$(aws ec2 create-internet-gateway \
    --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=${CLUSTER_NAME}-igw},{Key=Cluster,Value=$CLUSTER_NAME}]" \
    --region "$REGION" \
    | jq -r '.InternetGateway.InternetGatewayId')
  aws ec2 attach-internet-gateway --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID" --region "$REGION"
  log "Created IGW $IGW_ID"
else
  log "Reusing IGW $IGW_ID"
fi

allocate_eip_if_needed() {
  local allocation_id
  allocation_id=$(aws ec2 describe-addresses \
    --filters "Name=tag:Cluster,Values=$CLUSTER_NAME" "Name=domain,Values=vpc" \
    --region "$REGION" \
    | jq -r '.Addresses[0].AllocationId // empty')
  if [ -z "$allocation_id" ]; then
    allocation_id=$(aws ec2 allocate-address \
      --domain vpc \
      --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=${CLUSTER_NAME}-nat-eip},{Key=Cluster,Value=$CLUSTER_NAME}]" \
      --region "$REGION" \
      | jq -r '.AllocationId')
    log "Allocated EIP $allocation_id"
  else
    log "Reusing EIP $allocation_id"
  fi
  echo "$allocation_id"
}

ALLOCATION_ID=$(allocate_eip_if_needed)

PUBLIC_RT_ID=$(aws ec2 describe-route-tables \
  --filters "Name=tag:Name,Values=${CLUSTER_NAME}-public-rt" "Name=vpc-id,Values=$VPC_ID" \
  --region "$REGION" \
  | jq -r '.RouteTables[0].RouteTableId // empty')
if [ -z "$PUBLIC_RT_ID" ]; then
  PUBLIC_RT_ID=$(aws ec2 create-route-table \
    --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${CLUSTER_NAME}-public-rt},{Key=Cluster,Value=$CLUSTER_NAME}]" \
    --region "$REGION" \
    | jq -r '.RouteTable.RouteTableId')
  aws ec2 associate-route-table --route-table-id "$PUBLIC_RT_ID" --subnet-id "$PUBLIC_SUBNET_ID" --region "$REGION"
  aws ec2 create-route \
    --route-table-id "$PUBLIC_RT_ID" \
    --destination-cidr-block "0.0.0.0/0" \
    --gateway-id "$IGW_ID" \
    --region "$REGION" || true
  log "Created public route table $PUBLIC_RT_ID"
else
  log "Reusing public route table $PUBLIC_RT_ID"
fi

NAT_ID=$(aws ec2 describe-nat-gateways \
  --filter "Name=tag:Name,Values=${CLUSTER_NAME}-nat" \
           "Name=vpc-id,Values=$VPC_ID" \
           "Name=state,Values=available,pending" \
  --region "$REGION" \
  | jq -r '.NatGateways[0].NatGatewayId // empty')
if [ -z "$NAT_ID" ]; then
  NAT_ID=$(aws ec2 create-nat-gateway \
    --allocation-id "$ALLOCATION_ID" \
    --subnet-id "$PUBLIC_SUBNET_ID" \
    --tag-specifications "ResourceType=natgateway,Tags=[{Key=Name,Value=${CLUSTER_NAME}-nat},{Key=Cluster,Value=$CLUSTER_NAME}]" \
    --region "$REGION" \
    | jq -r '.NatGateway.NatGatewayId')
  aws ec2 wait nat-gateway-available --nat-gateway-ids "$NAT_ID" --region "$REGION"
  log "Created NAT $NAT_ID"
else
  log "Reusing NAT $NAT_ID"
fi

create_private_rt() {
  local name=$1
  local subnet_id=$2
  local rt_id
  rt_id=$(aws ec2 describe-route-tables \
    --filters "Name=tag:Name,Values=${CLUSTER_NAME}-${name}-rt" "Name=vpc-id,Values=$VPC_ID" \
    --region "$REGION" \
    | jq -r '.RouteTables[0].RouteTableId // empty')
  if [ -z "$rt_id" ]; then
    rt_id=$(aws ec2 create-route-table \
      --vpc-id "$VPC_ID" \
      --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${CLUSTER_NAME}-${name}-rt},{Key=Cluster,Value=$CLUSTER_NAME}]" \
      --region "$REGION" \
      | jq -r '.RouteTable.RouteTableId')
    aws ec2 associate-route-table --route-table-id "$rt_id" --subnet-id "$subnet_id" --region "$REGION"
    aws ec2 create-route \
      --route-table-id "$rt_id" \
      --destination-cidr-block "0.0.0.0/0" \
      --nat-gateway-id "$NAT_ID" \
      --region "$REGION" || true
    log "Created route table $rt_id for $name"
  else
    log "Reusing route table $rt_id for $name"
  fi
  echo "$rt_id"
}

STORAGE_RT_ID=$(create_private_rt storage "$STORAGE_SUBNET_ID")
STATELESS_RT_ID=$(create_private_rt stateless "$STATELESS_SUBNET_ID")
BENCH_RT_ID=$(create_private_rt bench "$BENCH_SUBNET_ID")

aws iam create-service-linked-role --aws-service-name vpc-flow-logs.amazonaws.com >/dev/null 2>&1 || true
aws logs create-log-group --log-group-name "$FLOW_LOG_GROUP" --region "$REGION" >/dev/null 2>&1 || true

FLOW_LOG_ID=$(aws ec2 describe-flow-logs \
  --filter "Name=log-group-name,Values=$FLOW_LOG_GROUP" "Name=resource-id,Values=$VPC_ID" \
  --region "$REGION" \
  | jq -r '.FlowLogs[0].FlowLogId // empty')
if [ -z "$FLOW_LOG_ID" ]; then
  FLOW_LOG_ID=$(aws ec2 create-flow-logs \
    --resource-type VPC \
    --resource-ids "$VPC_ID" \
    --traffic-type ALL \
    --log-group-name "$FLOW_LOG_GROUP" \
    --deliver-logs-permission-arn "arn:aws:iam::$ACCOUNT_ID:role/aws-service-role/vpc-flow-logs.amazonaws.com/AWSServiceRoleForVPCFlowLogs" \
    --region "$REGION" \
    | jq -r '.FlowLogIds[0]')
  log "Created flow log $FLOW_LOG_ID"
else
  log "Reusing flow log $FLOW_LOG_ID"
fi

create_endpoint() {
  local service=$1
  local endpoint_id
  endpoint_id=$(aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=service-name,Values=com.amazonaws.${REGION}.${service}" \
    --region "$REGION" \
    | jq -r '.VpcEndpoints[0].VpcEndpointId // empty')
  if [ -z "$endpoint_id" ]; then
    local default_sg
    default_sg=$(aws ec2 describe-security-groups \
      --filters Name=vpc-id,Values=$VPC_ID Name=group-name,Values=default \
      --region "$REGION" \
      | jq -r '.SecurityGroups[0].GroupId')
    if ! output=$(aws ec2 create-vpc-endpoint \
      --vpc-id "$VPC_ID" \
      --vpc-endpoint-type Interface \
      --service-name "com.amazonaws.${REGION}.${service}" \
      --subnet-ids "$STATELESS_SUBNET_ID" \
      --security-group-ids "$default_sg" \
      --private-dns-enabled \
      --tag-specifications "ResourceType=vpc-endpoint,Tags=[{Key=Name,Value=${CLUSTER_NAME}-${service}-endpoint},{Key=Cluster,Value=$CLUSTER_NAME}]" \
      --region "$REGION"); then
      log "ERROR: failed to create VPC endpoint for service $service. Resolve the AWS error (e.g. subnet AZ conflicts) and rerun."
      exit 1
    fi
    endpoint_id=$(echo "$output" | jq -r '.VpcEndpoint.VpcEndpointId')
    aws ec2 wait vpc-endpoint-available --vpc-endpoint-ids "$endpoint_id" --region "$REGION"
    log "Created endpoint $endpoint_id for $service"
  else
    log "Reusing endpoint $endpoint_id for $service"
  fi
  echo "$endpoint_id"
}

SSM_EP_ID=$(create_endpoint ssm)
EC2MSG_EP_ID=$(create_endpoint ec2messages)
SSMMSG_EP_ID=$(create_endpoint ssmmessages)
LOGS_EP_ID=$(create_endpoint logs)

cat >"$STATE_DIR/network.json" <<JSON
{
  "vpc_id": "$VPC_ID",
  "public_subnet_id": "$PUBLIC_SUBNET_ID",
  "storage_subnet_id": "$STORAGE_SUBNET_ID",
  "stateless_subnet_id": "$STATELESS_SUBNET_ID",
  "bench_subnet_id": "$BENCH_SUBNET_ID",
  "internet_gateway_id": "$IGW_ID",
  "nat_gateway_id": "$NAT_ID",
  "public_route_table_id": "$PUBLIC_RT_ID",
  "storage_route_table_id": "$STORAGE_RT_ID",
  "stateless_route_table_id": "$STATELESS_RT_ID",
  "bench_route_table_id": "$BENCH_RT_ID",
  "flow_log_id": "$FLOW_LOG_ID",
  "endpoints": {
    "ssm": "$SSM_EP_ID",
    "ec2messages": "$EC2MSG_EP_ID",
    "ssmmessages": "$SSMMSG_EP_ID",
    "logs": "$LOGS_EP_ID"
  }
}
JSON

aws s3 cp "$STATE_DIR/network.json" "s3://${STATE_BUCKET}/state/network.json"
aws ssm put-parameter \
  --name "${SSM_PARAMETER_PREFIX}/infra/network" \
  --type "String" \
  --value "$(cat "$STATE_DIR/network.json")" \
  --overwrite \
  --region "$REGION"

printf 'Network state saved to %s/network.json, S3, and SSM %s/infra/network\n' "$STATE_DIR" "$SSM_PARAMETER_PREFIX"

EOF
EOF
EOF
```

Run: `bash scripts/02-network.sh`  
Checkpoint artifacts: `state/network.json`, `s3://$STATE_BUCKET/state/network.json`, SSM `${SSM_PARAMETER_PREFIX}/infra/network`.

---

## Step 03 – Create Security Groups

Defines security boundaries for storage, stateless, and benchmark tiers with intra-cluster rules and points their route tables at the internet gateway so public IPv4 addresses stay reachable for SSH.

> Set `SSH_ALLOWED_CIDR` in `state/env.sh` (for example, `SSH_ALLOWED_CIDR=203.0.113.0/24`) before running this step so SSH access is restricted to your network. If unset, the script defaults to `0.0.0.0/0`.
> The script reuses `state/network.json` to swap the `storage`, `stateless`, and `bench` route tables (`0.0.0.0/0`) over to the internet gateway recorded in Step 02, ensuring those subnets can accept SSH to their public IPv4 addresses.

```bash
cat <<'EOF' > scripts/03-security-groups.sh
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"
SSH_ALLOWED_CIDR=${SSH_ALLOWED_CIDR:-0.0.0.0/0}

log() {
  printf '%s\n' "$*" >&2
}

NETWORK_JSON=$(cat "$STATE_DIR/network.json")
VPC_ID=$(echo "$NETWORK_JSON" | jq -r '.vpc_id')
IGW_ID=$(echo "$NETWORK_JSON" | jq -r '.internet_gateway_id')
STORAGE_RT_ID=$(echo "$NETWORK_JSON" | jq -r '.storage_route_table_id // empty')
STATELESS_RT_ID=$(echo "$NETWORK_JSON" | jq -r '.stateless_route_table_id // empty')
BENCH_RT_ID=$(echo "$NETWORK_JSON" | jq -r '.bench_route_table_id // empty')

if [ -z "$IGW_ID" ] || [ "$IGW_ID" = "null" ]; then
  log "Internet gateway ID missing from network.json; rerun Step 02 before continuing."
  exit 1
fi

ensure_public_route() {
  local tier=$1
  local rt_id=$2
  if [ -z "$rt_id" ] || [ "$rt_id" = "null" ]; then
    log "Skipping IGW route update for $tier; no route table recorded."
    return
  fi

  local current_via
  current_via=$(aws ec2 describe-route-tables \
    --route-table-ids "$rt_id" \
    --region "$REGION" \
    | jq -r '.RouteTables[0].Routes[] | select(.DestinationCidrBlock=="0.0.0.0/0") | (.GatewayId // .NatGatewayId // .NetworkInterfaceId // empty)')

  if [ "$current_via" = "$IGW_ID" ]; then
    log "Route table $rt_id already sends 0.0.0.0/0 to internet gateway for $tier."
    return
  fi

  if aws ec2 replace-route \
    --route-table-id "$rt_id" \
    --destination-cidr-block "0.0.0.0/0" \
    --gateway-id "$IGW_ID" \
    --region "$REGION" >/dev/null 2>&1; then
    log "Updated route table $rt_id to use internet gateway for $tier."
    return
  fi

  if aws ec2 create-route \
    --route-table-id "$rt_id" \
    --destination-cidr-block "0.0.0.0/0" \
    --gateway-id "$IGW_ID" \
    --region "$REGION" >/dev/null 2>&1; then
    log "Created default route via internet gateway for $tier (table $rt_id)."
    return
  fi

  log "ERROR: Failed to configure internet gateway route for $tier (table $rt_id)."
  exit 1
}

create_sg() {
  local name=$1
  local description=$2
  local sg_id
  sg_id=$(aws ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=${CLUSTER_NAME}-${name}-sg" \
    --region "$REGION" \
    | jq -r '.SecurityGroups[0].GroupId // empty')
  if [ -z "$sg_id" ]; then
    sg_id=$(aws ec2 create-security-group \
      --group-name "${CLUSTER_NAME}-${name}-sg" \
      --description "$description" \
      --vpc-id "$VPC_ID" \
      --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=${CLUSTER_NAME}-${name}-sg},{Key=Cluster,Value=$CLUSTER_NAME},{Key=Tier,Value=$name}]" \
      --region "$REGION" \
      | jq -r '.GroupId')
    log "Created SG $sg_id for $name"
  else
    log "Reusing SG $sg_id for $name"
  fi
  echo "$sg_id"
}

STORAGE_SG_ID=$(create_sg storage "FoundationDB storage servers")
STATELESS_SG_ID=$(create_sg stateless "FoundationDB stateless tier")
BENCH_SG_ID=$(create_sg bench "Benchmark host")

allow_rule() {
  local sg_id=$1
  local proto=$2
  local from=$3
  local to=$4
  local src=$5
  aws ec2 authorize-security-group-ingress \
    --group-id "$sg_id" \
    --ip-permissions "[{\"IpProtocol\":\"$proto\",\"FromPort\":$from,\"ToPort\":$to,$src}]" \
    --region "$REGION" >/dev/null 2>&1 || true
}

allow_ssh() {
  local sg_id=$1
  aws ec2 authorize-security-group-ingress \
    --group-id "$sg_id" \
    --protocol tcp \
    --port 22 \
    --cidr "$SSH_ALLOWED_CIDR" \
    --region "$REGION" >/dev/null 2>&1 || true
}

# Egress allow all
aws ec2 revoke-security-group-egress --group-id "$STORAGE_SG_ID" --ip-permission 'IpProtocol=-1,IpRanges=[]' --region "$REGION" >/dev/null 2>&1 || true
aws ec2 authorize-security-group-egress --group-id "$STORAGE_SG_ID" --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' --region "$REGION" >/dev/null 2>&1 || true
aws ec2 revoke-security-group-egress --group-id "$STATELESS_SG_ID" --ip-permission 'IpProtocol=-1,IpRanges=[]' --region "$REGION" >/dev/null 2>&1 || true
aws ec2 authorize-security-group-egress --group-id "$STATELESS_SG_ID" --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' --region "$REGION" >/dev/null 2>&1 || true
aws ec2 revoke-security-group-egress --group-id "$BENCH_SG_ID" --ip-permission 'IpProtocol=-1,IpRanges=[]' --region "$REGION" >/dev/null 2>&1 || true
aws ec2 authorize-security-group-egress --group-id "$BENCH_SG_ID" --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' --region "$REGION" >/dev/null 2>&1 || true

# Storage <-> Storage & Stateless
allow_rule "$STORAGE_SG_ID" tcp 4500 4599 "\"UserIdGroupPairs\":[{\"GroupId\":\"$STORAGE_SG_ID\"},{\"GroupId\":\"$STATELESS_SG_ID\"}]"

# Stateless inbound (from storage/stateless)
allow_rule "$STATELESS_SG_ID" tcp 4500 4599 "\"UserIdGroupPairs\":[{\"GroupId\":\"$STORAGE_SG_ID\"},{\"GroupId\":\"$STATELESS_SG_ID\"}]"

allow_ssh "$STORAGE_SG_ID"
allow_ssh "$STATELESS_SG_ID"
allow_ssh "$BENCH_SG_ID"

# Ensure public IPv4 routes land on the internet gateway so SSH succeeds once instances receive public IPs
ensure_public_route storage "$STORAGE_RT_ID"
ensure_public_route stateless "$STATELESS_RT_ID"
ensure_public_route bench "$BENCH_RT_ID"

# Bench outbound only (SSM)
allow_rule "$BENCH_SG_ID" tcp 2112 2112 "\"IpRanges\":[{\"CidrIp\":\"${OBSERVABILITY_CIDR}\"}]"

cat >"$STATE_DIR/security-groups.json" <<JSON
{
  "storage_sg_id": "$STORAGE_SG_ID",
  "stateless_sg_id": "$STATELESS_SG_ID",
  "bench_sg_id": "$BENCH_SG_ID"
}
JSON

aws s3 cp "$STATE_DIR/security-groups.json" "s3://${STATE_BUCKET}/state/security-groups.json"
aws ssm put-parameter \
  --name "${SSM_PARAMETER_PREFIX}/infra/security-groups" \
  --type "String" \
  --value "$(cat "$STATE_DIR/security-groups.json")" \
  --overwrite \
  --region "$REGION"

printf 'Security groups persisted to %s/security-groups.json and SSM %s/infra/security-groups\n' "$STATE_DIR" "$SSM_PARAMETER_PREFIX"

EOF
EOF
```

Run: `bash scripts/03-security-groups.sh`  
Checkpoint artifacts: `state/security-groups.json`, `s3://$STATE_BUCKET/state/security-groups.json`, SSM `${SSM_PARAMETER_PREFIX}/infra/security-groups`.

---

## Step 04 – IAM Roles, Policies, Instance Profiles

Creates EC2 roles for FoundationDB nodes and the benchmark host with the required managed policies plus scoped S3/SSM access.

```bash
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
          "kms:ViaService": "ssm.${REGION}.amazonaws.com"
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
  "cluster_role": "${CLUSTER_NAME}-ec2-role",
  "cluster_profile": "${CLUSTER_NAME}-ec2-profile",
  "bench_role": "${CLUSTER_NAME}-bench-role",
  "bench_profile": "${CLUSTER_NAME}-bench-profile"
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

Run: `bash scripts/04-iam.sh`  
Checkpoint artifacts: `state/iam.json`, `s3://$STATE_BUCKET/state/iam.json`, SSM `${SSM_PARAMETER_PREFIX}/infra/iam`.

---

## Step 05 – KMS Key and TLS Parameter Placeholders

Creates a dedicated KMS key, updates bucket encryption to use it, and seeds TLS parameter placeholders ready for real certs.

```bash
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
    echo "$output" | jq -r '.KeyMetadata.KeyId'
  fi
}

KEY_ID=$(fetch_existing_key)

if [ -z "$KEY_ID" ]; then
  log "No existing KMS key for alias $KMS_ALIAS; creating one"
  KEY_ID=$(aws kms create-key \
    --description "FoundationDB KMS key ${CLUSTER_NAME}" \
    --tags TagKey=Cluster,TagValue="$CLUSTER_NAME" \
    --region "$REGION" \
    | jq -r '.KeyMetadata.KeyId')
  aws kms create-alias --alias-name "$KMS_ALIAS" --target-key-id "$KEY_ID" --region "$REGION"
  log "Created KMS key $KEY_ID and alias $KMS_ALIAS"
else
  log "Reusing KMS key $KEY_ID for alias $KMS_ALIAS"
fi

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
  "kms_key_id": "$KEY_ID",
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
aws ssm put-parameter \
  --name "${SSM_PARAMETER_PREFIX}/tls/ca.pem" \
  --type "SecureString" \
  --value "PLACEHOLDER-CA" \
  --overwrite \
  --region "$REGION"

aws ssm put-parameter \
  --name "${SSM_PARAMETER_PREFIX}/tls/node.pem" \
  --type "SecureString" \
  --value "PLACEHOLDER-NODE" \
  --overwrite \
  --region "$REGION"

aws ssm put-parameter \
  --name "${SSM_PARAMETER_PREFIX}/tls/node.key" \
  --type "SecureString" \
  --value "PLACEHOLDER-KEY" \
  --overwrite \
  --region "$REGION"

log "KMS key $KEY_ID registered. Replace TLS placeholders under ${SSM_PARAMETER_PREFIX}/tls/* before production use."

EOF
EOF
EOF
```

Run: `bash scripts/05-kms-and-tls.sh`  
Checkpoint artifacts: `state/kms.json`, `s3://$STATE_BUCKET/state/kms.json`, SSM `${SSM_PARAMETER_PREFIX}/infra/kms` (plus TLS placeholders).

---

## Step 06 – Launch EC2 Instances (Storage, Stateless, Benchmark)

Creates placement groups, fetches the latest Amazon Linux 2023 AMI, and launches EC2 instances tagged per tier with public IPv4 addresses for SSH access (restricted by `SSH_ALLOWED_CIDR` from Step 03).

```bash
cat <<'EOF' > scripts/06-compute.sh
#!/usr/bin/env bash
set -euo pipefail

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"
KEY_NAME="${SSH_KEY_NAME:-${KEY_NAME:-}}"

if [ -z "$KEY_NAME" ]; then
  echo "Set SSH_KEY_NAME or KEY_NAME in env.sh to the EC2 key pair name." >&2
  exit 1
fi

NETWORK_JSON=$(cat "$STATE_DIR/network.json")
SECURITY_JSON=$(cat "$STATE_DIR/security-groups.json")
IAM_JSON=$(cat "$STATE_DIR/iam.json")

VPC_ID=$(echo "$NETWORK_JSON" | jq -r '.vpc_id')
STORAGE_SUBNET_ID=$(echo "$NETWORK_JSON" | jq -r '.storage_subnet_id')
STATELESS_SUBNET_ID=$(echo "$NETWORK_JSON" | jq -r '.stateless_subnet_id')
BENCH_SUBNET_ID=$(echo "$NETWORK_JSON" | jq -r '.bench_subnet_id')

STORAGE_SG_ID=$(echo "$SECURITY_JSON" | jq -r '.storage_sg_id')
STATELESS_SG_ID=$(echo "$SECURITY_JSON" | jq -r '.stateless_sg_id')
BENCH_SG_ID=$(echo "$SECURITY_JSON" | jq -r '.bench_sg_id')

CLUSTER_PROFILE=$(echo "$IAM_JSON" | jq -r '.cluster_profile')
BENCH_PROFILE=$(echo "$IAM_JSON" | jq -r '.bench_profile')

fetch_ami() {
  aws ssm get-parameter \
    --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64 \
    --region "$REGION" \
    | jq -r '.Parameter.Value'
}

AMI_ID=$(fetch_ami)
echo "Using AMI $AMI_ID"

create_pg_if_absent() {
  local name=$1
  local strategy=$2
  local args=${3:-}
  if aws ec2 describe-placement-groups --group-names "$name" --region "$REGION" >/dev/null 2>&1; then
    echo "Reusing placement group $name"
  else
    aws ec2 create-placement-group --group-name "$name" --strategy "$strategy" $args --region "$REGION"
    echo "Created placement group $name"
  fi
}

create_pg_if_absent "${CLUSTER_NAME}-storage-pg" partition "--partition-count 5"
create_pg_if_absent "${CLUSTER_NAME}-stateless-pg" cluster

launch_instances() {
  local tier=$1
  local desired=$2
  local instance_type=$3
  local subnet_id=$4
  local sg_id=$5
  local profile=$6
  local placement_group=$7

  existing=$(aws ec2 describe-instances \
    --filters "Name=tag:Cluster,Values=$CLUSTER_NAME" \
              "Name=tag:Tier,Values=$tier" \
              "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --region "$REGION" \
    | jq '[.Reservations[].Instances[] | select(.State.Name != "terminated")] | length')
  if [ "$existing" -ge "$desired" ]; then
    echo "Tier $tier already has $existing instances"
    return
  fi

  to_create=$((desired - existing))
  echo "Launching $to_create $tier instance(s)"
  aws ec2 run-instances \
    --count "$to_create" \
    --image-id "$AMI_ID" \
    --instance-type "$instance_type" \
    --iam-instance-profile "Name=$profile" \
    --key-name "$KEY_NAME" \
    --subnet-id "$subnet_id" \
    --security-group-ids "$sg_id" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${CLUSTER_NAME}-${tier}},{Key=Cluster,Value=$CLUSTER_NAME},{Key=Environment,Value=prod},{Key=Tier,Value=$tier}]" \
    --associate-public-ip-address \
    --placement "AvailabilityZone=$AZ,GroupName=$placement_group" \
    --block-device-mappings '[
        {"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":100,"VolumeType":"gp3","DeleteOnTermination":true}}
      ]' \
    --region "$REGION" >/dev/null
}

launch_instances storage 5 "i7i.8xlarge" "$STORAGE_SUBNET_ID" "$STORAGE_SG_ID" "$CLUSTER_PROFILE" "${CLUSTER_NAME}-storage-pg"
launch_instances stateless 3 "m7i.4xlarge" "$STATELESS_SUBNET_ID" "$STATELESS_SG_ID" "$CLUSTER_PROFILE" "${CLUSTER_NAME}-stateless-pg"
launch_instances bench 1 "c7a.4xlarge" "$BENCH_SUBNET_ID" "$BENCH_SG_ID" "$BENCH_PROFILE" ""

aws ec2 wait instance-running \
  --instance-ids $(aws ec2 describe-instances \
    --filters "Name=tag:Cluster,Values=$CLUSTER_NAME" \
              "Name=instance-state-name,Values=pending,running" \
    --region "$REGION" \
    | jq -r '.Reservations[].Instances[].InstanceId') \
  --region "$REGION"

INSTANCES_JSON=$(aws ec2 describe-instances \
  --filters "Name=tag:Cluster,Values=$CLUSTER_NAME" \
            "Name=instance-state-name,Values=running,stopped" \
  --region "$REGION" \
  | jq '[.Reservations[].Instances[] | select(.State.Name != "terminated")] | group_by(.Tags[] | select(.Key=="Tier") | .Value) | map({(.[0].Tags[] | select(.Key=="Tier") | .Value): map({instance_id: .InstanceId, private_ip: .PrivateIpAddress, public_ip: (.PublicIpAddress // null)})}) | add')

echo "$INSTANCES_JSON" | jq '.' > "$STATE_DIR/instances.json"
aws s3 cp "$STATE_DIR/instances.json" "s3://${STATE_BUCKET}/state/instances.json"
aws ssm put-parameter \
  --name "${SSM_PARAMETER_PREFIX}/infra/instances" \
  --type "String" \
  --value "$(cat "$STATE_DIR/instances.json")" \
  --overwrite \
  --region "$REGION"

printf 'Instance inventory written to %s/instances.json and SSM %s/infra/instances\n' "$STATE_DIR" "$SSM_PARAMETER_PREFIX"

EOF
EOF
```

Run: `bash scripts/06-compute.sh`  
Checkpoint artifacts: `state/instances.json`, `s3://$STATE_BUCKET/state/instances.json`, SSM `${SSM_PARAMETER_PREFIX}/infra/instances` (includes both private and public IPv4 addresses per tier).

---

## Step 07 – Bootstrap Hosts and Install FoundationDB

Downloads the required RPMs directly from the 7.3.69 release, formats NVMe storage, writes `foundationdb.conf`, and distributes the cluster file across storage/stateless/benchmark nodes.

> Ensure SSH access is configured (see Step 03 for `SSH_ALLOWED_CIDR`) and provide the EC2 private key via `SSH_KEY_PATH` or as the first argument when invoking the script (for example, `bash scripts/07-bootstrap-fdb.sh ~/.ssh/abdullah.pem`).

```bash
cat <<'EOF' > scripts/07-bootstrap-fdb.sh
#!/usr/bin/env bash
set -euo pipefail

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
command -v uuidgen >/dev/null || { echo "uuidgen is required" >&2; exit 1; }

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"

log() {
  printf '%s\n' "$*" >&2
}

KEY_ARG=${1:-}
if [[ -n "$KEY_ARG" ]]; then
  SSH_KEY_PATH="$KEY_ARG"
fi

if [[ -z "${SSH_KEY_PATH:-}" ]]; then
  echo "Usage: $0 /path/to/private-key" >&2
  echo "       or export SSH_KEY_PATH before running." >&2
  exit 1
fi

if [[ ! -f "$SSH_KEY_PATH" ]]; then
  echo "SSH key $SSH_KEY_PATH not found." >&2
  exit 1
fi

SSH_USER=${SSH_USER:-ec2-user}
SSH_OPTS=(
  -i "$SSH_KEY_PATH"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=10
  -o BatchMode=yes
)

INSTANCES_JSON=$(cat "$STATE_DIR/instances.json")

STORAGE_IPS=($(echo "$INSTANCES_JSON" | jq -r '.storage[]?.private_ip'))
STORAGE_IDS=($(echo "$INSTANCES_JSON" | jq -r '.storage[]?.instance_id'))
STATELESS_IDS=($(echo "$INSTANCES_JSON" | jq -r '.stateless[]?.instance_id'))
BENCH_ID=$(echo "$INSTANCES_JSON" | jq -r '.bench[0]?.instance_id')
BENCH_IP=$(echo "$INSTANCES_JSON" | jq -r '.bench[0]?.private_ip // empty')

if [ ${#STORAGE_IPS[@]} -ne 5 ]; then
  echo "Expected 5 storage nodes; found ${#STORAGE_IPS[@]}" >&2
  exit 1
fi

CLUSTER_ID=${CLUSTER_ID:-$(uuidgen)}
COORDINATORS=$(printf "%s:4500," "${STORAGE_IPS[@]}")
COORDINATORS=${COORDINATORS%,}
CLUSTER_LINE="${CLUSTER_NAME}:${CLUSTER_ID}@${COORDINATORS}"

echo "$CLUSTER_LINE" > "$STATE_DIR/fdb.cluster"
aws s3 cp "$STATE_DIR/fdb.cluster" "s3://${STATE_BUCKET}/state/fdb.cluster"
aws ssm put-parameter \
  --name "${SSM_PARAMETER_PREFIX}/config/fdb.cluster.base64" \
  --type "SecureString" \
  --value "$(base64 <"$STATE_DIR/fdb.cluster" | tr -d '\n')" \
  --overwrite \
  --region "$REGION"

COORD_JSON=$(printf '"%s:4500",' "${STORAGE_IPS[@]}")
COORD_JSON="[${COORD_JSON%,}]"

cat >"$STATE_DIR/cluster.json" <<JSON
{
  "cluster_id": "$CLUSTER_ID",
  "coordinators": $COORD_JSON,
  "cluster_file_s3": "s3://${STATE_BUCKET}/state/fdb.cluster"
}
JSON

aws s3 cp "$STATE_DIR/cluster.json" "s3://${STATE_BUCKET}/state/cluster.json"
aws ssm put-parameter \
  --name "${SSM_PARAMETER_PREFIX}/config/cluster" \
  --type "String" \
  --value "$(cat "$STATE_DIR/cluster.json")" \
  --overwrite \
  --region "$REGION"

release_json=$(curl -fsSL "https://api.github.com/repos/apple/foundationdb/releases/tags/${FDB_VERSION}")

select_rpm() {
  local component=$1
  local arch=${2:-x86_64}
  local url
  for distro in el9 el8 el7; do
    local name="foundationdb-${component}-${FDB_VERSION}-1.${distro}.${arch}.rpm"
    url=$(echo "$release_json" | jq -r --arg name "$name" '.assets[] | select(.name==$name) | .browser_download_url')
    if [ -n "$url" ] && [ "$url" != "null" ]; then
      echo "$url"
      return
    fi
  done
  echo ""
}

SERVER_RPM_URL=$(select_rpm server)
CLIENT_RPM_URL=$(select_rpm clients)

if [ -z "$SERVER_RPM_URL" ] || [ -z "$CLIENT_RPM_URL" ]; then
  echo "Unable to locate FoundationDB server/client RPM assets for version ${FDB_VERSION}" >&2
  exit 1
fi

wait_for_ssh() {
  local ip=$1
  local attempt=1
  while [ $attempt -le 36 ]; do
    if ssh "${SSH_OPTS[@]}" "$SSH_USER@$ip" 'exit 0' >/dev/null 2>&1; then
      log "SSH reachable: $ip"
      return
    fi
    log "Waiting for SSH on $ip (attempt $attempt/36)..."
    sleep 5
    attempt=$((attempt + 1))
  done
  echo "ERROR: Unable to reach $ip via SSH after waiting." >&2
  exit 1
}

render_template() {
  local template=$1
  local destination=$2
  sed -e "s|{{FDB_VERSION}}|$FDB_VERSION|g" \
      -e "s|{{SERVER_RPM_URL}}|$SERVER_RPM_URL|g" \
      -e "s|{{CLIENT_RPM_URL}}|$CLIENT_RPM_URL|g" \
      -e "s|{{CLUSTER_FILE_B64}}|$CLUSTER_FILE_B64|g" \
      -e "s|{{REGION}}|$REGION|g" \
      -e "s|{{SSM_PARAMETER_PREFIX}}|$SSM_PARAMETER_PREFIX|g" \
      -e "s|{{BENCH_REPO_URL}}|$BENCH_REPO_URL|g" \
      -e "s|{{BENCH_REPO_REF}}|$BENCH_REPO_REF|g" \
      -e "s|{{GO_VERSION}}|$GO_VERSION|g" \
      -e "s|{{BENCH_NAMESPACE}}|$BENCH_NAMESPACE|g" \
      "$template" > "$destination"
}

run_remote_script() {
  local tier=$1
  local ip=$2
  local script_path=$3
  local remote="/tmp/bootstrap-${tier}.sh"
  wait_for_ssh "$ip"
  log "Uploading ${tier} bootstrap to $ip"
  scp -i "$SSH_KEY_PATH" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "$script_path" "$SSH_USER@$ip:$remote"
  log "Executing ${tier} bootstrap on $ip"
  ssh "${SSH_OPTS[@]}" "$SSH_USER@$ip" "chmod +x $remote && sudo bash $remote"
}

CLUSTER_FILE_B64=$(base64 <"$STATE_DIR/fdb.cluster" | tr -d '\n')

cat >"$STATE_DIR/storage-bootstrap.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

FDB_VERSION="{{FDB_VERSION}}"
SERVER_RPM_URL="{{SERVER_RPM_URL}}"
CLIENT_RPM_URL="{{CLIENT_RPM_URL}}"
CLUSTER_FILE_B64="{{CLUSTER_FILE_B64}}"
REGION="{{REGION}}"
SSM_PARAMETER_PREFIX="{{SSM_PARAMETER_PREFIX}}"

sudo dnf update -y
sudo dnf install -y jq nvme-cli chrony xfsprogs
sudo systemctl enable --now chronyd

for dev in $(ls /dev/nvme*n1 2>/dev/null); do
  mount_point="/data/$(basename "$dev")"
  sudo umount "$dev" >/dev/null 2>&1 || true
  sudo mkfs.xfs -f "$dev"
  sudo mkdir -p "$mount_point"
  grep -q "$dev" /etc/fstab || echo "$dev $mount_point xfs defaults,noatime 0 0" | sudo tee -a /etc/fstab >/dev/null
  sudo mount "$mount_point"
done

sudo mkdir -p /data/nvme0/fdb-{4500,4501,4502,4503,4504,4505}
sudo chown -R foundationdb:foundationdb /data/nvme0

tmpdir=$(mktemp -d)
curl -fsSL "$SERVER_RPM_URL" -o "$tmpdir/server.rpm"
curl -fsSL "$CLIENT_RPM_URL" -o "$tmpdir/clients.rpm"
sudo rpm -Uvh --replacepkgs "$tmpdir/"*.rpm

echo "$CLUSTER_FILE_B64" | base64 -d | sudo tee /etc/foundationdb/fdb.cluster >/dev/null
sudo chown foundationdb:foundationdb /etc/foundationdb/fdb.cluster
sudo chmod 600 /etc/foundationdb/fdb.cluster

sudo tee /etc/foundationdb/foundationdb.conf >/dev/null <<CONF
[fdbmonitor]
user = foundationdb
group = foundationdb

[general]
cluster_file = /etc/foundationdb/fdb.cluster

[fdbserver]
command = /usr/sbin/fdbserver
listen_address = PUBLIC
public_address = auto:\$ID
datadir = /data/nvme0/fdb-\$ID
logdir = /var/log/foundationdb
class = storage
storage_engine = ssd-redwood-1
knob_redwood_mem_fraction = 0.45
knob_redwood_target_page_fill_pct = 0.6

[fdbserver.4500]
[fdbserver.4501]
[fdbserver.4502]
[fdbserver.4503]
[fdbserver.4504]
[fdbserver.4505]
CONF

sudo systemctl enable foundationdb
sudo systemctl restart foundationdb
SCRIPT

cat >"$STATE_DIR/stateless-bootstrap.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

FDB_VERSION="{{FDB_VERSION}}"
SERVER_RPM_URL="{{SERVER_RPM_URL}}"
CLIENT_RPM_URL="{{CLIENT_RPM_URL}}"
CLUSTER_FILE_B64="{{CLUSTER_FILE_B64}}"

sudo dnf update -y
sudo dnf install -y jq chrony
sudo systemctl enable --now chronyd

tmpdir=$(mktemp -d)
curl -fsSL "$SERVER_RPM_URL" -o "$tmpdir/server.rpm"
curl -fsSL "$CLIENT_RPM_URL" -o "$tmpdir/clients.rpm"
sudo rpm -Uvh --replacepkgs "$tmpdir/"*.rpm

sudo mkdir -p /var/lib/foundationdb/data/{4500,4501,4502,4503,4504,4505}
sudo chown -R foundationdb:foundationdb /var/lib/foundationdb

echo "$CLUSTER_FILE_B64" | base64 -d | sudo tee /etc/foundationdb/fdb.cluster >/dev/null
sudo chown foundationdb:foundationdb /etc/foundationdb/fdb.cluster
sudo chmod 600 /etc/foundationdb/fdb.cluster

sudo tee /etc/foundationdb/foundationdb.conf >/dev/null <<CONF
[fdbmonitor]
user = foundationdb
group = foundationdb

[general]
cluster_file = /etc/foundationdb/fdb.cluster

[fdbserver]
command = /usr/sbin/fdbserver
listen_address = PUBLIC
public_address = auto:\$ID
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

sudo systemctl enable foundationdb
sudo systemctl restart foundationdb
SCRIPT

cat >"$STATE_DIR/bench-bootstrap.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

CLIENT_RPM_URL="{{CLIENT_RPM_URL}}"
CLUSTER_FILE_B64="{{CLUSTER_FILE_B64}}"
BENCH_REPO_URL="{{BENCH_REPO_URL}}"
BENCH_REPO_REF="{{BENCH_REPO_REF}}"
GO_VERSION="{{GO_VERSION}}"
BENCH_NAMESPACE="{{BENCH_NAMESPACE}}"

sudo dnf update -y
sudo dnf install -y jq git tar

tmpdir=$(mktemp -d)
curl -fsSL "$CLIENT_RPM_URL" -o "$tmpdir/clients.rpm"
sudo rpm -Uvh --replacepkgs "$tmpdir/clients.rpm"

GO_TARBALL="https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
curl -fsSL "$GO_TARBALL" -o "$tmpdir/go.tgz"
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "$tmpdir/go.tgz"
echo 'export PATH=/usr/local/go/bin:$PATH' | sudo tee /etc/profile.d/golang.sh >/dev/null

sudo mkdir -p /etc/foundationdb
echo "$CLUSTER_FILE_B64" | base64 -d | sudo tee /etc/foundationdb/fdb.cluster >/dev/null
sudo chown root:root /etc/foundationdb/fdb.cluster
sudo chmod 600 /etc/foundationdb/fdb.cluster

mkdir -p /opt/bench
if [ ! -d /opt/bench/.git ]; then
  git clone "$BENCH_REPO_URL" /opt/bench
fi
cd /opt/bench
git fetch origin "$BENCH_REPO_REF"
git checkout "$BENCH_REPO_REF"
PATH=/usr/local/go/bin:$PATH go build ./internal/bench
cat <<EOF >/opt/bench/.bench.env
export FDB_CLUSTER_FILE=/etc/foundationdb/fdb.cluster
export BENCH_NAMESPACE=$BENCH_NAMESPACE
EOF
SCRIPT

storage_script="$STATE_DIR/storage-bootstrap-rendered.sh"
stateless_script="$STATE_DIR/stateless-bootstrap-rendered.sh"
bench_script="$STATE_DIR/bench-bootstrap-rendered.sh"

render_template "$STATE_DIR/storage-bootstrap.sh" "$storage_script"
render_template "$STATE_DIR/stateless-bootstrap.sh" "$stateless_script"
render_template "$STATE_DIR/bench-bootstrap.sh" "$bench_script"

for ip in "${STORAGE_IPS[@]}"; do
  run_remote_script "storage" "$ip" "$storage_script"
done

STATELESS_IPS=($(echo "$INSTANCES_JSON" | jq -r '.stateless[]?.private_ip'))
for ip in "${STATELESS_IPS[@]}"; do
  run_remote_script "stateless" "$ip" "$stateless_script"
done

if [[ -n "$BENCH_IP" ]]; then
  run_remote_script "bench" "$BENCH_IP" "$bench_script"
fi

printf 'FoundationDB packages deployed and cluster file distributed. Cluster ID %s\n' "$CLUSTER_ID"

EOF
EOF
SCRIPT

storage_script="$STATE_DIR/storage-bootstrap-rendered.sh"
stateless_script="$STATE_DIR/stateless-bootstrap-rendered.sh"
bench_script="$STATE_DIR/bench-bootstrap-rendered.sh"

render_template "$STATE_DIR/storage-bootstrap.sh" "$storage_script"
render_template "$STATE_DIR/stateless-bootstrap.sh" "$stateless_script"
render_template "$STATE_DIR/bench-bootstrap.sh" "$bench_script"

for ip in "${STORAGE_IPS[@]}"; do
  run_remote_script "storage" "$ip" "$storage_script"
done

STATELESS_IPS=($(echo "$INSTANCES_JSON" | jq -r '.stateless[]?.private_ip'))
for ip in "${STATELESS_IPS[@]}"; do
  run_remote_script "stateless" "$ip" "$stateless_script"
done

if [[ -n "$BENCH_IP" ]]; then
  run_remote_script "bench" "$BENCH_IP" "$bench_script"
fi

printf 'FoundationDB packages deployed and cluster file distributed. Cluster ID %s\n' "$CLUSTER_ID"

EOF
EOF
SCRIPT



Run:
```bash
bash scripts/07-bootstrap-fdb.sh ~/.ssh/abdullah.pem   # or set SSH_KEY_PATH before invoking
```
Checkpoint artifacts: `state/fdb.cluster`, `state/cluster.json`, `s3://$STATE_BUCKET/state/fdb.cluster`, SSM `${SSM_PARAMETER_PREFIX}/config/fdb.cluster.base64`, SSM `${SSM_PARAMETER_PREFIX}/config/cluster`.

---

## Step 08 – Configure FoundationDB Cluster

Sets coordinators, applies Redwood triple replication, tunes proxies/resolvers/logs, and captures status output. Uses `fdbcli configure` which is the supported pathway for topology and redundancy configuration.citeturn4search0

```bash
cat <<'EOF' > scripts/08-configure-cluster.sh
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"

INSTANCES_JSON=$(cat "$STATE_DIR/instances.json")
STAT_NODE_ID=$(echo "$INSTANCES_JSON" | jq -r '.stateless[0].instance_id')
STORAGE_IPS=$(echo "$INSTANCES_JSON" | jq -r '.storage[].private_ip')

if [ -z "$STAT_NODE_ID" ]; then
  echo "No stateless node available for fdbcli" >&2
  exit 1
fi

COORDINATORS=$(echo "$STORAGE_IPS" | awk '{printf "%s:4500 ", $1}' | xargs | sed 's/ /,/g')

cat >"$STATE_DIR/configure-cluster.sh" <<SCRIPT
#!/usr/bin/env bash
set -euo pipefail

sudo fdbcli --exec "coordinators $COORDINATORS"
sudo fdbcli --exec "configure new triple ssd-redwood-1 logs=8 commit_proxies=4 grv_proxies=2 resolvers=4"
sudo fdbcli --exec "status details" | tee /tmp/fdb-status.txt
SCRIPT

SCRIPT_KEY="scripts/configure-cluster-${ENV_ID}.sh"
aws s3 cp "$STATE_DIR/configure-cluster.sh" "s3://${STATE_BUCKET}/${SCRIPT_KEY}" --region "$REGION"

cat >"$STATE_DIR/configure-commands.json" <<JSON
{
  "commands": [
    "aws s3 cp s3://${STATE_BUCKET}/${SCRIPT_KEY} /tmp/configure-cluster.sh --region ${REGION}",
    "sudo bash /tmp/configure-cluster.sh"
  ]
}
JSON

CMD_OUTPUT=$(aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --parameters file://"$STATE_DIR/configure-commands.json" \
  --instance-ids "$STAT_NODE_ID" \
  --comment "${CLUSTER_NAME} configure" \
  --region "$REGION")

CMD_ID=$(echo "$CMD_OUTPUT" | jq -r '.Command.CommandId')
aws ssm wait command-executed --command-id "$CMD_ID" --instance-id "$STAT_NODE_ID" --region "$REGION"

aws ssm get-command-invocation --command-id "$CMD_ID" --instance-id "$STAT_NODE_ID" --region "$REGION" \
  | jq -r '.StandardOutputContent' > "$STATE_DIR/fdb-status-initial.txt"

aws s3 cp "$STATE_DIR/fdb-status-initial.txt" "s3://${STATE_BUCKET}/state/fdb-status-initial.txt"

printf 'Cluster configured. Status snapshot in %s/fdb-status-initial.txt\n' "$STATE_DIR"
EOF
```

Run: `bash scripts/08-configure-cluster.sh`  
Checkpoint artifacts: `state/fdb-status-initial.txt`, `s3://$STATE_BUCKET/state/fdb-status-initial.txt`.

---

## Step 09 – Enable Backups and Metric Exports

Starts continuous backups to the dedicated S3 bucket, sets lifecycle retention, and configures Prometheus scrape via a lightweight exporter.

```bash
cat <<'EOF' > scripts/09-backup-and-metrics.sh
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"

INSTANCES_JSON=$(cat "$STATE_DIR/instances.json")
STATELESS_IDS=($(echo "$INSTANCES_JSON" | jq -r '.stateless[]?.instance_id'))
STORAGE_IDS=($(echo "$INSTANCES_JSON" | jq -r '.storage[]?.instance_id'))

aws s3api put-bucket-lifecycle-configuration \
  --bucket "$BACKUP_BUCKET" \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "retain-30-days",
      "Status": "Enabled",
      "Transitions": [{"Days": 7, "StorageClass": "STANDARD_IA"}],
      "Expiration": {"Days": 30}
    }]
  }' \
  --region "$REGION"

cat >"$STATE_DIR/backup-template.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

sudo systemctl restart foundationdb
sudo fdbbackup abort -d blobstore://{{BACKUP_BUCKET}}/fdb >/dev/null 2>&1 || true
sudo fdbbackup start -d blobstore://{{BACKUP_BUCKET}}/fdb --log
SCRIPT

sed "s|{{BACKUP_BUCKET}}|$BACKUP_BUCKET|g" "$STATE_DIR/backup-template.sh" > "$STATE_DIR/backup.sh"

BACKUP_KEY="scripts/ops-backup-${ENV_ID}.sh"
aws s3 cp "$STATE_DIR/backup.sh" "s3://${STATE_BUCKET}/${BACKUP_KEY}" --region "$REGION"

cat >"$STATE_DIR/backup-commands.json" <<JSON
{
  "commands": [
    "aws s3 cp s3://${STATE_BUCKET}/${BACKUP_KEY} /tmp/backup.sh --region ${REGION}",
    "sudo bash /tmp/backup.sh"
  ]
}
JSON

CMD_OUTPUT=$(aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --parameters file://"$STATE_DIR/backup-commands.json" \
  --targets "Key=tag:Tier,Values=stateless" \
  --comment "${CLUSTER_NAME} backup start" \
  --region "$REGION")

CMD_ID=$(echo "$CMD_OUTPUT" | jq -r '.Command.CommandId')
for id in "${STATELESS_IDS[@]}"; do
  aws ssm wait command-executed --command-id "$CMD_ID" --instance-id "$id" --region "$REGION"
done

cat >"$STATE_DIR/exporter-template.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

if [ ! -x /usr/local/go/bin/go ]; then
  tmpdir=$(mktemp -d)
  curl -fsSL https://go.dev/dl/go{{GO_VERSION}}.linux-amd64.tar.gz -o "$tmpdir/go.tgz"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "$tmpdir/go.tgz"
  sudo rm -rf "$tmpdir"
fi

sudo dnf install -y git
sudo mkdir -p /opt/fdb-exporter
if [ ! -d /opt/fdb-exporter/.git ]; then
  sudo git clone https://github.com/FoundationDB/fdb-exporter.git /opt/fdb-exporter
fi
cd /opt/fdb-exporter
PATH=/usr/local/go/bin:$PATH sudo /usr/local/go/bin/go build ./cmd/fdb_exporter
sudo tee /etc/systemd/system/fdb-exporter.service >/dev/null <<SERVICE
[Unit]
Description=FoundationDB Prometheus exporter
After=network.target

[Service]
User=foundationdb
Group=foundationdb
Environment=FDB_CLUSTER_FILE=/etc/foundationdb/fdb.cluster
ExecStart=/opt/fdb-exporter/fdb_exporter --listen=:2112
Restart=always

[Install]
WantedBy=multi-user.target
SERVICE
sudo systemctl daemon-reload
sudo systemctl enable --now fdb-exporter
SCRIPT

sed "s|{{GO_VERSION}}|$GO_VERSION|g" "$STATE_DIR/exporter-template.sh" > "$STATE_DIR/exporter.sh"

EXPORTER_KEY="scripts/ops-exporter-${ENV_ID}.sh"
aws s3 cp "$STATE_DIR/exporter.sh" "s3://${STATE_BUCKET}/${EXPORTER_KEY}" --region "$REGION"

cat >"$STATE_DIR/exporter-commands.json" <<JSON
{
  "commands": [
    "aws s3 cp s3://${STATE_BUCKET}/${EXPORTER_KEY} /tmp/exporter.sh --region ${REGION}",
    "sudo bash /tmp/exporter.sh"
  ]
}
JSON

EXP_CMD=$(aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --parameters file://"$STATE_DIR/exporter-commands.json" \
  --targets "Key=tag:Tier,Values=storage" \
  --comment "${CLUSTER_NAME} exporter" \
  --region "$REGION")

EXP_ID=$(echo "$EXP_CMD" | jq -r '.Command.CommandId')
for id in "${STORAGE_IDS[@]}"; do
  aws ssm wait command-executed --command-id "$EXP_ID" --instance-id "$id" --region "$REGION"
done

printf 'Continuous backup started and Prometheus exporter enabled on storage nodes (port 2112).\n'
EOF
```

Run: `bash scripts/09-backup-and-metrics.sh`  
Checkpoint artifacts: backup lifecycle applied, exporter service running (verify via `aws ssm send-command` as needed).

---

## Step 10 – Run Benchmark (`internal/bench/bench.go`)

Executes the benchmark from the bench host, logs Prometheus metrics, and persists output to S3 for traceability.

```bash
cat <<'EOF' > scripts/10-run-benchmark.sh
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR="$SCRIPT_DIR/../state"
source "$STATE_DIR/env.sh"

INSTANCES_JSON=$(cat "$STATE_DIR/instances.json")
BENCH_ID=$(echo "$INSTANCES_JSON" | jq -r '.bench[0].instance_id')

TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
RUN_NAME="bench-${TIMESTAMP}"

cat >"$STATE_DIR/bench-template.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/local/go/bin:$PATH
export FDB_CLUSTER_FILE=/etc/foundationdb/fdb.cluster
export BENCH_NAMESPACE="{{BENCH_NAMESPACE}}"
cd /opt/bench
./bench \
  -cluster-file "$FDB_CLUSTER_FILE" \
  -directory "$BENCH_NAMESPACE" \
  -tps 250000 \
  -workers 800 \
  -duration 900s \
  -tx-timeout 300ms \
  -histogram "0.5,1,2,4,8" | tee /tmp/{{RUN_NAME}}.log
aws s3 cp /tmp/{{RUN_NAME}}.log s3://{{BENCH_BUCKET}}/runs/{{RUN_NAME}}.log
SCRIPT

sed -e "s|{{BENCH_NAMESPACE}}|$BENCH_NAMESPACE|g" \
    -e "s|{{RUN_NAME}}|$RUN_NAME|g" \
    -e "s|{{BENCH_BUCKET}}|$BENCH_BUCKET|g" \
    "$STATE_DIR/bench-template.sh" > "$STATE_DIR/bench.sh"

BENCH_KEY="scripts/bench-run-${RUN_NAME}.sh"
aws s3 cp "$STATE_DIR/bench.sh" "s3://${STATE_BUCKET}/${BENCH_KEY}" --region "$REGION"

cat >"$STATE_DIR/bench-commands.json" <<JSON
{
  "commands": [
    "aws s3 cp s3://${STATE_BUCKET}/${BENCH_KEY} /tmp/bench.sh --region ${REGION}",
    "bash /tmp/bench.sh"
  ]
}
JSON

CMD_OUTPUT=$(aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --parameters file://"$STATE_DIR/bench-commands.json" \
  --instance-ids "$BENCH_ID" \
  --comment "${CLUSTER_NAME} benchmark ${RUN_NAME}" \
  --region "$REGION")

CMD_ID=$(echo "$CMD_OUTPUT" | jq -r '.Command.CommandId')
echo "Benchmark command ${CMD_ID} running; waiting for completion (this takes ~15 minutes)..."
aws ssm wait command-executed --command-id "$CMD_ID" --instance-id "$BENCH_ID" --region "$REGION"

printf 'Benchmark completed as %s; logs stored at s3://%s/runs/%s.log\n' "$RUN_NAME" "$BENCH_BUCKET" "$RUN_NAME"
EOF
```

Run: `bash scripts/10-run-benchmark.sh`  
Checkpoint artifacts: `s3://$BENCH_BUCKET/runs/bench-<timestamp>.log`.

---

## Resume & Disaster Recovery Notes

1. To recreate environment variables, download the Parameter Store backup:
   ```bash
   aws ssm get-parameter --name "${SSM_PARAMETER_PREFIX}/env/base64" --with-decryption --region "$REGION" \
     | jq -r '.Parameter.Value' | base64 -d > state/env.sh
   source state/env.sh
   ```
2. Repeat scripts in order; each step skips existing resources safely.
3. Cluster file and instance inventory remain in `state/` and S3; ensure TLS secrets are refreshed before client use.

---

## Reference Checklist

- [ ] `scripts/00` through `scripts/10` executed successfully with state artifacts in S3 and Parameter Store.  
- [ ] FoundationDB status (`state/fdb-status-initial.txt`) shows `healthy` and `Full replication`.  
- [ ] Continuous backup running (`fdbbackup status`).  
- [ ] Prometheus exporter responding on `http://<storage-ip>:2112/metrics`.  
- [ ] Benchmark output archived under `s3://${BENCH_BUCKET}/runs/`.

---

**Next Steps**  
1. Replace TLS placeholders with real certificates in Parameter Store before handing credentials to clients.  
2. Set up automated validation of backup restore using a periodic scratch environment.  
3. Integrate exporter metrics with your monitoring stack (AMP, Prometheus, or Grafana Cloud) and alert on FoundationDB health indicators.
