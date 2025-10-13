# FoundationDB Benchmark on AWS EKS

This guide shows how to use the AWS CLI to deploy a single‑region, multi‑AZ FoundationDB cluster on Amazon EKS and run the `omsbench` workload from a dedicated EC2 instance to target **100k–500k TPS** while exporting p50/p99 latency metrics.

> **Prerequisites**
>
> - AWS CLI v2 configured with sufficient permissions (EKS, EC2, IAM, CloudFormation, CloudWatch, SSM).
> - `kubectl` v1.30+ and `eksctl` *optional* (not required in the steps below).
> - `jq`, `openssl`, and `base64`.
> - Go 1.24+ on the workstation (for building the benchmark binary) or on the EC2 runner.

---

## 1. Define Deployment Parameters

```bash
export AWS_REGION=us-east-1
export CLUSTER_NAME=fdb-oms
export VPC_CIDR=10.50.0.0/16
export SUBNET1_CIDR=10.50.0.0/19
export SUBNET2_CIDR=10.50.32.0/19
export SUBNET3_CIDR=10.50.64.0/19
export AZ1=${AWS_REGION}a
export AZ2=${AWS_REGION}b
export AZ3=${AWS_REGION}c
export K8S_VERSION=1.30
export NODE_INSTANCE_TYPE=c7i.4xlarge
export NODE_COUNT=6
export FDB_VERSION=7.3.28
export FDB_OPERATOR_VERSION=v2.15.0  # pin to a published operator release tag
```

Create a helper script so you can restore the variables after opening a new shell:

```bash
cat <<EOF > env.fdb
export AWS_REGION=${AWS_REGION}
export CLUSTER_NAME=${CLUSTER_NAME}
export VPC_CIDR=${VPC_CIDR}
export SUBNET1_CIDR=${SUBNET1_CIDR}
export SUBNET2_CIDR=${SUBNET2_CIDR}
export SUBNET3_CIDR=${SUBNET3_CIDR}
export AZ1=${AZ1}
export AZ2=${AZ2}
export AZ3=${AZ3}
export K8S_VERSION=${K8S_VERSION}
export NODE_INSTANCE_TYPE=${NODE_INSTANCE_TYPE}
export NODE_COUNT=${NODE_COUNT}
export FDB_VERSION=${FDB_VERSION}
export FDB_OPERATOR_VERSION=${FDB_OPERATOR_VERSION}
EOF
chmod +x env.fdb
echo "To restore later, run: source env.fdb"
```

Review the operator’s release page to confirm the tag before applying manifests.citeturn0search4

---

## 2. Networking (VPC + Subnets)

### 2.Resume
```bash
source env.fdb 2>/dev/null || true

# Recreate IDs if the environment is empty
export VPC_ID=$(aws ec2 describe-vpcs \
  --filters Name=tag:Name,Values=${CLUSTER_NAME}-vpc \
  --query 'Vpcs[0].VpcId' --output text)

export IGW_ID=$(aws ec2 describe-internet-gateways \
  --filters Name=attachment.vpc-id,Values=${VPC_ID} \
  --query 'InternetGateways[0].InternetGatewayId' --output text)

export ROUTE_TABLE_ID=$(aws ec2 describe-route-tables \
  --filters Name=vpc-id,Values=${VPC_ID} Name=tag:Name,Values=${CLUSTER_NAME}-rt \
  --query 'RouteTables[0].RouteTableId' --output text)

export SUBNET1_ID=$(aws ec2 describe-subnets \
  --filters Name=vpc-id,Values=${VPC_ID} Name=tag:Name,Values=${CLUSTER_NAME}-subnet-a \
  --query 'Subnets[0].SubnetId' --output text)
export SUBNET2_ID=$(aws ec2 describe-subnets \
  --filters Name=vpc-id,Values=${VPC_ID} Name=tag:Name,Values=${CLUSTER_NAME}-subnet-b \
  --query 'Subnets[0].SubnetId' --output text)
export SUBNET3_ID=$(aws ec2 describe-subnets \
  --filters Name=vpc-id,Values=${VPC_ID} Name=tag:Name,Values=${CLUSTER_NAME}-subnet-c \
  --query 'Subnets[0].SubnetId' --output text)

cat <<EOF >> env.fdb
export VPC_ID=${VPC_ID}
export IGW_ID=${IGW_ID}
export ROUTE_TABLE_ID=${ROUTE_TABLE_ID}
export SUBNET1_ID=${SUBNET1_ID}
export SUBNET2_ID=${SUBNET2_ID}
export SUBNET3_ID=${SUBNET3_ID}
EOF
```

```bash
VPC_ID=$(aws ec2 create-vpc \
  --cidr-block "$VPC_CIDR" \
  --region "$AWS_REGION" \
  --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=${CLUSTER_NAME}-vpc}]" \
  --output json | jq -r '.Vpc.VpcId')

aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-hostnames
aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-support

IGW_ID=$(aws ec2 create-internet-gateway \
  --region "$AWS_REGION" \
  --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=${CLUSTER_NAME}-igw}]" \
  --output json | jq -r '.InternetGateway.InternetGatewayId')
aws ec2 attach-internet-gateway --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID"

ROUTE_TABLE_ID=$(aws ec2 create-route-table --vpc-id "$VPC_ID" \
  --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${CLUSTER_NAME}-rt}]" \
  --output json | jq -r '.RouteTable.RouteTableId')
aws ec2 create-route --route-table-id "$ROUTE_TABLE_ID" --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW_ID"

create_subnet () {
  local cidr=$1 az=$2 name=$3
  aws ec2 create-subnet \
    --vpc-id "$VPC_ID" \
    --cidr-block "$cidr" \
    --availability-zone "$az" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${CLUSTER_NAME}-${name}}]" \
    --output json | jq -r '.Subnet.SubnetId'
}

SUBNET1_ID=$(create_subnet "$SUBNET1_CIDR" "$AZ1" "subnet-a")
SUBNET2_ID=$(create_subnet "$SUBNET2_CIDR" "$AZ2" "subnet-b")
SUBNET3_ID=$(create_subnet "$SUBNET3_CIDR" "$AZ3" "subnet-c")

for SUBNET_ID in $SUBNET1_ID $SUBNET2_ID $SUBNET3_ID; do
  aws ec2 associate-route-table --route-table-id "$ROUTE_TABLE_ID" --subnet-id "$SUBNET_ID"
  aws ec2 modify-subnet-attribute --subnet-id "$SUBNET_ID" --map-public-ip-on-launch
done
```

---

## 3. IAM Roles for EKS

### 3.Resume
```bash
source env.fdb 2>/dev/null || true

export CLUSTER_ROLE_ARN=$(aws iam get-role \
  --role-name ${CLUSTER_NAME}-eks-cluster-role \
  --query 'Role.Arn' --output text)

export NODE_ROLE_ARN=$(aws iam get-role \
  --role-name ${CLUSTER_NAME}-eks-node-role \
  --query 'Role.Arn' --output text)

export NODE_INSTANCE_PROFILE=${CLUSTER_NAME}-eks-node-profile

cat <<EOF >> env.fdb
export CLUSTER_ROLE_ARN=${CLUSTER_ROLE_ARN}
export NODE_ROLE_ARN=${NODE_ROLE_ARN}
export NODE_INSTANCE_PROFILE=${NODE_INSTANCE_PROFILE}
EOF
```

```bash
CLUSTER_ROLE_ARN=$(aws iam create-role \
  --role-name ${CLUSTER_NAME}-eks-cluster-role \
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Allow","Principal":{"Service":"eks.amazonaws.com"},"Action":"sts:AssumeRole"}]
  }' | jq -r '.Role.Arn')
aws iam attach-role-policy --role-name ${CLUSTER_NAME}-eks-cluster-role --policy-arn arn:aws:iam::aws:policy/AmazonEKSClusterPolicy

NODE_ROLE_ARN=$(aws iam create-role \
  --role-name ${CLUSTER_NAME}-eks-node-role \
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]
  }' | jq -r '.Role.Arn')
for POLICY in AmazonEKSWorkerNodePolicy AmazonEKS_CNI_Policy AmazonEC2ContainerRegistryReadOnly; do
  aws iam attach-role-policy --role-name ${CLUSTER_NAME}-eks-node-role --policy-arn arn:aws:iam::aws:policy/$POLICY
done
```

Create an instance profile:

```bash
aws iam create-instance-profile --instance-profile-name ${CLUSTER_NAME}-eks-node-profile
aws iam add-role-to-instance-profile --instance-profile-name ${CLUSTER_NAME}-eks-node-profile --role-name ${CLUSTER_NAME}-eks-node-role
```

---

## 4. Create the EKS Control Plane

### 4.Resume
```bash
source env.fdb 2>/dev/null || true

export EKS_ENDPOINT=$(aws eks describe-cluster \
  --name ${CLUSTER_NAME} --region ${AWS_REGION} \
  --query 'cluster.endpoint' --output text 2>/dev/null || true)

cat <<EOF >> env.fdb
export EKS_ENDPOINT=${EKS_ENDPOINT}
EOF
```

```bash
aws eks create-cluster \
  --name "$CLUSTER_NAME" \
  --region "$AWS_REGION" \
  --kubernetes-version "$K8S_VERSION" \
  --role-arn "$CLUSTER_ROLE_ARN" \
  --resources-vpc-config "subnetIds=$SUBNET1_ID,$SUBNET2_ID,$SUBNET3_ID,endpointPublicAccess=true"

aws eks wait cluster-active --name "$CLUSTER_NAME" --region "$AWS_REGION"
```

Update kubeconfig:

```bash
aws eks update-kubeconfig --name "$CLUSTER_NAME" --region "$AWS_REGION"
```

---

## 5. Managed Node Group

### 5.Resume
```bash
source env.fdb 2>/dev/null || true

export NODEGROUP_NAME=${CLUSTER_NAME}-primary-ng
cat <<EOF >> env.fdb
export NODEGROUP_NAME=${NODEGROUP_NAME}
EOF
```

```bash
aws eks create-nodegroup \
  --cluster-name "$CLUSTER_NAME" \
  --nodegroup-name "${CLUSTER_NAME}-primary-ng" \
  --scaling-config "minSize=$NODE_COUNT,desiredSize=$NODE_COUNT,maxSize=$NODE_COUNT" \
  --disk-size 200 \
  --subnets "$SUBNET1_ID" "$SUBNET2_ID" "$SUBNET3_ID" \
  --instance-types "$NODE_INSTANCE_TYPE" \
  --ami-type AL2_x86_64 \
  --node-role "$NODE_ROLE_ARN"

aws eks wait nodegroup-active \
  --cluster-name "$CLUSTER_NAME" \
  --nodegroup-name "${CLUSTER_NAME}-primary-ng" \
  --region "$AWS_REGION"
```

Verify nodes:

```bash
kubectl get nodes -o wide
```

---

## 6. Install the FoundationDB Kubernetes Operator

### 6.Resume
```bash
source env.fdb 2>/dev/null || true

kubectl config set-context --current --namespace=foundationdb-system >/dev/null 2>&1 || true
```

The operator maintainers recommend installing the CRDs and controller from a tagged release rather than `main`. Adjust `FDB_OPERATOR_VERSION` if a newer release appears on the project’s GitHub releases page.citeturn0search0

```bash
kubectl get namespace foundationdb-system >/dev/null 2>&1 || kubectl create namespace foundationdb-system

kubectl apply -f https://raw.githubusercontent.com/FoundationDB/fdb-kubernetes-operator/${FDB_OPERATOR_VERSION}/config/crd/bases/apps.foundationdb.org_foundationdbclusters.yaml
kubectl apply -f https://raw.githubusercontent.com/FoundationDB/fdb-kubernetes-operator/${FDB_OPERATOR_VERSION}/config/crd/bases/apps.foundationdb.org_foundationdbbackups.yaml
kubectl apply -f https://raw.githubusercontent.com/FoundationDB/fdb-kubernetes-operator/${FDB_OPERATOR_VERSION}/config/crd/bases/apps.foundationdb.org_foundationdbrestores.yaml

kubectl apply -n foundationdb-system \
    -f https://raw.githubusercontent.com/FoundationDB/fdb-kubernetes-operator/${FDB_OPERATOR_VERSION}/config/samples/deployment.yaml

kubectl -n foundationdb-system rollout status deployment/fdb-kubernetes-operator-controller-manager --timeout=5m
kubectl -n foundationdb-system logs -f -l app=fdb-kubernetes-operator-controller-manager --container=manager
```

Monitor the operator logs until the controller reports it is watching the cluster. When you later change a `FoundationDBCluster`, ensure `status.generations.reconciled` catches up with `metadata.generation` before proceeding to the next step.citeturn0search2

---

## 7. Deploy a Multi-AZ FoundationDB Cluster

### 7.Resume
```bash
source env.fdb 2>/dev/null || true

export FDB_CLUSTER_NS=foundationdb-system
cat <<EOF >> env.fdb
export FDB_CLUSTER_NS=${FDB_CLUSTER_NS}
EOF
```

Generate a production-tuned cluster manifest. The repo already includes `fdb-cluster.yaml`, which scales storage, logs, proxies, and resolvers to sustain >100k TPS while keeping pods evenly spread across three AZs.

```bash
# manifest is committed in the repo
envsubst < fdb-cluster.yaml | kubectl apply -f -
```

Key production levers:

- `storageServersPerPod` / `logServersPerPod` multiply storage and log processes per pod, yielding the 18 storage and 12 log processes required for sustained I/O without creating dozens of extra pods.
- High `RoleCounts` for proxies, commit proxies, resolvers, and log routers keep the transaction pipeline wide enough for six-figure TPS; FoundationDB’s architecture scales write throughput by recruiting additional processes for those roles.
- Elevated CPU/memory reservations for the main and sidecar containers ensure each pod stays CPU scheduled under load.

Apply and watch status:

```bash
envsubst < fdb-cluster.yaml | kubectl apply -f -
kubectl -n ${FDB_CLUSTER_NS} get foundationdbclusters.apps.foundationdb.org fdb-oms -o json | jq '.status.health'
kubectl -n ${FDB_CLUSTER_NS} get pods -l foundationdb.org/fdb-cluster-name=fdb-oms -o wide

kubectl -n ${FDB_CLUSTER_NS} get foundationdbclusters.apps.foundationdb.org fdb-oms \
  -o jsonpath='{.status.generations}'
echo "Wait until reconciled equals desired before load testing"
```

When healthy, front the cluster with an AWS Network Load Balancer and retrieve the connection information:

```bash
# service manifest is committed in the repo
kubectl apply -f fdb-public-svc.yaml
```

When the service has an address, obtain the cluster file and endpoint:

```bash
kubectl -n ${FDB_CLUSTER_NS} get secret fdb-oms-cluster-file -o jsonpath='{.data.cluster-file}' | base64 -d > fdb.cluster

FDB_LB=$(kubectl -n ${FDB_CLUSTER_NS} get svc fdb-oms-public -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
echo "FoundationDB public service: $FDB_LB"
```

---

## 8. Provision the Benchmark EC2 Host

### 8.Resume
```bash
source env.fdb 2>/dev/null || true

export SG_ID=$(aws ec2 describe-security-groups \
  --filters Name=vpc-id,Values=${VPC_ID} Name=group-name,Values=${CLUSTER_NAME}-bench-sg \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)

export BENCH_INSTANCE_ID=$(aws ec2 describe-instances \
  --filters Name=tag:Name,Values=${CLUSTER_NAME}-bench Name=instance-state-name,Values=running,stopped \
  --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null || true)

if [ -n "${BENCH_INSTANCE_ID}" ] && [ "${BENCH_INSTANCE_ID}" != "None" ]; then
  export BENCH_PUBLIC_IP=$(aws ec2 describe-instances --instance-ids ${BENCH_INSTANCE_ID} \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
fi

cat <<EOF >> env.fdb
export SG_ID=${SG_ID}
export BENCH_INSTANCE_ID=${BENCH_INSTANCE_ID}
export BENCH_PUBLIC_IP=${BENCH_PUBLIC_IP}
EOF
```

1. **Security group** (allow FDB + metrics):
   ```bash
   SG_ID=$(aws ec2 create-security-group \
     --group-name ${CLUSTER_NAME}-bench-sg \
     --description "FoundationDB benchmark host" \
     --vpc-id "$VPC_ID" \
     --output json | jq -r '.GroupId')

   aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
     --ip-permissions '[{"IpProtocol":"tcp","FromPort":4500,"ToPort":4500,"IpRanges":[{"CidrIp":"'${VPC_CIDR}'"}]}]'
   aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
     --ip-permissions '[{"IpProtocol":"tcp","FromPort":2112,"ToPort":2112,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'
   ```

2. **Key pair**:
   ```bash
   aws ec2 create-key-pair --key-name ${CLUSTER_NAME}-bench-key \
     --query 'KeyMaterial' --output text > ${CLUSTER_NAME}-bench.pem
   chmod 600 ${CLUSTER_NAME}-bench.pem
   ```

3. **Launch instance** (high-throughput compute, same subnets):
   ```bash
   BENCH_SUBNET_ID=$SUBNET1_ID
   BENCH_INSTANCE_ID=$(aws ec2 run-instances \
     --image-id $(aws ssm get-parameters \
         --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
         --query 'Parameters[0].Value' --output text --region "$AWS_REGION") \
     --instance-type c7i.8xlarge \
     --key-name ${CLUSTER_NAME}-bench-key \
     --security-group-ids "$SG_ID" \
     --subnet-id "$BENCH_SUBNET_ID" \
     --iam-instance-profile Name=${CLUSTER_NAME}-eks-node-profile \
     --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${CLUSTER_NAME}-bench}]" \
     --region "$AWS_REGION" \
     --output json | jq -r '.Instances[0].InstanceId')

   aws ec2 wait instance-status-ok --instance-ids "$BENCH_INSTANCE_ID" --region "$AWS_REGION"
   BENCH_PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$BENCH_INSTANCE_ID" \
     --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
   ```

Copy the `fdb.cluster` file to the EC2 host (use `scp`):

```bash
scp -i ${CLUSTER_NAME}-bench.pem fdb.cluster ec2-user@${BENCH_PUBLIC_IP}:/home/ec2-user/
```

---

## 9. Build and Run the Benchmark

### 9.Resume
```bash
source env.fdb 2>/dev/null || true

if [ -z "${BENCH_PUBLIC_IP}" ] || [ "${BENCH_PUBLIC_IP}" = "None" ]; then
  export BENCH_PUBLIC_IP=$(aws ec2 describe-instances --filters Name=tag:Name,Values=${CLUSTER_NAME}-bench \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null || true)
fi

cat <<EOF >> env.fdb
export BENCH_PUBLIC_IP=${BENCH_PUBLIC_IP}
EOF
```

On the EC2 host:

```bash
ssh -i ${CLUSTER_NAME}-bench.pem ec2-user@${BENCH_PUBLIC_IP}

sudo dnf install -y gcc git
curl -LO https://go.dev/dl/go1.24.7.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.24.7.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

git clone https://github.com/Abdullah1738/omsbench.git
cd omsbench
GO111MODULE=on go build ./cmd/omsbench
```

Run the benchmark (tune TPS/workers within the 100k–500k TPS band):

```bash
FDB_CLUSTER_FILE=/home/ec2-user/fdb.cluster
./omsbench run \
  --cluster-file "$FDB_CLUSTER_FILE" \
  --namespace omsbench \
  --tps 300000 \
  --workers 4096 \
  --duration 20m \
  --tx-timeout 5s \
  --metrics-addr ":2112" \
  --seed 20251013
```

- Increase `--tps` gradually (for example 150k → 300k → 450k).
- Adjust `--workers` (e.g. 3072–6144) to keep per-worker throughput reasonable.
- Use distinct namespaces for multiple concurrent runs to avoid key contention: `--namespace omsbench/run1`.

---

## 10. Observability (p50/p99 Latency)

### 10.Resume
```bash
source env.fdb 2>/dev/null || true
```

The benchmark exposes Prometheus-format metrics on port `2112`.

```bash
curl http://localhost:2112/metrics | grep omsbench_tx_seconds_bucket
```

Example PromQL (run in Prometheus or Grafana):

```promql
histogram_quantile(0.99, sum(rate(omsbench_tx_seconds_bucket[1m])) by (le))
histogram_quantile(0.50, sum(rate(omsbench_tx_seconds_bucket[1m])) by (le))
rate(omsbench_tx_total[1m])
rate(omsbench_tx_fail_total[1m])
```

You can scrape the endpoint with Amazon Managed Service for Prometheus or deploy a local Prometheus in the EKS cluster that scrapes the EC2 instance (ensure security group rules permit port 2112).

---

## 11. Tuning for 100k–500k TPS

### 11.Resume
```bash
source env.fdb 2>/dev/null || true
```

- **FDB topology**: triple redundancy with at least 6 storage and 6 log processes across three AZs. Increase process counts (e.g. 12 storage / 8 log) if CPU or disk usage exceeds 70%.
- **Resource sizing**: `c7i.8xlarge` EC2 benchmark host uses 32 vCPU; raise to `c7i.12xlarge` if per-core saturation occurs.
- **FDB ratekeeper**: Watch the `foundationdb` status (`kubectl get fdb -o yaml | jq '.status.health.ratekeeper'`). If throttling occurs, raise `processCounts`, storage volumes, or scale out the node group.
- **Client locality**: place the EC2 instance in the same VPC and AZ set as the EKS nodes to minimize latency.
- **Timeouts**: keep `--tx-timeout` at 5s–10s; FDB transactions are retried automatically by the driver when encountering conflicts.

---

## 12. Cleanup

### 12.Resume
```bash
source env.fdb 2>/dev/null || true
```

```bash
aws ec2 terminate-instances --instance-ids "$BENCH_INSTANCE_ID"
aws eks delete-nodegroup --cluster-name "$CLUSTER_NAME" --nodegroup-name "${CLUSTER_NAME}-primary-ng"
aws eks delete-cluster --name "$CLUSTER_NAME"
aws ec2 delete-security-group --group-id "$SG_ID"
aws iam delete-instance-profile --instance-profile-name ${CLUSTER_NAME}-eks-node-profile
aws iam remove-role-from-instance-profile --instance-profile-name ${CLUSTER_NAME}-eks-node-profile --role-name ${CLUSTER_NAME}-eks-node-role
aws iam detach-role-policy --role-name ${CLUSTER_NAME}-eks-node-role --policy-arn arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
aws iam detach-role-policy --role-name ${CLUSTER_NAME}-eks-node-role --policy-arn arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
aws iam detach-role-policy --role-name ${CLUSTER_NAME}-eks-node-role --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
aws iam delete-role --role-name ${CLUSTER_NAME}-eks-node-role
aws iam detach-role-policy --role-name ${CLUSTER_NAME}-eks-cluster-role --policy-arn arn:aws:iam::aws:policy/AmazonEKSClusterPolicy
aws iam delete-role --role-name ${CLUSTER_NAME}-eks-cluster-role
aws ec2 delete-route-table --route-table-id "$ROUTE_TABLE_ID"
aws ec2 detach-internet-gateway --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID"
aws ec2 delete-internet-gateway --internet-gateway-id "$IGW_ID"
for SUBNET_ID in $SUBNET1_ID $SUBNET2_ID $SUBNET3_ID; do aws ec2 delete-subnet --subnet-id "$SUBNET_ID"; done
aws ec2 delete-vpc --vpc-id "$VPC_ID"
rm -f ${CLUSTER_NAME}-bench.pem fdb.cluster
```

---

## 13. Next Steps

### 13.Resume
```bash
source env.fdb 2>/dev/null || true
```

- Integrate the Prometheus endpoint with Amazon Managed Service for Prometheus or AMP/AMG dashboards.
- Use AWS FIS (Fault Injection Simulator) to test FoundationDB resilience across AZ disruptions.
- Consider a dedicated CI job that re-runs the benchmark nightly with controlled seeds to track performance regressions.
