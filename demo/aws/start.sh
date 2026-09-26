#!/bin/bash
# ==============================================================================
# IPsecTrace — AWS Environment Start Script
# ==============================================================================

set -e

echo "================================================================================"
echo " IPsecTrace — AWS CLOUD DEMO PROVISIONING / START"
echo "================================================================================"
echo ""
echo "[INFO] Checking AWS CLI authentication..."
if ! command -v aws &> /dev/null; then
    echo "[ERROR] AWS CLI is not installed. Please install awscli or configure credentials."
    exit 1
fi

echo "[INFO] Verifying EC2 instance tags (Project: IPsecTrace)..."
INSTANCE_IDS=$(aws ec2 describe-instances \
    --filters "Name=tag:Project,Values=IPsecTrace" "Name=instance-state-name,Values=stopped" \
    --query "Reservations[*].Instances[*].InstanceId" \
    --output text)

if [ -z "$INSTANCE_IDS" ]; then
    echo "[INFO] No stopped IPsecTrace instances found to start."
    echo "[INFO] Please refer to demo/AWS_DEMO_SETUP.md for initial VPC & EC2 creation."
else
    echo "[INFO] Starting instances: $INSTANCE_IDS"
    aws ec2 start-instances --instance-ids $INSTANCE_IDS
    echo "[SUCCESS] EC2 instances are starting up."
fi
