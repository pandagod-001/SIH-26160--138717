#!/bin/bash
# ==============================================================================
# IPsecTrace — AWS Environment Stop Script (Cost Control)
# ==============================================================================

set -e

echo "================================================================================"
echo " IPsecTrace — AWS STOPPING RUNNING INSTANCES (COST SAVING)"
echo "================================================================================"
echo ""

if ! command -v aws &> /dev/null; then
    echo "[ERROR] AWS CLI is not installed."
    exit 1
fi

INSTANCE_IDS=$(aws ec2 describe-instances \
    --filters "Name=tag:Project,Values=IPsecTrace" "Name=instance-state-name,Values=running" \
    --query "Reservations[*].Instances[*].InstanceId" \
    --output text)

if [ -z "$INSTANCE_IDS" ]; then
    echo "[INFO] No running IPsecTrace instances found."
else
    echo "[INFO] Stopping instances to avoid charges: $INSTANCE_IDS"
    aws ec2 stop-instances --instance-ids $INSTANCE_IDS
    echo "[SUCCESS] EC2 instances stopped successfully."
fi
