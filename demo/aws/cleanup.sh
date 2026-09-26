#!/bin/bash
# ==============================================================================
# IPsecTrace — AWS Resource Cleanup & Teardown Script
# ==============================================================================

set -e

echo "================================================================================"
echo " IPsecTrace — AWS CLOUD INFRASTRUCTURE TEARDOWN"
echo "================================================================================"
echo ""
echo "WARNING: This will terminate all EC2 instances and resources tagged with 'Project: IPsecTrace'."
read -p "Are you sure you want to permanently delete these resources? (y/N): " CONFIRM

if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
    if ! command -v aws &> /dev/null; then
        echo "[ERROR] AWS CLI is not installed."
        exit 1
    fi

    INSTANCE_IDS=$(aws ec2 describe-instances \
        --filters "Name=tag:Project,Values=IPsecTrace" \
        --query "Reservations[*].Instances[*].InstanceId" \
        --output text)

    if [ -n "$INSTANCE_IDS" ]; then
        echo "[INFO] Terminating EC2 instances: $INSTANCE_IDS"
        aws ec2 terminate-instances --instance-ids $INSTANCE_IDS
        echo "[SUCCESS] EC2 instances terminated."
    else
        echo "[INFO] No instances found."
    fi
else
    echo "[INFO] Teardown aborted by user."
fi
