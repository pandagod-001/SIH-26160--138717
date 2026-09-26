#!/bin/bash
# ==============================================================================
# IPsecTrace — 60-Second Live Prototype Demonstration
# One-Command Interactive Execution Script
# ==============================================================================

set -e

# Change to project root directory
cd "$(dirname "$0")/.."

# Default arguments
PCAP=""
CLASS_TYPE="BULK"
LIVE=false
AWS=false
RECORD=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --pcap) PCAP="$2"; shift ;;
        --class) CLASS_TYPE="$2"; shift ;;
        --live) LIVE=true ;;
        --aws) AWS=true ;;
        --record) RECORD=true ;;
        -h|--help)
            echo "Usage: ./demo/start_demo.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --class <BULK|WEB|ICMP|INTERACTIVE>  Select verified native IPsec class (default: BULK)"
            echo "  --pcap <path_to_pcap>                Provide a custom real IPsec PCAP"
            echo "  --live                               Attempt live interface capture"
            echo "  --aws                                Show AWS cloud demo architecture & setup"
            echo "  --record                             Run in 60-second paced presentation mode"
            echo "  -h, --help                           Display this help message"
            exit 0
            ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

CMD="python demo/run_demo.py"

if [ "$AWS" = true ]; then
    CMD="$CMD --aws"
elif [ -n "$PCAP" ]; then
    CMD="$CMD --pcap \"$PCAP\""
else
    CMD="$CMD --class-type $CLASS_TYPE"
fi

if [ "$RECORD" = true ]; then
    CMD="$CMD --record"
fi

if [ "$LIVE" = true ]; then
    CMD="$CMD --live"
fi

eval $CMD
