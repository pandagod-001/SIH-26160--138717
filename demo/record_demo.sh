#!/bin/bash
# ==============================================================================
# IPsecTrace — Screen Recording Preparation & Execution Mode
# ==============================================================================

set -e

# Change to project root directory
cd "$(dirname "$0")/.."

echo "================================================================================"
echo " IPsecTrace — PREPARING TERMINAL FOR VIDEO RECORDING"
echo "================================================================================"
echo ""
echo " Recommended Recording Specifications:"
echo "   • Resolution : 1920 x 1080 (16:9 Aspect Ratio)"
echo "   • Font Size  : 20px - 24px (Consolas / Cascadia Code / Monospace)"
echo "   • Frame Rate : 30 fps or 60 fps (OBS Studio / Screen Studio)"
echo "   • Pacing     : 60-Second Guided Sequence with step delays"
echo ""
echo "Press ENTER to begin 60-second live prototype execution..."
read -r

clear
python demo/run_demo.py --class-type BULK --record
