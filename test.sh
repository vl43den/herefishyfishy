#!/bin/bash
# Simple test script to validate the installation

echo "Testing HereFishyFishy Domain Trust Scoring Tool..."
echo "================================================="

# Test basic functionality
echo -e "\n1. Testing basic domain analysis (google.com):"
python prototype.py google.com

# Test with whitelist
echo -e "\n2. Testing whitelist functionality:"
python prototype.py google.com --whitelist sample_whitelist.txt

# Test help
echo -e "\n3. Testing help command:"
python prototype.py --help

echo -e "\nAll tests completed!"
