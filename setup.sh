#!/bin/bash

echo "Setting up HereFishyFishy Domain Trust Scoring Tool..."
echo "======================================================"

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment and install dependencies
echo "Installing dependencies..."
source .venv/bin/activate
pip install -r requirements.txt

echo ""
echo "Setup complete! You can now run:"
echo "  python prototype.py <domain>"
echo ""
echo "Or activate the virtual environment first:"
echo "  source .venv/bin/activate"
echo "  python prototype.py <domain>"
echo ""
