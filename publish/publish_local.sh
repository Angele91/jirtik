#!/usr/bin/env bash
set -e

# Build the distribution
python setup.py sdist bdist_wheel

# Install in current environment (virtualenv or not)
pip install dist/*.whl

# Create a more accessible copy of the wheel in the home directory
mkdir -p ~/jirtik_dist
cp dist/*.whl ~/jirtik_dist/
chmod 755 ~/jirtik_dist/*.whl

# Display helpful message for installing outside virtualenv
WHEEL_FILE=$(ls dist/*.whl | head -n 1 | xargs basename)
VERSION=$(echo $WHEEL_FILE | sed -E 's/jirtik-([0-9]+\.[0-9]+\.[0-9]+).*/\1/')
echo ""
echo "✅ Jirtik v$VERSION installed in current environment"
echo ""
echo "📦 Wheel file copied to ~/jirtik_dist/$WHEEL_FILE"
echo ""
echo "To install outside this virtualenv, run:"
echo "pip install ~/jirtik_dist/$WHEEL_FILE"
echo ""

# Clean up build artifacts
python clean.py