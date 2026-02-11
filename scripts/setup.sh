#!/bin/bash
# Setup script for python-network-utils

set -e

PYTHON=${PYTHON:-python3}
VENV_DIR=".venv"

echo "🐍 Creating virtual environment..."
$PYTHON -m venv $VENV_DIR

echo "📦 Activating virtual environment..."
source $VENV_DIR/bin/activate

echo "⬆️  Upgrading pip..."
pip install --upgrade pip

echo "📥 Installing dependencies..."
pip install -e ".[dev]"

echo ""
echo "✅ Setup complete!"
echo ""
echo "To activate the virtual environment, run:"
echo "  source $VENV_DIR/bin/activate"
echo ""
echo "To run tests:"
echo "  pytest"
echo ""
echo "To deactivate:"
echo "  deactivate"
