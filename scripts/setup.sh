#!/usr/bin/env bash
# One-shot local setup: venv, dependencies, and a starting config.json.
# See README.md's Installation section for what this automates, and for the
# remaining manual steps (PostgreSQL, Ollama) this script does not perform.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -d venv ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

echo "Installing dependencies..."
venv/bin/pip install --upgrade pip
venv/bin/pip install -r requirements.txt

if [ ! -f config.json ]; then
    echo "Creating config.json from config.json.example..."
    cp config.json.example config.json
    echo "  -> Edit config.json with your integration credentials before running the server."
else
    echo "config.json already exists, leaving it as-is."
fi

cat <<'EOF'

Setup done. Still needed before the pipeline will work:
  1. Start PostgreSQL:        docker compose up -d postgres
  2. Start Ollama + pull a model:
       docker compose up -d ollama
       docker exec soc-ollama ollama pull llama3.1
     (if you pull a different model, update ollama.model in config.json to match)
  3. Activate the venv:       source venv/bin/activate

See README.md for the full Installation and Configuration sections.
EOF
