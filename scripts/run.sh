#!/usr/bin/env bash
set -euo pipefail
python -m pip install -r requirements.txt
streamlit run app.py --server.port 8501 --server.address 0.0.0.0
