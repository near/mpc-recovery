#!/bin/bash
set -euo pipefail

echo '{"sha": "'"$(git rev-parse HEAD)"'"}'
