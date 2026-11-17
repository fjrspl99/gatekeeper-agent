#!/bin/bash
# Start the Gatekeeper agent with the HMAC secret from .env (chmod 600, gitignored).
cd "$(dirname "$0")"
set -a
# shellcheck disable=SC1091
. ./.env
set +a
exec node server.mjs
