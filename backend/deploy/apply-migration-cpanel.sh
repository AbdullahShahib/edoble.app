#!/usr/bin/env bash
# Small helper script to apply initial SQL migration on cPanel MySQL
# Usage: bash apply-migration-cpanel.sh mysql_host mysql_port db_name db_user

set -e

if [ "$#" -ne 4 ]; then
  echo "Usage: $0 <host> <port> <database> <user>" >&2
  exit 2
fi

HOST="$1"
PORT="$2"
DB="$3"
USER="$4"

echo "Applying migration to ${USER}@${HOST}:${PORT}/${DB}"

mysql -h "$HOST" -P "$PORT" -u "$USER" -p "$DB" < "$(dirname "$0")/../prisma/migrations/0001_init/migration.sql"

echo "Migration applied."
