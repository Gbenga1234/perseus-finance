#!/usr/bin/env bash
# Creates one database per service with two roles each (least privilege):
#   <svc>_migrator  owns the schema and runs migrations (DDL)
#   <svc>_app       runtime role: DML only, no DDL; audit gets SELECT/INSERT only
set -euo pipefail


create_service_db() {
  local svc="$1" app_privileges="$2"
  # Passwords come from <SVC>_DB_MIGRATOR_PASSWORD / <SVC>_DB_APP_PASSWORD env vars.
  local upper
  upper="$(printf '%s' "$svc" | tr '[:lower:]' '[:upper:]')"
  local migrator_var="${upper}_DB_MIGRATOR_PASSWORD" app_var="${upper}_DB_APP_PASSWORD"
  local migrator_pw="${!migrator_var:?${migrator_var} is not set}"
  local app_pw="${!app_var:?${app_var} is not set}"

  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
    -v db="$svc" -v migrator="${svc}_migrator" -v app="${svc}_app" \
    -v migrator_pw="$migrator_pw" -v app_pw="$app_pw" <<'SQL'
CREATE ROLE :"migrator" LOGIN PASSWORD :'migrator_pw';
CREATE ROLE :"app" LOGIN PASSWORD :'app_pw' CONNECTION LIMIT 60;
CREATE DATABASE :"db" OWNER :"migrator";
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO :"app";
SQL

  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$svc" \
    -v migrator="${svc}_migrator" -v app="${svc}_app" -v privileges="$app_privileges" <<'SQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO :"migrator";
GRANT USAGE ON SCHEMA public TO :"app";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator" IN SCHEMA public
  GRANT :privileges ON TABLES TO :"app";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator" IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO :"app";
SQL
  echo "provisioned database ${svc}"
}

create_service_db auth          "SELECT, INSERT, UPDATE, DELETE"
create_service_db accounts      "SELECT, INSERT, UPDATE, DELETE"
create_service_db ledger        "SELECT, INSERT, UPDATE, DELETE"
create_service_db fraud         "SELECT, INSERT, UPDATE, DELETE"
create_service_db notifications "SELECT, INSERT, UPDATE, DELETE"
create_service_db audit         "SELECT, INSERT"
