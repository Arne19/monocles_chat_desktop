#!/usr/bin/env bash
# Create + migrate the dev SQLite database that sqlx's compile-time `query!` macros
# in mxc-store check against. Run once before the first `cargo build`.
#
# The build reads DATABASE_URL from .cargo/config.toml, which points at the absolute
# path of .sqlx-dev.db in THIS folder (machine-specific, git-ignored). This script
# (re)creates that file from the migrations.
#
# Alternative for offline/CI builds: `cargo install sqlx-cli` then
# `cargo sqlx prepare --workspace` to vendor a `.sqlx/` metadata dir and build with
# `SQLX_OFFLINE=true` (no DATABASE_URL needed).
set -euo pipefail
cd "$(dirname "$0")/.."

DB_FILE=".sqlx-dev.db"
export DATABASE_URL="sqlite://$(pwd)/${DB_FILE}"

# `cargo install sqlx-cli` installs both `sqlx` and `cargo-sqlx` into ~/.cargo/bin, which is
# often not on PATH (e.g. with a distro-packaged cargo). `cargo sqlx` still works then, because
# cargo looks up `cargo-<subcommand>` in $CARGO_HOME/bin itself.
if command -v sqlx >/dev/null 2>&1; then
  SQLX=(sqlx)
elif command -v cargo >/dev/null 2>&1 && cargo sqlx --version >/dev/null 2>&1; then
  SQLX=(cargo sqlx)
else
  echo "sqlx-cli not found. Install with: cargo install sqlx-cli --no-default-features --features sqlite,rustls"
  echo "Or create the DB manually from ALL migrations with sqlite3:"
  echo "  rm -f ${DB_FILE}; for m in crates/mxc-store/migrations/*.sql; do sqlite3 ${DB_FILE} < \"\$m\"; done"
  echo "(or use the python snippet in README.md)"
  exit 1
fi

"${SQLX[@]}" database create
"${SQLX[@]}" migrate run --source crates/mxc-store/migrations
echo "Dev DB ready at $(pwd)/${DB_FILE}."
echo "DATABASE_URL is set in .cargo/config.toml — update it if you move this folder."
