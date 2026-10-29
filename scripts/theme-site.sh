#!/bin/sh
# The design system's demo as a static site, for GitHub Pages: the theme's
# folder, jq79 with its notice, and the demo's page with the paths the
# dashboard serves it at made relative, so it works under any prefix
# (Pages serves it at /intergate/theme/). The release's pages job runs it;
# the build runs it on every push to check it.
#
#   scripts/theme-site.sh site/theme
#
# Pages sends no Content-Security-Policy, so the nonce the dashboard's page
# carries is a fixed word here: jq79 builds its scripts the same way, and
# nothing checks them. See RECORD/2026-10-29.a-design-system.completed.md.
set -eu

out=${1:?usage: scripts/theme-site.sh OUT}
root=$(cd "$(dirname "$0")/.." && pwd)
ui=$root/internal/web/ui

mkdir -p "$out/vendor"
cp -R "$ui/theme/default/." "$out/"
cp "$ui/vendor/jq79.js" "$ui/vendor/README.md" "$out/vendor/"
# The favicon is the landing's, one folder up.
sed -e 's|{{\.Nonce}}|pages|g' \
    -e 's|/ui/theme/default/|./|g' \
    -e 's|/ui/vendor/|./vendor/|g' \
    -e 's|/ui/favicon\.svg|../favicon.svg|g' \
    "$root/internal/web/templates/theme.html" > "$out/index.html"

if grep -n '{{\|"/ui/' "$out/index.html"; then
  echo "theme-site.sh: $out/index.html still names a template field or a dashboard path" >&2
  exit 1
fi
echo "theme-site.sh: the design system is in $out"
