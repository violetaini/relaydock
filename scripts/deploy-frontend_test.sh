#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/arcway-frontend-deploy.XXXXXXXX")"
cleanup() {
  rm -rf -- "$workspace"
}
trap cleanup EXIT

root="$workspace/web"
releases="$root/releases"
for release in v1.0.0 v1.0.1; do
  mkdir -p "$releases/$release/assets"
  printf '__RELAYDOCK_DEFAULT_THEME__<script src="/assets/app.js"></script>\n' >"$releases/$release/index.html"
  printf 'console.log(%q)\n' "$release" >"$releases/$release/assets/app.js"
done

# Legacy deployments wrote an absolute current link. The deploy script must
# accept only this canonical in-root form and replace it with a relative link.
ln -s "$releases/v1.0.1" "$root/current"
ln -s "$releases/v1.0.0" "$root/previous"

mkdir "$workspace/bin"
cat >"$workspace/bin/ssh" <<'MOCK_SSH'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
count="${#args[@]}"
exec bash -s -- "${args[@]:count-3:3}"
MOCK_SSH
chmod 0700 "$workspace/bin/ssh"

PATH="$workspace/bin:$PATH" bash "$script_dir/deploy-frontend.sh" rollback \
  --host mock-control \
  --remote-root "$root"

test "$(readlink "$root/current")" = "releases/v1.0.0"
test "$(readlink "$root/previous")" = "releases/v1.0.1"
echo "deploy frontend absolute-link test passed"
