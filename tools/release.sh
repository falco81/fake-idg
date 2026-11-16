#!/usr/bin/env bash
#
# tools/release.sh — make release/fake-igd-X.Y.Z.tar.gz from this repository (1.4.0).
#
# As otp's releases: the package folder fake-igd-X.Y.Z/, a MANIFEST with the SHA-256 of
# every file in it, and MANIFEST.sig - the Ed25519 signature of MANIFEST by the release
# key, whose public half is deploy/release-keys/fake-igd-release-1.pub (what install.sh
# puts in /opt/fake-igd/release-keys/ and fake_igd_upgrade.py checks against).
#
#   tools/release.sh /path/to/fake-igd-release-1.key
#   FAKE_IGD_RELEASE_KEY=/path/to/key tools/release.sh
#
# The private key is never in the repository. The last ten packages are kept in release/.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY="${1:-${FAKE_IGD_RELEASE_KEY:-}}"
[[ -n "$KEY" && -f "$KEY" ]] || { echo "the release key (the private one): tools/release.sh KEY" >&2; exit 1; }
cd "$ROOT"
V="$(sed -n "s/^__version__ = '\(.*\)'.*/\1/p" src/fake-igd.py | head -n1)"
[[ "$V" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "src/fake-igd.py has no __version__ X.Y.Z" >&2; exit 1; }
# Every place that says the version says the same one - as committed.
git diff --quiet HEAD -- src/fake-igd.py src/upnp.py web/igd-page.php CHANGELOG.md README.md \
  || { echo "commit the version first: the package is made from HEAD" >&2; exit 1; }
grep -q "^VERSION = \"$V\"" src/upnp.py || { echo "src/upnp.py VERSION is not $V" >&2; exit 1; }
grep -q "const IGD_VERSION = '$V';" web/igd-page.php || { echo "web/igd-page.php IGD_VERSION is not $V" >&2; exit 1; }
grep -q "^## $V\b" CHANGELOG.md || { echo "CHANGELOG.md has no ## $V" >&2; exit 1; }
grep -q "^# fake-igd $V" README.md || { echo "README.md does not start with # fake-igd $V" >&2; exit 1; }
# The public key beside the private one must be the one the package ships.
PUB="$(openssl pkey -in "$KEY" -pubout 2>/dev/null)"
grep -qF "$(echo "$PUB" | sed -n 2p)" deploy/release-keys/*.pub || { echo "that key is not one of deploy/release-keys/" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TOP="fake-igd-$V"
mkdir "$WORK/$TOP"
# What goes in (1.5.3): the committed tree of HEAD - never what is lying in the working folder
# (work in progress, files of somebody else's), and never the releases, the tools, git's own.
git archive --format=tar HEAD | tar -x -C "$WORK/$TOP"
rm -rf "$WORK/$TOP/release" "$WORK/$TOP/tools" "$WORK/$TOP/.gitignore" "$WORK/$TOP/.github"
find "$WORK/$TOP" -name __pycache__ -prune -exec rm -rf {} +
find "$WORK/$TOP" -type d -empty -delete
( cd "$WORK/$TOP" && find . -type f ! -name MANIFEST ! -name MANIFEST.sig -printf '%P\n' | LC_ALL=C sort \
    | while IFS= read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done > MANIFEST )
openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$WORK/$TOP/MANIFEST" -out "$WORK/$TOP/MANIFEST.sig"
openssl pkeyutl -verify -pubin -inkey <(echo "$PUB") -rawin -in "$WORK/$TOP/MANIFEST" -sigfile "$WORK/$TOP/MANIFEST.sig" >/dev/null
mkdir -p release
OUT="release/$TOP.tar.gz"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$(git log -1 --format=%ct 2>/dev/null || date +%s)" \
    -C "$WORK" -czf "$OUT" "$TOP"
# The last ten kept.
ls -1 release/fake-igd-*.tar.gz | sort -V | head -n -10 | xargs -r rm -f
echo "$OUT: $(wc -l < "$WORK/$TOP/MANIFEST") files, signed, $(du -h "$OUT" | cut -f1)"
