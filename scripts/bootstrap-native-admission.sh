#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/^wardenNativeVersion=//p' gradle.properties)
revision=${version#0.24.1.1-warden.}
if ! [[ $revision =~ ^[0-9a-f]{40}$ ]]; then echo 'Invalid pinned native revision' >&2; exit 1; fi
checkout=${WARDEN_NATIVE_BINDING_CHECKOUT:-build/native-admission/libdatachannel-java}
if ! test -e "$checkout/.git"; then
  mkdir -p "$(dirname "$checkout")"
  git clone https://github.com/teamziax/libdatachannel-java.git "$checkout"
fi
if test -n "$(git -C "$checkout" status --porcelain)"; then echo 'Native checkout must be clean' >&2; exit 1; fi
if test "$(git -C "$checkout" rev-parse HEAD)" != "$revision"; then
  git -C "$checkout" fetch origin "$revision"
  git -C "$checkout" checkout --detach "$revision"
fi
git -C "$checkout" submodule update --init --recursive
"$checkout/scripts/package-admission-development.sh" "${WARDEN_MAVEN_REPOSITORY:-$HOME/.m2/repository}"
