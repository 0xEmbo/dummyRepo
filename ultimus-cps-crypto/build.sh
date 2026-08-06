#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$ROOT/build/classes" "$ROOT/build/jar"
MONTOYA="${MONTOYA_JAR:-/tmp/montoya-api.jar}"
GSON="${GSON_JAR:-/tmp/gson.jar}"
if [[ ! -f "$MONTOYA" ]]; then
  curl -fsSL "https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2025.8/montoya-api-2025.8.jar" -o "$MONTOYA"
fi
if [[ ! -f "$GSON" ]]; then
  curl -fsSL "https://repo1.maven.org/maven2/com/google/code/gson/gson/2.11.0/gson-2.11.0.jar" -o "$GSON"
fi
find "$ROOT/src" -name '*.java' > "$ROOT/build/sources.list"
javac --release 21 -cp "$MONTOYA:$GSON" -d "$ROOT/build/classes" @"$ROOT/build/sources.list"
rm -rf "$ROOT/build/shade" && mkdir -p "$ROOT/build/shade"
cp -a "$ROOT/build/classes/." "$ROOT/build/shade/"
( cd "$ROOT/build/shade" && jar xf "$GSON" && rm -rf META-INF/maven META-INF/MANIFEST.MF META-INF/*.SF META-INF/*.RSA META-INF/*.DSA 2>/dev/null || true )
cat > "$ROOT/build/manifest.mf" << 'EOF'
Manifest-Version: 1.0
Created-By: Ultimus CPS Crypto rebuild
EOF
jar cfm "$ROOT/build/jar/ultimus-cps-crypto.jar" "$ROOT/build/manifest.mf" -C "$ROOT/build/shade" .
cp "$ROOT/build/jar/ultimus-cps-crypto.jar" "$ROOT/ultimus-cps-crypto.jar"
echo "Built $ROOT/ultimus-cps-crypto.jar"
