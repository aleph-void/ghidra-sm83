#!/usr/bin/env bash
# Compile the module's Java (loader, analyzers, userop library) into lib/SM83.jar so a Ghidra
# install that has this directory linked/copied under Ghidra/Processors/SM83 picks it up
# (Ghidra loads <module>/lib/*.jar).  The release route is `gradle buildExtension`; this is the
# quick path for the test harness.
#   GHIDRA_INSTALL_DIR=... test/build-jar.sh
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
MOD=$(cd "$(dirname "$0")/.." && pwd)
G=$GHIDRA_INSTALL_DIR/Ghidra
CP=$(find "$G/Framework" "$G/Features" "$G/Debug" -name '*.jar' ! -name '*-src*' | tr '\n' ':')
JAVAC=javac
[[ -n ${JAVA_HOME:-} ]] && JAVAC=$JAVA_HOME/bin/javac
OUT=$(mktemp -d "${TMPDIR:-/tmp}/SM83-jar.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
"$JAVAC" -nowarn --release 21 -cp "$CP" -d "$OUT" $(find "$MOD/src/main/java" -name '*.java')
mkdir -p "$MOD/lib"
JAR=jar
[[ -n ${JAVA_HOME:-} ]] && JAR=$JAVA_HOME/bin/jar
# write and rename, so a running Ghidra keeps reading the jar it opened
"$JAR" cf "$MOD/lib/SM83.jar.tmp" -C "$OUT" .
mv "$MOD/lib/SM83.jar.tmp" "$MOD/lib/SM83.jar"
echo "built $MOD/lib/SM83.jar"
