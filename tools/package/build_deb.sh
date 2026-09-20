#!/bin/sh
# Builds the unsigned MON Linux endpoint collector .deb from a built collector binary.
# usage: build_deb.sh <collector-binary> <version> <output-dir>
set -eu
BIN="$1"; VERSION="$2"; OUT="$3"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
PKG="$ROOT/pkg"
mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/lib/systemd/system" "$PKG/etc/mon-linux-endpoint-collector" "$OUT"
install -m 0755 "$BIN" "$PKG/usr/bin/mon-linux-endpoint-collector"
install -m 0644 "$HERE/packaging/linux/collector.env" "$PKG/etc/mon-linux-endpoint-collector/collector.env"
# Derive the packaged unit from the repository-owned unit: absolute binary path and
# env-file driven identifiers instead of <PLACEHOLDERS>.
sed \
  -e 's#/usr/local/bin/mon-linux-endpoint-collector#/usr/bin/mon-linux-endpoint-collector#' \
  -e 's#"<TENANT_ID>"#"${MON_TENANT_ID}"#' \
  -e 's#"<SITE_ID>"#"${MON_SITE_ID}"#' \
  -e 's#"<SENSOR_ID>"#"${MON_SENSOR_ID}"#' \
  -e 's#--site-url http://127.0.0.1:8090#--site-url ${MON_SITE_URL}#' \
  -e 's#--poll-interval-seconds 30#--poll-interval-seconds ${MON_POLL_INTERVAL_SECONDS}#' \
  -e 's#^Type=simple#Type=simple\nEnvironmentFile=/etc/mon-linux-endpoint-collector/collector.env#' \
  "$HERE/tools/systemd/mon-linux-endpoint-collector.service" \
  > "$PKG/lib/systemd/system/mon-linux-endpoint-collector.service"
chmod 0644 "$PKG/lib/systemd/system/mon-linux-endpoint-collector.service"
for script in postinst prerm postrm; do
  install -m 0755 "$HERE/packaging/linux/$script" "$PKG/DEBIAN/$script"
done
echo "/etc/mon-linux-endpoint-collector/collector.env" > "$PKG/DEBIAN/conffiles"
SIZE="$(du -sk "$PKG/usr" "$PKG/lib" "$PKG/etc" | awk '{s+=$1} END {print s}')"
cat > "$PKG/DEBIAN/control" <<CONTROL
Package: mon-linux-endpoint-collector
Version: $VERSION
Section: admin
Priority: optional
Architecture: amd64
Maintainer: MON Security Fabric <noreply@example.invalid>
Installed-Size: $SIZE
Depends: systemd, adduser
Description: MON Linux endpoint collector (unsigned candidate)
 Collects Linux endpoint authentication and process telemetry for MON.
 Contains no credentials; identifiers are configured in
 /etc/mon-linux-endpoint-collector/collector.env.
CONTROL
dpkg-deb --root-owner-group --build "$PKG" "$OUT/mon-linux-endpoint-collector_${VERSION}_amd64.deb"
