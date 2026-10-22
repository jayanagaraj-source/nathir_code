#mock vulnerable PHP host (v2, source-built)
#
# Purpose: seed a known pre-patch PHP release so Cloud Security /
# Vulnerability Management scanning can match on version and surface:
#   - CVE-2026-109618  (RCE via OOM corruption)      — CVSSv4.0 9.2
#   - CVE-2026-109619  (RCE via stale global state)   — CVSSv4.0 9.2
#
# Source: PHP security advisory (php.net/archive/2026.php#2026-10-21-5),
# PHP GitHub advisories GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp.
#
# This builds straight from an official pre-fix php.net source tarball —
# no distro-package-string guessing, no exploit code, no PoC. Detection
# relies entirely on the reported `php -v` / `phpversion()` string, which
# is what version-matching scanners key off.
#
# Fixed versions (deliberately NOT used here):
#   8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
# EOL branches (7.4-8.1) got only source backports, never a full release;
# 5.4-7.3 got no fix at all. This fixture uses the last 8.2.x release
# before the fix so the branch is still "supported" but clearly vulnerable.

FROM debian:bookworm-slim AS builder

ARG PHP_VULN_VERSION=8.2.34

RUN apt-get update && apt-get install -y --no-install-recommends \
        wget ca-certificates build-essential autoconf bison re2c \
        libxml2-dev libsqlite3-dev libssl-dev zlib1g-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN wget -q https://www.php.net/distributions/php-${PHP_VULN_VERSION}.tar.gz && \
    tar xzf php-${PHP_VULN_VERSION}.tar.gz

WORKDIR /usr/src/php-${PHP_VULN_VERSION}
RUN ./configure --prefix=/opt/php-vuln \
        --disable-cgi --without-pear && \
    make -j"$(nproc)" && \
    make install

FROM debian:bookworm-slim
COPY --from=builder /opt/php-vuln /opt/php-vuln
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 libxml2 libsqlite3-0 && \
    rm -rf /var/lib/apt/lists/*
ENV PATH="/opt/php-vuln/bin:${PATH}"

# Leave upload_progress / memory handling at build defaults (the
# vulnerable config) -- do not apply the interim mitigations from the
# advisory, since the point of this fixture is to be detected, not hardened.

LABEL vuln.cve="CVE-2026-109618,CVE-2026-109619" \
      vuln.name="PHP2Shell" \
      vuln.cvss="9.2" \
      vuln.affected="PHP 8.2.x < 8.2.35" \
      vuln.fixed_in="8.2.35,8.3.36,8.4.27,8.5.12" \
      vuln.advisory="https://www.php.net/archive/2026.php#2026-10-21-5" \
      vuln.purpose="tigergate-test-infra vulnerability-management detection fixture -- version-match only, no exploit code"

CMD ["php", "-v"]
