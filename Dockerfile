
# Purpose: seed a known-vulnerable PHP version so Cloud Security /
# Vulnerability Management scanning picks up:
#   - CVE-2026-109618  (RCE via OOM corruption, upload_progress unserializer UAF)
#   - CVE-2026-109619  (RCE via stale global state / fatal-error backtrace UAF)
#
# This installs a PHP release BELOW the fixed versions so the package
# manager's installed-version metadata (dpkg/apt) is what the scanner
# matches against. It does not include, build, or run any exploit code —
# detection only.
#
# Fixed versions (NOT used here): 8.2.35, 8.3.36, 8.4.27, 8.5.12
# Vulnerable branch used below:   8.2.x < 8.2.35

FROM debian:bookworm-slim

ARG PHP_BRANCH=8.2
# Last known-vulnerable patch release on the 8.2 branch before the fix.
# Confirm the exact prior patch version against your distro's changelog
# before relying on this for a demo — pin precisely, don't assume.
ARG PHP_VULN_VERSION=8.2.34-1~deb12u1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates gnupg wget lsb-release apt-transport-https && \
    wget -qO /etc/apt/trusted.gpg.d/sury-php.gpg https://packages.sury.org/php/apt.gpg && \
    echo "deb https://packages.sury.org/php/ bookworm main" > /etc/apt/sources.list.d/sury-php.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        php${PHP_BRANCH}=${PHP_VULN_VERSION} \
        php${PHP_BRANCH}-fpm=${PHP_VULN_VERSION} \
        php${PHP_BRANCH}-cli=${PHP_VULN_VERSION} && \
    apt-mark hold php${PHP_BRANCH} php${PHP_BRANCH}-fpm php${PHP_BRANCH}-cli && \
    rm -rf /var/lib/apt/lists/*

# Leave upload_progress and fatal_error_backtraces at their vulnerable
# defaults (do not apply the interim mitigations) so the fixture reflects
# the pre-patch configuration a scanner should flag.

LABEL vuln.cve="CVE-2026-109618,CVE-2026-109619" \
      vuln.name="PHP2Shell" \
      vuln.cvss="9.2" \
      vuln.fixed_in="8.2.35,8.3.36,8.4.27,8.5.12" \
      vuln.purpose="tigergate-test-infra vulnerability-management detection fixture"

CMD ["php", "-v"]
