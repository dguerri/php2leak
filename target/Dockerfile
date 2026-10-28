# Vulnerable PHP 8.4.26 + Apache mod_php (prefork) testbed target.
#
# This image intentionally pins PHP 8.4.26, which is vulnerable to the
# PHP2Shell chain (CVE-2026-109618 / CVE-2026-109619). It is fixed in 8.4.27.
#
# Stock Apache prefork MPM is used (no worker-pinning): the exploit sends its
# arm + leak requests over ONE HTTP/1.1 keep-alive connection, which prefork
# serves from the same child process (same ASLR + stale .bss globals).
FROM php:8.4.26-apache-bookworm

# --- Fully default PHP config (no php.ini overrides needed) ---
COPY php.ini /usr/local/etc/php/conf.d/zz-php2leak.ini

# --- A trivial application: the vulnerable path runs before any script code ---
COPY index.php /var/www/html/index.php
# Ground-truth addresses for verifying the leak (/proc/self/maps)
COPY debug.php /var/www/html/debug.php

# Make sure www-data can write session files (files save handler)
RUN mkdir -p /var/lib/php/sessions && chown www-data:www-data /var/lib/php/sessions

EXPOSE 80
