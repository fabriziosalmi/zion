# The lab image of one WordPress/PHP-FPM version (#699), CVE-2017-1001000. BASE_IMAGE pins the
# official wordpress image, by digest, to the exact vulnerable/fixed pair (see ../compose.yml);
# nothing here re-installs WordPress at a different version, so the version that really runs is
# whatever that pinned base shipped -- measured by stack.toml's version_cmd and written into the
# lab's result JSON, never assumed from this file.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

# The shipped php-fpm pool (www.conf) only listens on 127.0.0.1:9000 -- fine when nginx is the
# same container (the official apache variant), but here nginx is a separate container on the
# compose network and needs to reach fpm over TCP. This override loads after www.conf
# (alphabetically: zz- sorts last in php-fpm.d/*.conf) and switches the listener to all
# interfaces.
COPY zz-listen-any.conf /usr/local/etc/php-fpm.d/zz-listen-any.conf

# The base image's own docker-entrypoint.sh (wp-config.php generation + CREATE DATABASE IF NOT
# EXISTS) only runs its setup when invoked with CMD exactly "php-fpm" (it gates on
# `[ "$1" = php-fpm ]`), and ends with a real exec() -- nothing can run after it from inside
# that script, so forking it to add a step is awkward. Instead this shims the "php-fpm" binary
# itself: the real one is renamed, and a wrapper of the same name takes its place, so
# `exec "$@"` (the vendor script's last line, "$@" being the single arg "php-fpm") resolves via
# PATH to the wrapper. The wrapper runs the lab's one-time WordPress install
# (install-bootstrap.php, using wp_install() the way wp-admin/install.php itself does -- no
# wp-cli needed, nothing extra to download) and then hands off, still by exec, so the real
# php-fpm binary ends up PID 1.
RUN mv /usr/local/sbin/php-fpm /usr/local/sbin/php-fpm-real
COPY php-fpm-shim.sh /usr/local/sbin/php-fpm
COPY install-bootstrap.php /usr/local/bin/wp-install-bootstrap.php
RUN chmod +x /usr/local/sbin/php-fpm /usr/local/sbin/php-fpm-real

# /var/www/html is still empty at build time (the base image's entrypoint only copies WordPress
# core into it at container start), so the must-use plugin that keeps siteurl/home matching the
# request's own Host header (mu-siteurl.php) is staged here and copied into place by the shim,
# once the real WordPress tree exists.
RUN mkdir -p /usr/local/share/zion-lab
COPY mu-siteurl.php /usr/local/share/zion-lab/mu-siteurl.php
