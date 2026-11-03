#!/bin/sh
# Runs once, after the base image's docker-entrypoint.sh has written wp-config.php and created
# the database but before php-fpm starts answering requests on the compose network: installs
# WordPress (wp_install()) if it is not installed yet, then hands off -- by exec, so the real
# php-fpm binary ends up PID 1, not this shim.
set -eu
# The vendor entrypoint has just copied WordPress core into /var/www/html (it was empty at
# build time, so the mu-plugin could not be placed there until now); drop in the one that
# keeps siteurl/home matching whatever Host header a request actually used (mu-siteurl.php).
mkdir -p /var/www/html/wp-content/mu-plugins
cp /usr/local/share/zion-lab/mu-siteurl.php /var/www/html/wp-content/mu-plugins/zion-lab-siteurl.php
php /usr/local/bin/wp-install-bootstrap.php
exec /usr/local/sbin/php-fpm-real "$@"
