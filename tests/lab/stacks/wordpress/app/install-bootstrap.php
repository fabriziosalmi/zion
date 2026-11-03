<?php
/**
 * One-time WordPress install for the CVE lab (#699), run by php-fpm-shim.sh before the real
 * php-fpm takes over. Uses wp_install() -- the same core function wp-admin/install.php itself
 * calls -- instead of wp-cli, so the image needs nothing beyond what the official
 * wordpress:*-fpm-alpine base already ships.
 */
chdir('/var/www/html');
// wp_install() ends by emailing the admin via wp_mail(), whose default From: address is built
// from $_SERVER['SERVER_NAME'] (pluggable.php) -- empty in this CLI context, producing the
// invalid address "wordpress@" and an uncaught PHPMailer exception. A dotted placeholder host
// keeps PHPMailer's address validator happy; nothing actually sends (no MTA in this container,
// wp_mail() just returns false, which wp_new_blog_notification() does not check).
$_SERVER['SERVER_NAME'] = 'zion-lab.invalid';
$_SERVER['SERVER_PORT'] = '80';
$_SERVER['HTTP_HOST'] = 'zion-lab.invalid';
$_SERVER['REQUEST_URI'] = '/';
define('WP_INSTALLING', true);
require '/var/www/html/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';

if (is_blog_installed()) {
    fwrite(STDERR, "zion-lab: wordpress already installed\n");
    exit(0);
}

wp_install(
    getenv('WP_SITE_TITLE') ?: 'zion-lab-wordpress',
    getenv('WP_ADMIN_USER') ?: 'admin',
    getenv('WP_ADMIN_EMAIL') ?: 'admin@example.invalid',
    true,
    '',
    getenv('WP_ADMIN_PASSWORD') ?: 'zion-lab-admin-pw-1'
);

// Default (plain) permalinks already serve /wp-json/ -- WordPress registers that rewrite rule
// unconditionally -- but pretty permalinks make the benign session's homepage and post reads
// look like an ordinary site rather than bare ?p=1 query vars.
update_option('permalink_structure', '/%postname%/');
flush_rewrite_rules(false);

fwrite(STDERR, "zion-lab: wordpress installed\n");
