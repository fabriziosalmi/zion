<?php
/**
 * Must-use plugin for the CVE lab (#699): keeps `siteurl`/`home` matching whatever Host header
 * the client actually used, instead of the one fixed value wp_install() baked in at install
 * time (there is no single real hostname here -- the same WordPress answers on its own
 * published port, through zion on a throwaway port, and from inside install-bootstrap.php with
 * no HTTP request at all). Without this, WordPress's canonical-redirect logic 301s every
 * request whose Host does not match the stored siteurl, which every probe and benign check in
 * probes.toml would otherwise have to follow instead of reading directly.
 */
add_filter('option_siteurl', 'zion_lab_dynamic_url');
add_filter('option_home', 'zion_lab_dynamic_url');

function zion_lab_dynamic_url($value) {
    if (!empty($_SERVER['HTTP_HOST'])) {
        return 'http://' . $_SERVER['HTTP_HOST'];
    }
    return $value;
}
