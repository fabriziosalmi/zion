vcl 4.1;

backend nginx {
    .host = "nginx";
    .port = "8080";
    .connect_timeout = 1s;
    .first_byte_timeout = 5s;
    .between_bytes_timeout = 2s;
}

backend nginx_modsec {
    .host = "nginx-modsec";
    .port = "8080";
    .connect_timeout = 1s;
    .first_byte_timeout = 5s;
    .between_bytes_timeout = 2s;
}

sub vcl_recv {
    set req.backend_hint = nginx;

    # Cache static assets aggressively
    if (req.url ~ "^/_next/static/") {
        unset req.http.Cookie;
        return (hash);
    }

    # API calls - pass through
    if (req.url ~ "^/api/") {
        return (pass);
    }

    return (hash);
}

sub vcl_backend_response {
    if (bereq.url ~ "^/_next/static/") {
        set beresp.ttl = 365d;
        set beresp.http.Cache-Control = "public, max-age=31536000, immutable";
        unset beresp.http.Set-Cookie;
    }
}

sub vcl_deliver {
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }
}
