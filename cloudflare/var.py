### Cloudflare WAF Variables ###

## Customer 1 ##

customer1_vars = {

    # Base Variables

    "zone_id": "some_id",
    "target": "foobar.ai",

    # DNS Record
    
    "dns_record": {
        "name": "kittens-txt",
        "hostname": "kittens",
        "type": "TXT",
        "value": "foo",
        "ttl": 3600
    },

    # Cloudflare Custom Rules

    "custom_rules": [
        {
            "action": "block",
            "expression": '(http.host eq "foo.com")',
            "description": "Block HTTP Foo Example",
            "enabled": False
        },
        {
            "action": "skip",
            "action_parameters": {"ruleset": "current"},
            "expression": '(http.user_agent eq "Stripe/1.0 (+https://stripe.com/docs/webhooks)" and ip.geoip.asnum eq 16509)',
            "description": "Permit Stripe",
            "enabled": False
        },
        {
            "action": "block",
            "expression": '(ip.geoip.country eq "T1")',
            "description": "Block TOR",
            "enabled": False
        },
        {
            "action": "block",
            "expression": "(ip.geoip.asnum in {4134 4837 9808 56048 36352 24940 26496 55286 16276 14061 9009 8048 28573 12389 9737 7713 17974 8100 37518 203020 46261 17557 396190 60781 15003 395954 396362 30633 205544 394380 19148 7203 27411 28753 133752 393886 59253 60068 199524 57858 18403 132203 45090 37963 45102 134963 48095 19531 45899 31549 8560 6724 206092 30823})",
            "description": "Block Malicious ASNs",
            "enabled": False
        },
        {
            "action": "block",
            "expression": '(cf.verified_bot_category eq "AI Crawler")',
            "description": "Block AI",
            "enabled": True
        },
    ],

    # Cloudflare Managed Rulesets

    "managed_rules": [
        {
            "description": "Enable Cloudflare OWASP Ruleset",
            "action": "execute",
            "action_parameters": {
                "id": "4814384a9e5d4991b9815dcfc25d2f1f"
            },
            "expression": '(http.host eq "target.com")',
            "enabled": True
        },
        {
            "description": "Enable Cloudflare Managed Ruleset",
            "action": "execute",
            "action_parameters": {
                "id": "efb7b8c949ac4650a09736fc376e9aee"
            },
            "expression": '(http.host eq "target.com")',
            "enabled": True
        },
        {
            "description": "Enable Cloudflare Exposed Credentials Check Ruleset",
            "action": "execute",
            "action_parameters": {
                "id": "c2e184081120413c86c3ab7e14069605"
            },
            "expression": '(http.host eq "target.com")',
            "enabled": True
        },
    ],

    # Cloudflare Bot Management

    "bot_management": {
        "fight_mode": True,
        "ai_bots_protection": "block",
        "enable_js": True,
        "sbfm_definitely_automated": "block",
        "sbfm_verified_bots": "allow",
        "sbfm_static_resource_protection": False,
        "optimize_wordpress": False
    },

    # Cloudflare Security Settings

    "security_settings": {
        "zero_rtt": "off",
        # "advanced_ddos": "on",
        "always_online": "off",
        "always_use_https": "off",
        "automatic_https_rewrites": "on",
        "brotli": "on",
        "browser_cache_ttl": 14400,
        "browser_check": "on",
        "cache_level": "aggressive",
        "challenge_ttl": 1800,
        # "ciphers": [],
        "cname_flattening": "flatten_at_root",
        "development_mode": "off",
        "early_hints": "off",
        # "edge_cache_ttl": 7200,
        "email_obfuscation": "on",
        "filter_logs_to_cloudflare": "off",
        "hotlink_protection": "on",
        "http2": "on",
        "http3": "on",
        "ip_geolocation": "on",
        "ipv6": "on",
        "log_to_cloudflare": "on",
        # "long_lived_grpc": "off",
        "max_upload": 100,
        "min_tls_version": "1.2",
        "minify": {
            "css": "on",
            "html": "on",
            "js": "on"
        },
        "mirage": "off",
        # "mobile_redirect": {
        #     "status": "off",
        #     "mobile_subdomain": None,
        #     "strip_uri": False
        # },
        "opportunistic_encryption": "on",
        "opportunistic_onion": "off",
        "orange_to_orange": "off",
        "origin_error_page_pass_thru": "off",
        "polish": "off",
        # "pq_keyex": "on",
        "prefetch_preload": "off",
        "privacy_pass": "on",
        "proxy_read_timeout": 100,
        "pseudo_ipv4": "off",
        # "replace_insecure_js": True,
        # "insecure_js": "off",
        "response_buffering": "off",
        "rocket_loader": "off",
        "security_header": {
            "enabled": True,
            "include_subdomains": True,
            "max_age": 31536000,
            "nosniff": True,
            "preload": True,
        },
        "security_level": "medium",
        "server_side_exclude": "on",
        "sort_query_string_for_cache": "off",
        "ssl": "full",
        "tls_1_3": "on",
        "tls_client_auth": "off",
        "true_client_ip_header": "off",
        "visitor_ip": "on",
        "waf": "on",
        "webp": "on",
        "websockets": "on"
    },

    # HTTP Response Headers Transform Rules

    "response_headers": {
        "csp": "default-src 'self'; script-src 'self';",
        "referrer_policy": "strict-origin-when-cross-origin",
        "reporting_endpoints": "csp-endpoint=\"https://someendpoint.e.g.pipedream\"",
        "x_content_type_options": "nosniff",
        "x_frame_options": "DENY"
    },
}

## Customer 2 ##

# Fill the void when ready...

