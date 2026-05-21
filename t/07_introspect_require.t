use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();

our $idp_port = 1985;
our $backend_port = 1986;

add_block_preprocessor(sub {
    my $block = shift;

    if (!defined $block->http_config) {
        $block->set_value('http_config', <<"_END_"
    auth_oauth2_token_client_id     "test-client";
    auth_oauth2_token_client_secret "test-secret";

    auth_oauth2_token_claim_set \$oauth2_aud   aud;
    auth_oauth2_token_claim_set \$oauth2_scope scope;

    map \$oauth2_aud \$mcp_aud_ok {
        default 0;
        "https://mcp.example.com/mcp" 1;
    }

    map \$oauth2_scope \$mcp_has_required_scope {
        default 0;
        "~(^|\\s)mcp:read(\\s|\$)" 1;
    }

    server {
        listen $idp_port;

        location /introspect/full {
            add_header Content-Type application/json;
            return 200 '{"active":true,"sub":"user123","aud":"https://mcp.example.com/mcp","scope":"mcp:read mcp:write"}';
        }

        location /introspect/wrong_aud {
            add_header Content-Type application/json;
            return 200 '{"active":true,"sub":"user123","aud":"https://other.example.com/api","scope":"mcp:read"}';
        }

        location /introspect/missing_scope {
            add_header Content-Type application/json;
            return 200 '{"active":true,"sub":"user123","aud":"https://mcp.example.com/mcp","scope":"profile email"}';
        }

        location /introspect/inactive {
            add_header Content-Type application/json;
            return 200 '{"active":false}';
        }
    }

    server {
        listen $backend_port;

        location / {
            return 200 "backend OK";
        }
    }
_END_
        );
    }
});

run_tests();

__DATA__

=== TEST 1: require passes when variable evaluates to "1"
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/full;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_require $mcp_aud_ok;
        auth_oauth2_token_require $mcp_has_required_scope error=403;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_full
--- error_code: 200


=== TEST 2: require rejects with default 401 when variable is "0"
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/wrong_aud;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_require $mcp_aud_ok;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_wrong_aud
--- error_code: 401


=== TEST 3: require rejects with error=403 when variable is "0"
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/missing_scope;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_require $mcp_has_required_scope error=403;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_missing_scope
--- error_code: 403


=== TEST 4: multiple variables on one directive evaluated with AND
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/full;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_require $mcp_aud_ok $mcp_has_required_scope error=403;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_full_multi
--- error_code: 200


=== TEST 5: multiple variables on one directive - first false rejects
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/wrong_aud;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_require $mcp_aud_ok $mcp_has_required_scope error=403;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_wrong_aud_multi
--- error_code: 403


=== TEST 6: inactive token rejected before require evaluated
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/inactive;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_require $mcp_aud_ok error=403;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_inactive
--- error_code: 401
--- response_headers
WWW-Authenticate: Bearer error="invalid_token"


=== TEST 7: cache hit still evaluates require
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/wrong_aud;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_introspect_cache    zone=require_cache:1m max_ttl=60s;

        auth_oauth2_token_require $mcp_aud_ok;

        proxy_pass http://127.0.0.1:1986/;
    }
--- pipelined_requests eval
["GET /test", "GET /test"]
--- more_headers eval
["Authorization: Bearer tok_cache_require", "Authorization: Bearer tok_cache_require"]
--- error_code eval
[401, 401]


=== TEST 8: require with code outside 400-599 is rejected at config time
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/full;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_require $mcp_aud_ok error=200;

        proxy_pass http://127.0.0.1:1986/;
    }
--- must_die
--- error_log
directive error code must be 400-599


=== TEST 9: require with error=444 is rejected at config time
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/full;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_require $mcp_aud_ok error=444;

        proxy_pass http://127.0.0.1:1986/;
    }
--- must_die
--- error_log
excluding 444 and 499


=== TEST 10: require with error=499 is rejected at config time
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/full;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_require $mcp_aud_ok error=499;

        proxy_pass http://127.0.0.1:1986/;
    }
--- must_die
--- error_log
excluding 444 and 499


=== TEST 11: require without a variable (only error=) is rejected at config time
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/full;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_require error=403;

        proxy_pass http://127.0.0.1:1986/;
    }
--- must_die
--- error_log
directive requires at least one variable


=== TEST 12: require with empty string value rejects
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/full;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_require $http_x_missing_header error=403;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_full_missing_header
--- error_code: 403


=== TEST 13: separate require directives in same location are AND-combined
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/missing_scope;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_require $mcp_aud_ok;
        auth_oauth2_token_require $mcp_has_required_scope error=403;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_missing_scope_split
--- error_code: 403


=== TEST 14: server-level require inherits into location
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/wrong_aud;
    }

    auth_oauth2_token_require $mcp_aud_ok error=403;

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_inherit_aud
--- error_code: 403
