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

    server {
        listen $idp_port;

        location /introspect/active {
            add_header Content-Type application/json;
            return 200 '{"active":true,"sub":"user123","scope":"openid profile","client_id":"test-app","exp":9999999999}';
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

=== TEST 1: default phase (ACCESS) - claims resolved, PREACCESS ignored
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/active;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        add_header X-Token-Sub $oauth2_token_sub always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer valid_token_123
--- error_code: 200
--- response_headers
X-Token-Sub: user123
--- error_log: auth_oauth2_token: ignore phase: PREACCESS
--- log_level: debug


=== TEST 2: explicit preaccess phase - claims resolved, ACCESS ignored
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/active;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_phase               preaccess;

        add_header X-Token-Sub $oauth2_token_sub always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer valid_token_123
--- error_code: 200
--- response_headers
X-Token-Sub: user123
--- error_log: auth_oauth2_token: ignore phase: ACCESS
--- log_level: debug


=== TEST 3: explicit access phase - equivalent to default
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/active;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_phase               access;

        add_header X-Token-Sub $oauth2_token_sub always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer valid_token_123
--- error_code: 200
--- response_headers
X-Token-Sub: user123
--- error_log: auth_oauth2_token: ignore phase: PREACCESS
--- log_level: debug


=== TEST 4: preaccess phase - claim resolved before a later PREACCESS handler
limit_req is a PREACCESS-phase handler. With auth_oauth2_token_phase preaccess,
this module must resolve $oauth2_token_sub and still let limit_req run
afterward, so per-subject rate limiting keyed on the claim is enforced.
--- http_config
    auth_oauth2_token_client_id     "test-client";
    auth_oauth2_token_client_secret "test-secret";

    limit_req_zone $oauth2_token_sub zone=phase_t4:1m rate=1r/m;

    server {
        listen 1985;

        location /introspect/active {
            add_header Content-Type application/json;
            return 200 '{"active":true,"sub":"user123","scope":"openid profile","client_id":"test-app","exp":9999999999}';
        }
    }

    server {
        listen 1986;

        location / {
            return 200 "backend OK";
        }
    }
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/active;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_phase               preaccess;

        limit_req zone=phase_t4;

        proxy_pass http://127.0.0.1:1986/;
    }
--- pipelined_requests eval
["GET /test", "GET /test"]
--- more_headers eval
["Authorization: Bearer valid_token_123", "Authorization: Bearer valid_token_123"]
--- error_code eval
[200, 503]
