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

        location /introspect/inactive {
            add_header Content-Type application/json;
            return 200 '{"active":false}';
        }

        location /introspect/error {
            return 500 'Internal Server Error';
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

=== TEST 1: valid bearer token - introspection active
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/active;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        add_header X-Token-Sub    $oauth2_token_sub    always;
        add_header X-Token-Scope  $oauth2_token_scope  always;
        add_header X-Token-Active $oauth2_token_active always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer valid_token_123
--- error_code: 200
--- response_headers
X-Token-Active: 1
X-Token-Sub: user123
X-Token-Scope: openid profile


=== TEST 2: invalid bearer token - introspection inactive
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/inactive;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer invalid_token
--- error_code: 401
--- response_headers
WWW-Authenticate: Bearer error="invalid_token"


=== TEST 3: no Authorization header
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/active;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- error_code: 401


=== TEST 4: non-Bearer Authorization header
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/active;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Basic dXNlcjpwYXNz
--- error_code: 401


=== TEST 5: module disabled - request passes through
--- config
    location /test {
        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- error_code: 200


=== TEST 6: introspection endpoint returns error - returns 500
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/error;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer some_token
--- error_code: 500
