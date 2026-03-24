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

        location /token/ok {
            add_header Content-Type application/json;
            return 200 '{"access_token":"new_exchanged_token_xyz","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":300}';
        }

        location /token/error {
            add_header Content-Type application/json;
            return 400 '{"error":"invalid_request"}';
        }
    }

    server {
        listen $backend_port;

        location / {
            add_header X-Received-Auth \$http_authorization always;
            return 200 "backend OK";
        }
    }
_END_
        );
    }
});

run_tests();

__DATA__

=== TEST 1: full pipeline - introspect and exchange both succeed
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/active;
    }

    location = /_token {
        internal;
        proxy_pass http://127.0.0.1:1985/token/ok;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_exchange          on;
        auth_oauth2_token_token_endpoint    /_token;
        auth_oauth2_token_audience          "backend-service";
        auth_oauth2_token_scope             "api:read";

        add_header X-Token-Sub       $oauth2_token_sub            always;
        add_header X-Token-Scope     $oauth2_token_scope          always;
        add_header X-Token-Active    $oauth2_token_active         always;
        add_header X-Token-Client-Id $oauth2_token_client_id      always;
        add_header X-New-Token       $oauth2_token_new_token      always;
        add_header X-New-Token-Type  $oauth2_token_new_token_type always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer original_token
--- error_code: 200
--- response_headers
X-Token-Active: 1
X-Token-Sub: user123
X-Token-Scope: openid profile
X-Token-Client-Id: test-app
X-New-Token: new_exchanged_token_xyz
X-New-Token-Type: Bearer
X-Received-Auth: Bearer new_exchanged_token_xyz


=== TEST 2: introspection inactive - exchange is skipped, returns 401
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/inactive;
    }

    location = /_token {
        internal;
        proxy_pass http://127.0.0.1:1985/token/ok;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_exchange          on;
        auth_oauth2_token_token_endpoint    /_token;
        auth_oauth2_token_audience          "backend-service";

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer inactive_token
--- error_code: 401
--- response_headers
WWW-Authenticate: Bearer error="invalid_token"


=== TEST 3: introspection endpoint error - exchange is skipped, returns 500
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/error;
    }

    location = /_token {
        internal;
        proxy_pass http://127.0.0.1:1985/token/ok;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_exchange          on;
        auth_oauth2_token_token_endpoint    /_token;
        auth_oauth2_token_audience          "backend-service";

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer some_token
--- error_code: 500


=== TEST 4: exchange endpoint error after successful introspection returns 500
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/active;
    }

    location = /_token {
        internal;
        proxy_pass http://127.0.0.1:1985/token/error;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_exchange          on;
        auth_oauth2_token_token_endpoint    /_token;
        auth_oauth2_token_audience          "backend-service";

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer original_token
--- error_code: 500


=== TEST 5: no Authorization header - returns 401 before any IdP call
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/active;
    }

    location = /_token {
        internal;
        proxy_pass http://127.0.0.1:1985/token/ok;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        auth_oauth2_token_exchange          on;
        auth_oauth2_token_token_endpoint    /_token;
        auth_oauth2_token_audience          "backend-service";

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- error_code: 401


=== TEST 6: both caches enabled - pipelined requests succeed
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/active;
    }

    location = /_token {
        internal;
        proxy_pass http://127.0.0.1:1985/token/ok;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_introspect_cache    zone=ie_introspect_t6:1m max_ttl=60s;

        auth_oauth2_token_exchange          on;
        auth_oauth2_token_token_endpoint    /_token;
        auth_oauth2_token_audience          "backend-service";
        auth_oauth2_token_scope             "api:read";
        auth_oauth2_token_exchange_cache    zone=ie_exchange_t6:1m max_ttl=60s;

        add_header X-Token-Sub  $oauth2_token_sub       always;
        add_header X-New-Token  $oauth2_token_new_token always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- pipelined_requests eval
["GET /test", "GET /test"]
--- more_headers eval
["Authorization: Bearer cached_pipeline_token", "Authorization: Bearer cached_pipeline_token"]
--- error_code eval
[200, 200]
--- response_headers eval
[
  "X-Token-Sub: user123\nX-New-Token: new_exchanged_token_xyz\nX-Received-Auth: Bearer new_exchanged_token_xyz",
  "X-Token-Sub: user123\nX-New-Token: new_exchanged_token_xyz\nX-Received-Auth: Bearer new_exchanged_token_xyz"
]


=== TEST 7: both caches enabled - different tokens have separate entries
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/active;
    }

    location = /_token {
        internal;
        proxy_pass http://127.0.0.1:1985/token/ok;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_introspect_cache    zone=ie_introspect_t7:1m max_ttl=60s;

        auth_oauth2_token_exchange          on;
        auth_oauth2_token_token_endpoint    /_token;
        auth_oauth2_token_audience          "backend-service";
        auth_oauth2_token_scope             "api:read";
        auth_oauth2_token_exchange_cache    zone=ie_exchange_t7:1m max_ttl=60s;

        add_header X-Token-Sub  $oauth2_token_sub       always;
        add_header X-New-Token  $oauth2_token_new_token always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- pipelined_requests eval
["GET /test", "GET /test", "GET /test"]
--- more_headers eval
["Authorization: Bearer token_a", "Authorization: Bearer token_b", "Authorization: Bearer token_a"]
--- error_code eval
[200, 200, 200]
--- response_headers eval
[
  "X-Token-Sub: user123\nX-New-Token: new_exchanged_token_xyz\nX-Received-Auth: Bearer new_exchanged_token_xyz",
  "X-Token-Sub: user123\nX-New-Token: new_exchanged_token_xyz\nX-Received-Auth: Bearer new_exchanged_token_xyz",
  "X-Token-Sub: user123\nX-New-Token: new_exchanged_token_xyz\nX-Received-Auth: Bearer new_exchanged_token_xyz"
]
