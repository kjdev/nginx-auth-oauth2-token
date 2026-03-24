use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();

# debug log level required for cache hit/miss verification
$ENV{TEST_NGINX_LOG_LEVEL} = 'debug';

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

=== TEST 1: cache enabled - multiple requests succeed
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/active;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_introspect_cache    zone=introspect_t1:1m max_ttl=60s;

        add_header X-Token-Sub    $oauth2_token_sub    always;
        add_header X-Token-Active $oauth2_token_active always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- pipelined_requests eval
["GET /test", "GET /test"]
--- more_headers eval
["Authorization: Bearer cached_token_1", "Authorization: Bearer cached_token_1"]
--- error_code eval
[200, 200]
--- response_headers eval
[
  "X-Token-Active: 1\nX-Token-Sub: user123",
  "X-Token-Active: 1\nX-Token-Sub: user123"
]


=== TEST 2: without cache - no cache hits occur
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
--- pipelined_requests eval
["GET /test", "GET /test"]
--- more_headers eval
["Authorization: Bearer no_cache_token", "Authorization: Bearer no_cache_token"]
--- error_code eval
[200, 200]
--- response_headers eval
[
  "X-Token-Sub: user123",
  "X-Token-Sub: user123"
]
--- no_error_log
introspection cache hit


=== TEST 3: inactive response is not cached
Two requests with inactive token both return 401.
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/inactive;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_introspect_cache    zone=introspect_t3:1m max_ttl=60s;

        proxy_pass http://127.0.0.1:1986/;
    }
--- pipelined_requests eval
["GET /test", "GET /test"]
--- more_headers eval
["Authorization: Bearer inactive_token", "Authorization: Bearer inactive_token"]
--- error_code eval
[401, 401]
--- no_error_log
introspection cache hit


=== TEST 4: different tokens have separate cache entries
Each token uses a different introspect endpoint returning a different sub.
token_a -> sub=user_a, token_b -> sub=user_b.
Third request (token_a again) must return sub=user_a from cache, not sub=user_b.
--- http_config
    auth_oauth2_token_client_id     "test-client";
    auth_oauth2_token_client_secret "test-secret";

    server {
        listen 1985;

        location /introspect/for_a {
            add_header Content-Type application/json;
            return 200 '{"active":true,"sub":"user_a","scope":"openid","client_id":"test-app","exp":9999999999}';
        }

        location /introspect/for_b {
            add_header Content-Type application/json;
            return 200 '{"active":true,"sub":"user_b","scope":"openid","client_id":"test-app","exp":9999999999}';
        }
    }

    server {
        listen 1986;

        location / {
            return 200 "backend OK";
        }
    }
--- config
    location = /_introspect_a {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/for_a;
    }

    location = /_introspect_b {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/for_b;
    }

    location /test-a {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect_a;
        auth_oauth2_token_introspect_cache    zone=introspect_t4:1m max_ttl=60s;

        add_header X-Token-Sub $oauth2_token_sub always;

        proxy_pass http://127.0.0.1:1986/;
    }

    location /test-b {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect_b;
        auth_oauth2_token_introspect_cache    zone=introspect_t4:1m max_ttl=60s;

        add_header X-Token-Sub $oauth2_token_sub always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- pipelined_requests eval
["GET /test-a", "GET /test-b", "GET /test-a"]
--- more_headers eval
["Authorization: Bearer token_a", "Authorization: Bearer token_b", "Authorization: Bearer token_a"]
--- error_code eval
[200, 200, 200]
--- response_headers eval
[
  "X-Token-Sub: user_a",
  "X-Token-Sub: user_b",
  "X-Token-Sub: user_a"
]


=== TEST 5: cache directive with zone and max_ttl
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/active;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_introspect_cache    zone=introspect_t5:2m max_ttl=120s;

        add_header X-Token-Scope  $oauth2_token_scope  always;
        add_header X-Token-Active $oauth2_token_active always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer directive_test
--- error_code: 200
--- response_headers
X-Token-Active: 1
X-Token-Scope: openid profile
