use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();

# debug log level required for cache hit/miss verification
$ENV{TEST_NGINX_LOG_LEVEL} = 'debug';

our $idp_port = 1985;
our $backend_port = 1986;

run_tests();

__DATA__

=== TEST 1: cache enabled - multiple requests succeed
--- http_config
    auth_oauth2_token_client_id     "test-client";
    auth_oauth2_token_client_secret "test-secret";

    server {
        listen 1985;

        location /token/ok {
            add_header Content-Type application/json;
            return 200 '{"access_token":"new_token_abc","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":300}';
        }
    }

    server {
        listen 1986;

        location / {
            add_header X-Received-Auth $http_authorization always;
            return 200 "backend OK";
        }
    }
--- config
    location = /_token {
        internal;
        proxy_pass http://127.0.0.1:1985/token/ok;
    }

    location /test {
        auth_oauth2_token_exchange          on;
        auth_oauth2_token_token_endpoint    /_token;
        auth_oauth2_token_audience          "backend-service";
        auth_oauth2_token_scope             "api:read";
        auth_oauth2_token_exchange_cache    zone=exchange_t1:1m max_ttl=60s;

        add_header X-New-Token $oauth2_token_new_token always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- pipelined_requests eval
["GET /test", "GET /test"]
--- more_headers eval
["Authorization: Bearer original_token", "Authorization: Bearer original_token"]
--- error_code eval
[200, 200]
--- response_headers eval
[
  "X-New-Token: new_token_abc\nX-Received-Auth: Bearer new_token_abc",
  "X-New-Token: new_token_abc\nX-Received-Auth: Bearer new_token_abc"
]


=== TEST 2: without cache - no cache hits occur
--- http_config
    auth_oauth2_token_client_id     "test-client";
    auth_oauth2_token_client_secret "test-secret";

    server {
        listen 1985;

        location /token/ok {
            add_header Content-Type application/json;
            return 200 '{"access_token":"new_token_abc","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":300}';
        }
    }

    server {
        listen 1986;

        location / {
            add_header X-Received-Auth $http_authorization always;
            return 200 "backend OK";
        }
    }
--- config
    location = /_token {
        internal;
        proxy_pass http://127.0.0.1:1985/token/ok;
    }

    location /test {
        auth_oauth2_token_exchange          on;
        auth_oauth2_token_token_endpoint    /_token;
        auth_oauth2_token_audience          "backend-service";
        auth_oauth2_token_scope             "api:read";

        add_header X-New-Token $oauth2_token_new_token always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- pipelined_requests eval
["GET /test", "GET /test"]
--- more_headers eval
["Authorization: Bearer original_token", "Authorization: Bearer original_token"]
--- error_code eval
[200, 200]
--- response_headers eval
[
  "X-New-Token: new_token_abc",
  "X-New-Token: new_token_abc"
]
--- no_error_log
exchange cache hit


=== TEST 3: different tokens produce separate cache entries
Each token endpoint returns a different exchanged token.
token_a -> exchanged_a, token_b -> exchanged_b.
Third request (token_a again) must return exchanged_a from cache, not exchanged_b.
--- http_config
    auth_oauth2_token_client_id     "test-client";
    auth_oauth2_token_client_secret "test-secret";

    server {
        listen 1985;

        location /token/for_a {
            add_header Content-Type application/json;
            return 200 '{"access_token":"exchanged_a","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":300}';
        }

        location /token/for_b {
            add_header Content-Type application/json;
            return 200 '{"access_token":"exchanged_b","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":300}';
        }
    }

    server {
        listen 1986;

        location / {
            add_header X-Received-Auth $http_authorization always;
            return 200 "backend OK";
        }
    }
--- config
    location = /_token_a {
        internal;
        proxy_pass http://127.0.0.1:1985/token/for_a;
    }

    location = /_token_b {
        internal;
        proxy_pass http://127.0.0.1:1985/token/for_b;
    }

    location /test-a {
        auth_oauth2_token_exchange          on;
        auth_oauth2_token_token_endpoint    /_token_a;
        auth_oauth2_token_audience          "backend-service";
        auth_oauth2_token_scope             "api:read";
        auth_oauth2_token_exchange_cache    zone=exchange_t3:1m max_ttl=60s;

        add_header X-New-Token $oauth2_token_new_token always;

        proxy_pass http://127.0.0.1:1986/;
    }

    location /test-b {
        auth_oauth2_token_exchange          on;
        auth_oauth2_token_token_endpoint    /_token_b;
        auth_oauth2_token_audience          "backend-service";
        auth_oauth2_token_scope             "api:read";
        auth_oauth2_token_exchange_cache    zone=exchange_t3:1m max_ttl=60s;

        add_header X-New-Token $oauth2_token_new_token always;

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
  "X-New-Token: exchanged_a",
  "X-New-Token: exchanged_b",
  "X-New-Token: exchanged_a"
]


=== TEST 4: cache key includes audience and scope
Two locations with different audience use separate token endpoints returning
distinct tokens. They share the same cache zone but must get separate entries.
--- http_config
    auth_oauth2_token_client_id     "test-client";
    auth_oauth2_token_client_secret "test-secret";

    server {
        listen 1985;

        location /token/for_svc_a {
            add_header Content-Type application/json;
            return 200 '{"access_token":"exchanged_for_svc_a","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":300}';
        }

        location /token/for_svc_b {
            add_header Content-Type application/json;
            return 200 '{"access_token":"exchanged_for_svc_b","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":300}';
        }
    }

    server {
        listen 1986;

        location / {
            add_header X-Received-Auth $http_authorization always;
            return 200 "backend OK";
        }
    }
--- config
    location = /_token_a {
        internal;
        proxy_pass http://127.0.0.1:1985/token/for_svc_a;
    }

    location = /_token_b {
        internal;
        proxy_pass http://127.0.0.1:1985/token/for_svc_b;
    }

    location /test-a {
        auth_oauth2_token_exchange          on;
        auth_oauth2_token_token_endpoint    /_token_a;
        auth_oauth2_token_audience          "service-a";
        auth_oauth2_token_scope             "read";
        auth_oauth2_token_exchange_cache    zone=exchange_t4:1m max_ttl=60s;

        add_header X-New-Token $oauth2_token_new_token always;

        proxy_pass http://127.0.0.1:1986/;
    }

    location /test-b {
        auth_oauth2_token_exchange          on;
        auth_oauth2_token_token_endpoint    /_token_b;
        auth_oauth2_token_audience          "service-b";
        auth_oauth2_token_scope             "write";
        auth_oauth2_token_exchange_cache    zone=exchange_t4:1m max_ttl=60s;

        add_header X-New-Token $oauth2_token_new_token always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- pipelined_requests eval
["GET /test-a", "GET /test-b", "GET /test-a"]
--- more_headers eval
["Authorization: Bearer same_token", "Authorization: Bearer same_token", "Authorization: Bearer same_token"]
--- error_code eval
[200, 200, 200]
--- response_headers eval
[
  "X-New-Token: exchanged_for_svc_a",
  "X-New-Token: exchanged_for_svc_b",
  "X-New-Token: exchanged_for_svc_a"
]
