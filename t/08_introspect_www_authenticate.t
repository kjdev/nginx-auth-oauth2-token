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

=== TEST 1: default - emits Bearer error="invalid_token" challenge
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


=== TEST 2: explicit on - same as default
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/inactive;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_www_authenticate    on;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer invalid_token
--- error_code: 401
--- response_headers
WWW-Authenticate: Bearer error="invalid_token"


=== TEST 3: off - suppresses WWW-Authenticate header (inactive token)
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/inactive;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_www_authenticate    off;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer invalid_token
--- error_code: 401
--- response_headers
!WWW-Authenticate


=== TEST 4: off - suppresses WWW-Authenticate header (no token)
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/active;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_www_authenticate    off;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- error_code: 401
--- response_headers
!WWW-Authenticate


=== TEST 5: custom string replaces the default challenge
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/inactive;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_www_authenticate    'Bearer resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", scope="mcp:read"';

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer invalid_token
--- error_code: 401
--- response_headers
WWW-Authenticate: Bearer resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", scope="mcp:read"


=== TEST 6: custom string with variable expansion
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/inactive;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_www_authenticate    'Bearer realm="$host"';

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Host: rs.example.com
Authorization: Bearer invalid_token
--- error_code: 401
--- response_headers
WWW-Authenticate: Bearer realm="rs.example.com"


=== TEST 7: server-scope off is inherited by location
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
--- http_config
    auth_oauth2_token_client_id     "test-client";
    auth_oauth2_token_client_secret "test-secret";
    auth_oauth2_token_www_authenticate off;

    server {
        listen 1985;

        location /introspect/inactive {
            add_header Content-Type application/json;
            return 200 '{"active":false}';
        }
    }

    server {
        listen 1986;

        location / {
            return 200 "backend OK";
        }
    }
--- request
GET /test
--- more_headers
Authorization: Bearer invalid_token
--- error_code: 401
--- response_headers
!WWW-Authenticate


=== TEST 8: location overrides server off with custom string
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/inactive;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_www_authenticate    'Bearer realm="api"';

        proxy_pass http://127.0.0.1:1986/;
    }
--- http_config
    auth_oauth2_token_client_id     "test-client";
    auth_oauth2_token_client_secret "test-secret";
    auth_oauth2_token_www_authenticate off;

    server {
        listen 1985;

        location /introspect/inactive {
            add_header Content-Type application/json;
            return 200 '{"active":false}';
        }
    }

    server {
        listen 1986;

        location / {
            return 200 "backend OK";
        }
    }
--- request
GET /test
--- more_headers
Authorization: Bearer invalid_token
--- error_code: 401
--- response_headers
WWW-Authenticate: Bearer realm="api"
