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

=== TEST 1: exchange only - new token replaces Authorization header
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

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer original_token
--- error_code: 200
--- response_headers
X-Received-Auth: Bearer new_exchanged_token_xyz


=== TEST 2: exchange only - no Authorization header returns 401
--- config
    location = /_token {
        internal;
        proxy_pass http://127.0.0.1:1985/token/ok;
    }

    location /test {
        auth_oauth2_token_exchange          on;
        auth_oauth2_token_token_endpoint    /_token;
        auth_oauth2_token_audience          "backend-service";

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- error_code: 401


=== TEST 3: exchange variables are populated
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

        add_header X-New-Token      $oauth2_token_new_token      always;
        add_header X-New-Token-Type $oauth2_token_new_token_type always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer original_token
--- error_code: 200
--- response_headers
X-New-Token: new_exchanged_token_xyz
X-New-Token-Type: Bearer


=== TEST 4: introspect + exchange full pipeline
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

        add_header X-Token-Sub      $oauth2_token_sub      always;
        add_header X-New-Token      $oauth2_token_new_token always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer original_token
--- error_code: 200
--- response_headers
X-Token-Sub: user123
X-New-Token: new_exchanged_token_xyz
X-Received-Auth: Bearer new_exchanged_token_xyz


=== TEST 5: exchange endpoint returns error
--- config
    location = /_token {
        internal;
        proxy_pass http://127.0.0.1:1985/token/error;
    }

    location /test {
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
