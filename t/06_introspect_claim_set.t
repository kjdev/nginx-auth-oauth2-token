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

    auth_oauth2_token_claim_set \$oauth2_aud            aud;
    auth_oauth2_token_claim_set \$oauth2_iat            iat;
    auth_oauth2_token_claim_set \$oauth2_verified       email_verified;
    auth_oauth2_token_claim_set \$oauth2_realm_access   realm_access;
    auth_oauth2_token_claim_set \$oauth2_absent         absent_field;

    server {
        listen $idp_port;

        location /introspect/aud_string {
            add_header Content-Type application/json;
            return 200 '{"active":true,"sub":"user123","aud":"https://api.example.com"}';
        }

        location /introspect/aud_array {
            add_header Content-Type application/json;
            return 200 '{"active":true,"sub":"user123","aud":["https://a.example.com","https://b.example.com","https://c.example.com"]}';
        }

        location /introspect/numeric {
            add_header Content-Type application/json;
            return 200 '{"active":true,"sub":"user123","iat":1700000000}';
        }

        location /introspect/bool_true {
            add_header Content-Type application/json;
            return 200 '{"active":true,"sub":"user123","email_verified":true}';
        }

        location /introspect/bool_false {
            add_header Content-Type application/json;
            return 200 '{"active":true,"sub":"user123","email_verified":false}';
        }

        location /introspect/object {
            add_header Content-Type application/json;
            return 200 '{"active":true,"sub":"user123","realm_access":{"roles":["admin","user"]}}';
        }

        location /introspect/missing {
            add_header Content-Type application/json;
            return 200 '{"active":true,"sub":"user123"}';
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

=== TEST 1: string claim is bound to variable verbatim
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/aud_string;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        add_header X-Aud "[$oauth2_aud]" always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_string
--- error_code: 200
--- response_headers
X-Aud: [https://api.example.com]


=== TEST 2: array claim is joined by commas
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/aud_array;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        add_header X-Aud "[$oauth2_aud]" always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_array
--- error_code: 200
--- response_headers
X-Aud: [https://a.example.com,https://b.example.com,https://c.example.com]


=== TEST 3: numeric claim is rendered as JSON literal
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/numeric;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        add_header X-Iat "[$oauth2_iat]" always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_numeric
--- error_code: 200
--- response_headers
X-Iat: [1700000000]


=== TEST 4: boolean true claim is rendered as "true"
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/bool_true;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        add_header X-Verified "[$oauth2_verified]" always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_bool_true
--- error_code: 200
--- response_headers
X-Verified: [true]


=== TEST 5: boolean false claim is rendered as "false"
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/bool_false;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        add_header X-Verified "[$oauth2_verified]" always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_bool_false
--- error_code: 200
--- response_headers
X-Verified: [false]


=== TEST 6: object claim is rendered as compact JSON
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/object;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        add_header X-Obj "[$oauth2_realm_access]" always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_object
--- error_code: 200
--- response_headers
X-Obj: [{"roles":["admin","user"]}]


=== TEST 7: missing claim produces empty value
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/missing;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        add_header X-Absent "[$oauth2_absent]" always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_missing
--- error_code: 200
--- response_headers
X-Absent: []


=== TEST 8: inactive token leaves variable undefined (no crash)
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/inactive;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;

        add_header X-Aud "[$oauth2_aud]" always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- request
GET /test
--- more_headers
Authorization: Bearer tok_inactive
--- error_code: 401
--- response_headers
X-Aud: []


=== TEST 9: cache hit re-binds claim variable from cached JSON
--- config
    location = /_introspect {
        internal;
        proxy_pass http://127.0.0.1:1985/introspect/aud_string;
    }

    location /test {
        auth_oauth2_token_introspect          on;
        auth_oauth2_token_introspect_endpoint /_introspect;
        auth_oauth2_token_introspect_cache    zone=claim_cache:1m max_ttl=60s;

        add_header X-Aud "[$oauth2_aud]" always;

        proxy_pass http://127.0.0.1:1986/;
    }
--- pipelined_requests eval
["GET /test", "GET /test"]
--- more_headers eval
["Authorization: Bearer tok_cache_1", "Authorization: Bearer tok_cache_1"]
--- error_code eval
[200, 200]
--- response_headers eval
[
  "X-Aud: [https://api.example.com]",
  "X-Aud: [https://api.example.com]"
]
