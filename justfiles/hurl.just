
hurl_opts := "--test --jobs 4 --variables-file ./tests/variables"
    
wait-for-api:
    hurl tests/health.hurl --retry 5 --retry-interval 1000 {{ hurl_opts }}
    
hurl_test *args: wait-for-api
    hurl tests/*.hurl {{ hurl_opts }} {{ args }}

run-release: shutdown
    just run-q &  

# will run the server without the logs
[no-exit-message]
@run-q *args:
    cargo run {{args}} 2>&1

# shutdown whatever is running at the port    
shutdown:
    lsof -t -i:{{SERVER_PORT}} | xargs -r kill    

# ---------------------------------------------------------------------------
# compose the api_test
hurl_tests:
    #!/usr/bin/env bash
    just shutdown
    just run-release 2>&1
    just hurl_test
    just shutdown