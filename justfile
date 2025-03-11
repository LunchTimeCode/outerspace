import 'justfiles/linting.just'
import 'justfiles/docker.just'
import 'justfiles/hurl.just'

image_name := "ghcr.io/lunchtimecode/free_lunch"
SERVER_PORT := "9999"


run *args:
    cargo run -- {{args}}


w:
    cargo watch --ignore 'assets/css' -s 'just run'
