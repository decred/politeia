#!/bin/bash
# The script does automatic checking on a Go package and its sub-packages, including:
# 1. gofmt         (http://golang.org/cmd/gofmt/)
# 2. go vet        (http://golang.org/cmd/vet)
# 3. gosimple      (https://github.com/dominikh/go-simple)
# 4. unconvert     (https://github.com/mdempsky/unconvert)
# 5. ineffassign   (https://github.com/gordonklaus/ineffassign)
# 6. misspell      (https://github.com/client9/misspell)
# 7. bodyclose     (https://github.com/timakin/bodyclose)
# 8. race detector (http://blog.golang.org/race-detector)
# 9. test coverage (http://blog.golang.org/cover)

set -ex

# run tests
env GORACE="halt_on_error=1" go test -short -race ./...

# golangci-lint (github.com/golangci/golangci-lint) is used to run each each
# static checker.

# check linters
golangci-lint run
