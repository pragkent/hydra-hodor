GIT_COMMIT := $(shell git rev-parse --short HEAD)
GIT_DIRTY := $(shell test -n "`git status --porcelain`" && echo "*" || true)
LDFLAGS := " -X main.GitCommit=${GIT_COMMIT}${GIT_DIRTY}"

bin:
	go build -ldflags ${LDFLAGS} -o bin/hydra-hodor

docker-bin:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags ${LDFLAGS} -o bin/hydra-hodor

fmt:
	go fmt ./...

test:
	go test ./...

testcover:
	go test -cover ./...

testrace:
	go test -race ./...

vet:
	go vet ./...

dep:
	dep -ensure -v

clean:
	rm -f bin/

.PHONY: bin docker-bin fmt test cover testrace vet clean
