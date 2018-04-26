FROM alpine:3.5

RUN apk add --no-cache ca-certificates

COPY /bin/hydra-hodor /usr/bin/

ENTRYPOINT ["/usr/bin/hydra-hodor"]
