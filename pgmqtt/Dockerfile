FROM golang

RUN mkdir -p /go/src/simulators

ADD . /go/src/simulators

RUN go get  -t -v ./...
RUN go get  github.com/canthefason/go-watcher
RUN go install github.com/canthefason/go-watcher/cmd/watcher

ENTRYPOINT  watcher -run simulators/pgmqtt/cmd/  -watch simulators/pgmqtt
