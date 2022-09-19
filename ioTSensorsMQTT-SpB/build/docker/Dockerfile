FROM golang:1.19 AS build

ENV CGO_ENABLED=0
ENV GOOS=linux
RUN useradd -u 10001 ioTSensors

WORKDIR /go/src/github.com/amineamaach/simulators/iotSensorsMQTT-SpB/

# Update dependencies
COPY go.* /go/src/github.com/amineamaach/simulators/iotSensorsMQTT-SpB/
RUN go mod download

# Build
COPY . /go/src/github.com/amineamaach/simulators/iotSensorsMQTT-SpB/
RUN go build -tags "timetzdata" -o ./target/ioTSensorsSpB ./cmd/sparkplugb/

# Pack
FROM busybox AS package

LABEL maintainer="Amine Amaach <amine.amaach@um6p.ma>"

WORKDIR /

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /go/src/github.com/amineamaach/simulators/iotSensorsMQTT-SpB/target/ioTSensorsSpB .
COPY ./configs/config.json /configs/config.json

USER ioTSensors

EXPOSE 8080

ENTRYPOINT ["/ioTSensorsSpB"]
