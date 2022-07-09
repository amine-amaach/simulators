# Build:
FROM golang as build

# Set the Current Working Directory inside the container
WORKDIR /simulators/pgmqtt

# Populate the module cache based on the go.{mod,sum} files.
COPY go.mod .
COPY go.sum .

# RUN go mod download

COPY . .

# Build the Go Microservice
RUN CGO_ENABLED=0 go build -o ./out/pgmqtt ./cmd/pgmqtt/

# Deployement:
# Start fresh from a smaller image
FROM alpine:latest

COPY --from=build /simulators/pgmqtt/out/pgmqtt /simulators/pgmqtt
COPY --from=build /simulators/pgmqtt/configs/ /configs/


ENTRYPOINT  ["/simulators/pgmqtt"]