# Build:
FROM golang as build

# Set the Current Working Directory inside the container
WORKDIR /simulators/ioTSensorsOPCUA

# Populate the module cache based on the go.{mod,sum} files.
COPY go.mod .
COPY go.sum .

# RUN go mod download
COPY . .

# Build the Go Microservice
RUN CGO_ENABLED=0 go build -o ./out/ioTSensorsOPCUA ./cmd/

# Deployement:
# Start fresh from a smaller image
FROM alpine:latest

COPY --from=build /simulators/ioTSensorsOPCUA/out/ioTSensorsOPCUA /simulators/ioTSensorsOPCUA
COPY --from=build /simulators/ioTSensorsOPCUA/configs/ /configs/

EXPOSE 46010

ENTRYPOINT  ["/simulators/ioTSensorsOPCUA"]