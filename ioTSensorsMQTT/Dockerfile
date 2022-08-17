# Build:
FROM golang as build

# Set the Current Working Directory inside the container
WORKDIR /simulators/iotSensorsMQTT

# Copy files to the container after running `go mod vendor` 
# for faster image building. 
COPY . .

# Build the Go Microservice
RUN CGO_ENABLED=0 go build -o ./out/iotSensorsMQTT ./cmd/

# Deployement:
# Start fresh from a smaller image
FROM alpine:latest

COPY --from=build /simulators/iotSensorsMQTT/out/iotSensorsMQTT /simulators/iotSensorsMQTT
COPY --from=build /simulators/iotSensorsMQTT/configs/ /configs/


ENTRYPOINT  ["/simulators/iotSensorsMQTT"]