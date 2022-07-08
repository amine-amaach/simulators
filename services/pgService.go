package services

import (
	"context"
	"encoding/json"

	"github.com/amine-amaach/simulators/services/models"
)

// PgmqttService describes a service that generates power-generator data to
// be published to an MQTT Broker.
type PgmqttService interface {

	// BuildPowerGenerators returns a slice of power-generators of length nb.
	BuildPowerGenerators(ctx context.Context, nb int) ([]models.Generator, error)

	// MakeMessagePayload generates random data for a given power-generator and
	// returns a map contains its topics with corresponding message payloads.
	BuildMessagePayloads(ctx context.Context, pg models.Generator) (map[string]json.RawMessage, error)
}
