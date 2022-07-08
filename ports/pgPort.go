package ports

import (
	"encoding/json"

	"github.com/amine-amaach/simulators/pgmqtt/models"
)

// PgPort describes a service that generates power-generator data to
// be published to an MQTT Broker.
type PgPort interface {

	// BuildPowerGenerators returns a slice of power-generators of length nb.
	BuildPowerGenerators(nb int) []models.Generator

	// MakeMessagePayload generates random data for a given power-generator and
	// returns a map contains its topics with corresponding message payloads.
	MakeMessagePayloads(pg models.Generator) (map[string]json.RawMessage, error)
}
