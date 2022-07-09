package ports

import (
	"encoding/json"

	"github.com/amine-amaach/simulators/services"
	"github.com/amine-amaach/simulators/services/models"
	"github.com/amine-amaach/simulators/utils"
	"go.uber.org/zap"
)

// PgPort describes a service that generates power-generator data to
// be published to an MQTT Broker.
type PgPort interface {

	// BuildPowerGenerators returns a slice of power-generators of length nb.
	BuildPowerGenerators(pGenerators []models.Generator, cfg *utils.Config, nb int)

	// BuildPGMessagePayloads returns a map contains the power-generator general info
	// (identification infos) with the corresponding topic.
	BuildPGMessagePayloads(sim *services.SimService, pg *models.Generator, logger *zap.SugaredLogger) map[string]json.RawMessage

	// Update used to generate/update the power-generator tags message payload.
	// it returns a map contains the pg topics with corresponding message payloads.
	Update(sim *services.SimService, pg *models.Generator, logger *zap.SugaredLogger) map[string]json.RawMessage
}
