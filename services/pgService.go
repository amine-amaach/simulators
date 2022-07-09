package services

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"

	"github.com/amine-amaach/simulators/services/models"
	"github.com/amine-amaach/simulators/utils"
	"github.com/bxcodec/faker/v3"
	"go.uber.org/zap"
)

type pgService struct{}

func NewService(pGenerators []models.Generator, cfg *utils.Config, pgNumber int) *pgService {
	pgSvc := pgService{}
	pgSvc.BuildPowerGenerators(pGenerators, cfg, pgNumber)
	return &pgSvc
}

// MakeMessagePayload generates random data for a given power-generator and
// returns a map contains its topics with corresponding message payloads.
func (svc *pgService) BuildMessagePayloads(sim *simService, pg *models.Generator, logger *zap.SugaredLogger) map[string]json.RawMessage {

	type pgPayload struct {
		Name string
		Lat  float32
		Lon  float32
	}

	msgPayloads := make(map[string]json.RawMessage, 6)

	// For encoding pg general message payload
	if jsonBytes, err := json.Marshal(pgPayload{Name: pg.GeneratorID, Lat: pg.Lat, Lon: pg.Lon}); err != nil {
		logger.Errorf("Couldn't marshal message payload ❌ %v", err)
	} else {
		msgPayloads[pg.GeneratorTopic] = jsonBytes
	}

	// For each tag of the generator encode its message payload
	// As we don't have a lot of tags, it is fine to do it by hand.
	// In case we have a lot of tags we should convert the pg struct
	// to an iterable type.

	marshalTemperature(sim, pg, msgPayloads, logger)
	marshalLoad(sim, pg, msgPayloads, logger)
	marshalPower(sim, pg, msgPayloads, logger)
	marshalBaseFuel(sim, pg, msgPayloads, logger)
	marshalCurrentFuel(sim, pg, msgPayloads, logger)
	marshalFuelUsed(sim, pg, msgPayloads, logger)

	// In case there is an error, we return the map with the encoded
	// payloads. The map could be empty in case all the encoding failed.
	return msgPayloads

}

// BuildPowerGenerators returns a slice of power-generators of length nb.
func (svc *pgService) BuildPowerGenerators(pGenerators []models.Generator, cfg *utils.Config, nb int) {
	for i := 0; i < nb; i++ {
		svc.initPG(&pGenerators[i], i+1)
		svc.buildPublishTopicString(&pGenerators[i], cfg)
	}
}

// initPG() initializes a power-generator instance.
func (svc *pgService) initPG(pg *models.Generator, pgNumber int) {

	pg.GeneratorID = "Generator_" + fmt.Sprint(pgNumber)
	pg.Lat = float32(faker.Latitude())
	pg.Lon = float32(faker.Latitude())

	pg.Load = models.Message{
		ItemValue:    0,
		ItemName:     "Load",
		ItemId:       fmt.Sprint(faker.UnixTime()),
		ItemDataType: "INT",
	}

	pg.Temperature = models.Message{
		ItemValue:    float32(0.),
		ItemName:     "Temperature",
		ItemId:       fmt.Sprint(faker.UnixTime()),
		ItemDataType: "FLOAT32",
	}

	pg.Power = models.Message{
		ItemValue:    float32(0.),
		ItemName:     "Power",
		ItemId:       fmt.Sprint(faker.UnixTime()),
		ItemDataType: "FLOAT32",
	}

	pg.CurrentFuel = models.Message{
		ItemValue:    float32(0.),
		ItemName:     "Fuel",
		ItemId:       fmt.Sprint(faker.UnixTime()),
		ItemDataType: "FLOAT32",
	}

	pg.Base_fuel = models.Message{
		ItemValue:    float32(900. + rand.Float32() + 9.),
		ItemName:     "BaseFuel",
		ItemId:       fmt.Sprint(faker.UnixTime()),
		ItemDataType: "FLOAT32",
	}

	pg.Fuel_used = models.Message{
		ItemValue:    float32(0.),
		ItemName:     "FuelUsed",
		ItemId:       fmt.Sprint(faker.UnixTime()),
		ItemDataType: "FLOAT32",
	}
}

// buildPublishTopicString() builds a power-generator publish topics.
func (svc *pgService) buildPublishTopicString(g *models.Generator, cfg *utils.Config) {
	rootTopic := strings.Join([]string{cfg.Site, cfg.Area, "Power-Generators"}, "/")
	g.GeneratorTopic = strings.Join([]string{rootTopic, g.GeneratorID}, "/")
	g.Load.ItemTopic = strings.Join([]string{rootTopic, g.GeneratorID, g.Load.ItemName}, "/")
	g.Temperature.ItemTopic = strings.Join([]string{rootTopic, g.GeneratorID, g.Temperature.ItemName}, "/")
	g.Power.ItemTopic = strings.Join([]string{rootTopic, g.GeneratorID, g.Power.ItemName}, "/")
	g.CurrentFuel.ItemTopic = strings.Join([]string{rootTopic, g.GeneratorID, g.CurrentFuel.ItemName}, "/")
	g.Base_fuel.ItemTopic = strings.Join([]string{rootTopic, g.GeneratorID, g.Base_fuel.ItemName}, "/")
	g.Fuel_used.ItemTopic = strings.Join([]string{rootTopic, g.GeneratorID, g.Fuel_used.ItemName}, "/")
}

// marshXXX() used to return the JSON encoding of a message payload.

func marshalTemperature(sim *simService, pg *models.Generator, msgPayloads map[string]json.RawMessage, logger *zap.SugaredLogger) {
	sim.SetTemperature(pg)
	if jsonBytes, err := json.Marshal(pg.Temperature); err != nil {
		logger.Errorf("Couldn't marshal message payload ❌ %v", err)
	} else {
		msgPayloads[pg.Temperature.ItemTopic] = jsonBytes
	}
}

func marshalPower(sim *simService, pg *models.Generator, msgPayloads map[string]json.RawMessage, logger *zap.SugaredLogger) {
	sim.SetPower(pg)
	if jsonBytes, err := json.Marshal(pg.Power); err != nil {
		logger.Errorf("Couldn't marshal message payload ❌ %v", err)
	} else {
		msgPayloads[pg.Power.ItemTopic] = jsonBytes
	}
}

func marshalLoad(sim *simService, pg *models.Generator, msgPayloads map[string]json.RawMessage, logger *zap.SugaredLogger) {
	sim.SetLoad(pg)
	if jsonBytes, err := json.Marshal(pg.Load); err != nil {
		logger.Errorf("Couldn't marshal message payload ❌ %v", err)
	} else {
		msgPayloads[pg.Load.ItemTopic] = jsonBytes
	}
}

func marshalCurrentFuel(sim *simService, pg *models.Generator, msgPayloads map[string]json.RawMessage, logger *zap.SugaredLogger) {
	sim.SetFuelLevel(pg)
	if jsonBytes, err := json.Marshal(pg.CurrentFuel); err != nil {
		logger.Errorf("Couldn't marshal message payload ❌ %v", err)
	} else {
		msgPayloads[pg.CurrentFuel.ItemTopic] = jsonBytes
	}
}

func marshalFuelUsed(sim *simService, pg *models.Generator, msgPayloads map[string]json.RawMessage, logger *zap.SugaredLogger) {
	// Fuel used is updated when calling SetFuelLevel()
	if jsonBytes, err := json.Marshal(pg.Fuel_used); err != nil {
		logger.Errorf("Couldn't marshal message payload ❌ %v", err)
	} else {
		msgPayloads[pg.Fuel_used.ItemTopic] = jsonBytes
	}
}

func marshalBaseFuel(sim *simService, pg *models.Generator, msgPayloads map[string]json.RawMessage, logger *zap.SugaredLogger) {
	// Base fuel is set only once when creating the pg instance.
	if jsonBytes, err := json.Marshal(pg.Base_fuel); err != nil {
		logger.Errorf("Couldn't marshal message payload ❌ %v", err)
	} else {
		msgPayloads[pg.Base_fuel.ItemTopic] = jsonBytes
	}
}
