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
func (svc *pgService) BuildPGMessagePayloads(sim *SimService, pg *models.Generator, logger *zap.SugaredLogger) map[string]json.RawMessage {

	type pgPayload struct {
		Name     string
		Lat      float32
		Lon      float32
		BaseFuel float32
	}

	msgPayloads := make(map[string]json.RawMessage, 1)

	// Add power-generator general infos that gets published once.
	jsonBytes, err := json.Marshal(pgPayload{Name: pg.GeneratorID, Lat: pg.Lat, Lon: pg.Lon, BaseFuel: pg.Base_fuel.ItemValue.(float32)})
	if err != nil {
		logger.Errorf("Couldn't marshal message payload ❌ %v", err)
	} else {
		msgPayloads[pg.GeneratorTopic] = jsonBytes
	}
	
	return msgPayloads
}

// Update used to update the power-generator tags message payload and republish it.
func (svc *pgService) Update(sim *SimService, pg *models.Generator, logger *zap.SugaredLogger) map[string]json.RawMessage {
	msgPayloads := make(map[string]json.RawMessage, 5)

	// For each tag of the generator encode its message payload
	// As we don't have a lot of tags, it is fine to do it by hand.
	// In case we have a lot of tags we should convert the pg struct
	// to an iterable type.

	marshalLoad(sim, pg, msgPayloads, logger)
	marshalTemperature(sim, pg, msgPayloads, logger)
	marshalPower(sim, pg, msgPayloads, logger)
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

	baseFuel := float32(900. + rand.Float32() + 9.)

	pg.GeneratorID = "Generator_" + fmt.Sprint(pgNumber)
	pg.Lat = float32(faker.Latitude())
	pg.Lon = float32(faker.Latitude())

	pg.Load = models.NewMessage(0, "Load", fmt.Sprint(faker.UnixTime()), "INT")

	pg.Temperature = models.NewMessage(float32(0.), "Temperature", fmt.Sprint(faker.UnixTime()), "FLOAT32")

	pg.Power = models.NewMessage(float32(0.), "Power", fmt.Sprint(faker.UnixTime()), "FLOAT32")

	pg.CurrentFuel = models.NewMessage(float32(0.), "Fuel", fmt.Sprint(faker.UnixTime()), "FLOAT32")

	pg.Fuel_used = models.NewMessage(float32(0.), "FuelUsed", fmt.Sprint(faker.UnixTime()), "FLOAT32")

	pg.Base_fuel = models.NewMessage(baseFuel, "BaseFuel", fmt.Sprint(faker.UnixTime()), "FLOAT32")
	{
		pg.Base_fuel.ItemOldValue = baseFuel

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

func marshalTemperature(sim *SimService, pg *models.Generator, msgPayloads map[string]json.RawMessage, logger *zap.SugaredLogger) {
	sim.SetTemperature(pg)
	if jsonBytes, err := json.Marshal(pg.Temperature); err != nil {
		logger.Errorf("Couldn't marshal message payload ❌ %v", err)
	} else {
		msgPayloads[pg.Temperature.ItemTopic] = jsonBytes
	}
}

func marshalPower(sim *SimService, pg *models.Generator, msgPayloads map[string]json.RawMessage, logger *zap.SugaredLogger) {
	sim.SetPower(pg)
	if jsonBytes, err := json.Marshal(pg.Power); err != nil {
		logger.Errorf("Couldn't marshal message payload ❌ %v", err)
	} else {
		msgPayloads[pg.Power.ItemTopic] = jsonBytes
	}
}

func marshalLoad(sim *SimService, pg *models.Generator, msgPayloads map[string]json.RawMessage, logger *zap.SugaredLogger) {
	sim.SetLoad(pg)
	if jsonBytes, err := json.Marshal(pg.Load); err != nil {
		logger.Errorf("Couldn't marshal message payload ❌ %v", err)
	} else {
		msgPayloads[pg.Load.ItemTopic] = jsonBytes
	}
}

func marshalCurrentFuel(sim *SimService, pg *models.Generator, msgPayloads map[string]json.RawMessage, logger *zap.SugaredLogger) {
	sim.SetFuelLevel(pg)
	if jsonBytes, err := json.Marshal(pg.CurrentFuel); err != nil {
		logger.Errorf("Couldn't marshal message payload ❌ %v", err)
	} else {
		msgPayloads[pg.CurrentFuel.ItemTopic] = jsonBytes
	}
}

func marshalFuelUsed(sim *SimService, pg *models.Generator, msgPayloads map[string]json.RawMessage, logger *zap.SugaredLogger) {
	// Fuel used is updated when calling SetFuelLevel()
	// SetFuelUsed updates old values.
	sim.SetFuelUsed(pg)
	if jsonBytes, err := json.Marshal(pg.Fuel_used); err != nil {
		logger.Errorf("Couldn't marshal message payload ❌ %v", err)
	} else {
		msgPayloads[pg.Fuel_used.ItemTopic] = jsonBytes
	}
}
