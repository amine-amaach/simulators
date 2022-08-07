package services

import (
	"math/rand"
	"time"

	"github.com/amine-amaach/simulators/pgmqtt/services/models"
)

type SimService struct{}

func NewSimService() *SimService {
	return &SimService{}
}

// setTemperature implements the simPort by setting the pg temperature.
func (svc *SimService) SetTemperature(pg *models.Generator) {

	pg.Temperature.ItemOldValue = pg.Temperature.ItemValue
	pg.Temperature.PreviousTimestamp, pg.Temperature.ChangedTimestamp = pg.Temperature.ChangedTimestamp, time.Now().Format(time.RFC3339)

	// Assert load data type to int.
	load, ok := pg.Load.ItemValue.(int)
	if !ok {
		load = int(load)
	}

	// Temperature is set based on the pg load value.
	switch {
	case load >= 75:
		pg.Temperature.ItemValue = float32(210. + rand.Float32() + 89.) // between 210 and 300 exclusive
	case load >= 50:
		pg.Temperature.ItemValue = float32(200. + rand.Float32() + 9.) // between 200 and 210 exclusive
	case load >= 25:
		pg.Temperature.ItemValue = float32(190. + rand.Float32() + 9.) // between 190 and 200 exclusive
	case load == 0:
		pg.Temperature.ItemValue = float32(160.)
	default:
		pg.Temperature.ItemValue = float32(170. + rand.Float32() + 19.) // between 170 and 190 exclusive
	}
}

// SetFuelLevel implements the simPort by setting the pg Fuel level.
func (svc *SimService) SetFuelLevel(pg *models.Generator) {

	pg.CurrentFuel.ItemOldValue = pg.CurrentFuel.ItemValue
	pg.CurrentFuel.PreviousTimestamp, pg.CurrentFuel.ChangedTimestamp = pg.CurrentFuel.ChangedTimestamp, time.Now().Format(time.RFC3339)

	// Assert load data type to int.
	load, ok := pg.Load.ItemValue.(int)
	if !ok {
		load = int(load)
	}

	// Fuel level is set based on the pg load, base fuel and used fuel values.
	switch {
	case load >= 75:
		pg.Fuel_used.ItemValue = float32(90. + rand.Float32() + 39.) // between 90 and 130 exclusive
	case load >= 50:
		pg.Fuel_used.ItemValue = float32(75. + rand.Float32() + 14.) // between 75 and 90 exclusive
	case load >= 25:
		pg.Fuel_used.ItemValue = float32(50. + rand.Float32() + 24.) // between 50 and 75 exclusive
	case load == 0:
		pg.Fuel_used.ItemValue = float32(0.)
	default:
		pg.Fuel_used.ItemValue = float32(10 + rand.Float32() + 39.) // between 10 and 50 exclusive
	}

	pg.CurrentFuel.ItemValue = pg.Base_fuel.ItemValue.(float32) - pg.Fuel_used.ItemValue.(float32)

	if pg.CurrentFuel.ItemValue.(float32) <= 0. {
		pg.CurrentFuel.ItemValue = pg.CurrentFuel.ItemValue.(float32) + float32(500.+rand.Float32()+499.)
	} else {
		pg.CurrentFuel.ItemValue = pg.CurrentFuel.ItemValue.(float32) - pg.Fuel_used.ItemValue.(float32)
	}
}

// SetPower implements the simPort by setting the pg power.
func (svc *SimService) SetPower(pg *models.Generator) {

	pg.Power.ItemOldValue = pg.Power.ItemValue
	pg.Power.PreviousTimestamp, pg.Power.ChangedTimestamp = pg.Power.ChangedTimestamp, time.Now().Format(time.RFC3339)

	// Assert load data type to int.
	load, ok := pg.Load.ItemValue.(int)
	if !ok {
		load = int(load)
	}

	// Power is set based on the pg load value.
	switch {
	case load >= 75:
		pg.Power.ItemValue = float32(2000. + rand.Float32() + 599.) // between 2000 and 2600 exclusive
	case load >= 50:
		pg.Power.ItemValue = float32(1100. + rand.Float32() + 899) // between 1100 and 900 exclusive
	case load >= 25:
		pg.Power.ItemValue = float32(500. + rand.Float32() + 599) // between 500 and 1100 exclusive
	case load == 0:
		pg.Power.ItemValue = float32(0.)
	default:
		pg.Power.ItemValue = float32(100. + rand.Float32() + 399) // between 100 and 500 exclusive
	}
}

// SetPower implements the simPort by setting the pg load.
// TODO : this shouldn't be random.
func (svc *SimService) SetLoad(pg *models.Generator) {

	pg.Load.ItemOldValue = pg.Load.ItemValue
	pg.Load.PreviousTimestamp, pg.Load.ChangedTimestamp = pg.Load.ChangedTimestamp, time.Now().Format(time.RFC3339)
	pg.Load.ItemValue = rand.Intn(100)
}

// SetPower implements the simPort by updating the pg used fuel.
func (svc *SimService) SetFuelUsed(pg *models.Generator) {
	pg.Fuel_used.ItemOldValue = pg.Fuel_used.ItemValue
	pg.Fuel_used.PreviousTimestamp, pg.Fuel_used.ChangedTimestamp = pg.Fuel_used.ChangedTimestamp, time.Now().Format(time.RFC3339)
}

// Support functions :
