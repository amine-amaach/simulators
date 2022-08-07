package ports

import "github.com/amine-amaach/simulators/pgmqtt/services/models"

type SimulatorPort interface {
	SetTemperature(payload *models.Generator)
	SetFuelLevel(payload *models.Generator)
	SetFuelUsed(payload *models.Generator)
	SetPower(payload *models.Generator)
	SetLoad(payload *models.Generator)
}
