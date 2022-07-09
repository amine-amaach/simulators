package ports

import "github.com/amine-amaach/simulators/services/models"

type SimulatorPort interface {
	SetTemperature(payload *models.Generator)
	SetFuelLevel(payload *models.Generator)
	SetPower(payload *models.Generator)
	SetLoad(payload *models.Generator)
}
