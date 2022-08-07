package ports

type sensorPort interface {
	CalculateNextValue()
	DecideFactor() int
}
