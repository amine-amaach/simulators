package ports

import (
	"context"
	"encoding/json"

	"github.com/amine-amaach/simulators/utils"
	"github.com/eclipse/paho.golang/autopaho"
	"go.uber.org/zap"
)

type MqttPort interface {
	Connect(ctx context.Context, logger *zap.SugaredLogger, cfg *utils.Config) *autopaho.ConnectionManager
	Close(cancel context.CancelFunc, logger *zap.SugaredLogger)
	Publish(ctx context.Context, cm *autopaho.ConnectionManager, logger *zap.SugaredLogger, msgPayloads map[string]json.RawMessage, qos byte, retain bool)
}
