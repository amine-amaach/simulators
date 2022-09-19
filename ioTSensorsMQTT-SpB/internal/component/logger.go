package component

type Logger struct {
	Level            string `mapstructure:"level"`
	Format           string `mapstructure:"format"`
	DisableTimestamp bool `mapstructure:"disable_timestamp"`
}
