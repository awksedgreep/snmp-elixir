import Config

# Common configuration for all environments
config :logger,
  level: :info

# Include environment-specific configs
import_config "#{config_env()}.exs"
