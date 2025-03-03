import Config

# Test environment configuration
config :logger,
  level: :warning

config :snmp_ex,
  log_snmp_operations: true,  # Enable logging in test
  # Use a different port for tests to avoid conflicts
  snmp_port: 5000,
  # Integration tests are disabled by default
  run_integration_tests: false
