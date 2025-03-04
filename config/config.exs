import Config

config :snmp_ex,
  # Enable detailed SNMP operation logging
  log_snmp_operations: true,
  # Set logging level
  log_level: :debug,
  # Default request timeout in ms
  timeout: 15000,
  # Defualt non-repeaters for bulkwalk
  non_repeaters: 0,
  # Default max repetitions for bulkwalk
  max_repetitions: 12
