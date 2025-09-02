-- kong/plugins/auth-mapper/schema.lua
local typedefs = require("kong.db.schema.typedefs")

return {
  name = "auth-mapper",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          {
            client_id_header = {
              type = "string",
              required = true,
              default = "client_id",
            },
          },
          {
            client_secret_header = {
              type = "string",
              required = true,
              default = "client_secret",
            },
          },
          {
            concat_glue = {
              type = "string",
              required = false,
              default = ":",
            },
          },
          {
            match_mode = {
              type = "string",
              required = false,
              default = "both",
              one_of = { "both", "client_id_only" },
            },
          },
          {
            auth_mappings_json = {
              type = "string",
              required = true,
              referenceable = true,
            },
          },
          {
            cache_enabled = {
              type = "boolean",
              required = false,
              default = true,
            },
          },
          {
            cache_ttl = {
              type = "number",
              required = false,
              default = 300,
              gt = 0,
            },
          },
        },
        entity_checks = {
          { distinct = { "client_id_header", "client_secret_header" } },
        },
      },
    },
  },
}
