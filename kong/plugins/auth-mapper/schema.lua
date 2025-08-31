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
            auth_mappings_json = {
              type = "string",
              required = true,
              referenceable = true, -- The entire JSON mapping can be from vault!
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
              default = 300, -- 5 minutes
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
