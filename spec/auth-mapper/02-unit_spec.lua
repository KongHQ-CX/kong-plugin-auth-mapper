-- spec/auth-mapper/02-unit_spec.lua
local PLUGIN_NAME = "auth-mapper"
describe(PLUGIN_NAME .. ": (unit)", function()
  local plugin
  local header_name, header_value

  setup(function()
    _G.kong = {
      log = {
        debug = function(...)
          -- print("KONG DEBUG:", ...)
        end,
        info = function(...)
          -- print("KONG INFO:", ...)
        end,
        warn = function(...)
          -- print("KONG WARN:", ...)
        end,
        error = function(...)
          -- print("KONG ERROR:", ...)
        end,
      },
      request = {
        get_header = function(name)
          if name == "client_id" then
            return "acme"
          elseif name == "client_id_multi" then
            return { "first-id", "second-id" }
          elseif name == "client_secret" then
            return "s3cr3t"
          elseif name == "client_secret_multi" then
            return { "first-secret", "second-secret" }
          elseif name == "empty_header" then
            return ""
          elseif name == "whitespace_header" then
            return "   \t\n   "
          elseif name == "client_id_trim" then
            return "  acme  "
          elseif name == "client_secret_trim" then
            return "\ts3cr3t\n"
          else
            return nil
          end
        end,
        set_header = function(name, val)
          header_name = name
          header_value = val
        end,
      },
      service = {
        request = {
          set_header = function(name, val)
            header_name = name
            header_value = val
          end,
        },
      },
    }
    -- load the plugin code
    plugin = require("kong.plugins." .. PLUGIN_NAME .. ".handler")
  end)

  before_each(function()
    -- clear the upvalues to prevent test results mixing between tests
    header_name = nil
    header_value = nil
  end)

  describe("both mode (default)", function()
    it("injects mapped Basic Authorization on mapping hit", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = '{"acme:s3cr3t":{"client_id":"entra-id-1","client_secret":"entra-secret-1"}}',
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("entra-id-1:entra-secret-1")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)
    end)

    it("falls back to original credentials when no mapping found", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = '{"different:credentials":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("acme:s3cr3t")

      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)
    end)

    it("uses default both mode when match_mode not specified", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = ":",
        -- match_mode not specified - should default to "both"
        auth_mappings_json = '{"acme:s3cr3t":{"client_id":"entra-id-1","client_secret":"entra-secret-1"}}',
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("entra-id-1:entra-secret-1")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)
    end)

    it("skips processing when client_id header is missing", function()
      local conf = {
        client_id_header = "client_id_miss",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = '{"acme:s3cr3t":{"client_id":"entra-id-1","client_secret":"entra-secret-1"}}',
      }

      plugin:access(conf)

      assert.is_nil(header_name)
      assert.is_nil(header_value)
    end)

    it("skips processing when client_secret header is missing", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "missing_header",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = '{"acme:s3cr3t":{"client_id":"entra-id-1","client_secret":"entra-secret-1"}}',
      }

      plugin:access(conf)

      assert.is_nil(header_name)
      assert.is_nil(header_value)
    end)
  end)

  describe("client_id_only mode", function()
    it("injects mapped Basic Authorization on client_id mapping hit", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        match_mode = "client_id_only",
        auth_mappings_json = '{"acme":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("mapped-id:mapped-secret")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)
    end)

    it("falls back to original credentials when no client_id mapping found", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        match_mode = "client_id_only",
        auth_mappings_json = '{"different-client":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("acme:s3cr3t")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)
    end)

    it("skips processing when client_id header is missing", function()
      local conf = {
        client_id_header = "missing_client_id",
        client_secret_header = "client_secret",
        match_mode = "client_id_only",
        auth_mappings_json = '{"acme":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
      }

      plugin:access(conf)

      assert.is_nil(header_name)
      assert.is_nil(header_value)
    end)

    it("skips processing when client_secret header is missing (needed for Basic auth)", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "missing_secret",
        match_mode = "client_id_only",
        auth_mappings_json = '{"acme":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
      }

      plugin:access(conf)

      -- Should skip because both headers are required regardless of mode
      assert.is_nil(header_name)
      assert.is_nil(header_value)
    end)

    it("works with different client_ids mapping to different credentials", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        match_mode = "client_id_only",
        auth_mappings_json = '{"acme":{"client_id":"acme-mapped","client_secret":"acme-secret"},"other":{"client_id":"other-mapped","client_secret":"other-secret"}}',
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("acme-mapped:acme-secret")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)
    end)

    it("ignores concat_glue in client_id_only mode", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = "|", -- Should be ignored in client_id_only mode
        match_mode = "client_id_only",
        auth_mappings_json = '{"acme":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("mapped-id:mapped-secret")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)
    end)
  end)

  describe("common behavior across modes", function()
    it("skips processing when both headers are missing", function()
      local conf = {
        client_id_header = "missing_id_header",
        client_secret_header = "missing_secret_header",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = '{"acme:s3cr3t":{"client_id":"entra-id-1","client_secret":"entra-secret-1"}}',
      }

      plugin:access(conf)

      assert.is_nil(header_name)
      assert.is_nil(header_value)
    end)

    it("handles empty string headers as missing", function()
      local conf = {
        client_id_header = "empty_header",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = '{"acme:s3cr3t":{"client_id":"entra-id-1","client_secret":"entra-secret-1"}}',
      }

      plugin:access(conf)

      assert.is_nil(header_name)
      assert.is_nil(header_value)
    end)

    it("handles whitespace-only headers as missing", function()
      local conf = {
        client_id_header = "whitespace_header",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = '{"acme:s3cr3t":{"client_id":"entra-id-1","client_secret":"entra-secret-1"}}',
      }

      plugin:access(conf)

      assert.is_nil(header_name)
      assert.is_nil(header_value)
    end)

    it("uses first value when client_id header has multiple values", function()
      local conf = {
        client_id_header = "client_id_multi",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = '{"first-id:s3cr3t":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("mapped-id:mapped-secret")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)
    end)

    it("uses first value when client_secret header has multiple values", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret_multi",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = '{"acme:first-secret":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("mapped-id:mapped-secret")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)
    end)

    it("uses default ':' glue when concat_glue is nil", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = nil, -- Should default to ":"
        match_mode = "both",
        auth_mappings_json = '{"acme:s3cr3t":{"client_id":"entra-id-1","client_secret":"entra-secret-1"}}',
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("entra-id-1:entra-secret-1")

      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)
    end)

    it("uses empty string glue when concat_glue is empty", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = "", -- Empty string glue
        match_mode = "both",
        auth_mappings_json = '{"acmes3cr3t":{"client_id":"entra-id-1","client_secret":"entra-secret-1"}}',
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("entra-id-1:entra-secret-1")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)
    end)

    it("uses custom glue character for lookup key", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = "|", -- Custom glue character
        match_mode = "both",
        auth_mappings_json = '{"acme|s3cr3t":{"client_id":"entra-id-1","client_secret":"entra-secret-1"}}',
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("entra-id-1:entra-secret-1")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)
    end)

    it("uses fallback injection when mapped client_id is missing", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = '{"acme:s3cr3t":{"client_secret":"entra-secret-1"}}', -- Missing client_id
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("acme:s3cr3t")
      assert.equal(header_name, "Authorization")
      assert.equal(header_value, expected)
    end)

    it("uses fallback injection when mapped client_secret is missing", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = '{"acme:s3cr3t":{"client_id":"entra-id-1"}}', -- Missing client_secret
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("acme:s3cr3t")
      assert.equal(header_name, "Authorization")
      assert.equal(header_value, expected)
    end)

    it("uses fallback injection when mapped client_id is null", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = '{"acme:s3cr3t":{"client_id":null,"client_secret":"entra-secret-1"}}', -- Explicit null
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("acme:s3cr3t")
      assert.equal(header_name, "Authorization")
      assert.equal(header_value, expected)
    end)

    it("uses fallback injection when mapped client_secret is null", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = '{"acme:s3cr3t":{"client_id":"entra-id-1","client_secret":null}}', -- Explicit null
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("acme:s3cr3t")
      assert.equal(header_name, "Authorization")
      assert.equal(header_value, expected)
    end)

    it("trims whitespace from header values before processing", function()
      local conf = {
        client_id_header = "client_id_trim",
        client_secret_header = "client_secret_trim",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = '{"acme:s3cr3t":{"client_id":"entra-id-1","client_secret":"entra-secret-1"}}',
      }

      plugin:access(conf)

      local expected = "Basic " .. ngx.encode_base64("entra-id-1:entra-secret-1")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)
    end)

    it("handles malformed JSON gracefully", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = '{"invalid": json}', -- Malformed JSON
      }

      plugin:access(conf)

      -- Should fallback to original credentials when JSON parsing fails
      local expected = "Basic " .. ngx.encode_base64("acme:s3cr3t")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)
    end)

    it("handles empty JSON object", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        auth_mappings_json = "{}", -- Empty JSON object
      }

      plugin:access(conf)

      -- Should fallback to original credentials when no mapping found
      local expected = "Basic " .. ngx.encode_base64("acme:s3cr3t")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)
    end)
  end)
end)
