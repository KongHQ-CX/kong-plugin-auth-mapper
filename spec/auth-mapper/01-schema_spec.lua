-- spec/auth-mapper/01-schema_spec.lua
local PLUGIN_NAME = "auth-mapper"

local validate
do
  local validate_entity = require("spec.helpers").validate_plugin_config_schema
  local plugin_schema = require("kong.plugins." .. PLUGIN_NAME .. ".schema")

  function validate(data)
    return validate_entity(data, plugin_schema)
  end
end

describe(PLUGIN_NAME .. ": (schema)", function()
  it("accepts a valid minimal configuration", function()
    local ok, err = validate({
      client_id_header = "client_id",
      client_secret_header = "client_secret",
      concat_glue = ":",
      auth_mappings_json = '{"acme123:secret456":{"client_id":"00000000-1111-2222-3333-444444444444","client_secret":"s3cr3t"}}',
    })
    assert.is_nil(err)
    assert.is_truthy(ok)
  end)

  it("accepts configuration with custom headers and glue", function()
    local ok, err = validate({
      client_id_header = "x-id",
      client_secret_header = "x-secret",
      concat_glue = ":",
      auth_mappings_json = '{"left:right":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
    })
    assert.is_nil(err)
    assert.is_truthy(ok)
  end)

  it("does not accept configuration with empty string glue", function()
    local ok, err = validate({
      client_id_header = "client_id",
      client_secret_header = "client_secret",
      concat_glue = "",
      auth_mappings_json = '{"acmesecret":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
    })
    assert.is_nil(ok)
    assert.is_truthy(err)
  end)

  it("uses default values when fields are not provided", function()
    local ok, err = validate({
      auth_mappings_json = '{"default:key":{"client_id":"test-id","client_secret":"test-secret"}}',
    })
    assert.is_nil(err)
    assert.is_truthy(ok)
  end)

  it("rejects identical client_id_header and client_secret_header", function()
    local ok, err = validate({
      client_id_header = "same-header",
      client_secret_header = "same-header",
      auth_mappings_json = '{"k":{"client_id":"a","client_secret":"b"}}',
    })

    assert.is_falsy(ok)
    assert.is_not_nil(err)
    assert.is_not_nil(err.config)
    assert.is_not_nil(err.config["@entity"])
  end)

  it("rejects empty auth_mappings_json string", function()
    local ok, err = validate({
      client_id_header = "id",
      client_secret_header = "secret",
      auth_mappings_json = "", -- Empty string should fail
    })
    assert.is_falsy(ok)
    assert.is_not_nil(err)
  end)

  it("accepts empty JSON object (validation happens at runtime)", function()
    -- Schema validation only checks if it's a string, not if JSON is valid
    local ok, err = validate({
      client_id_header = "id",
      client_secret_header = "secret",
      auth_mappings_json = "{}", -- Empty JSON object is valid string
    })
    assert.is_truthy(ok) -- Schema validation passes
    assert.is_nil(err)
  end)

  it("accepts any JSON string (validation happens at runtime)", function()
    -- Kong schema validation only validates it's a non-empty string
    -- JSON parsing and structure validation happens in the handler
    local ok, err = validate({
      client_id_header = "id",
      client_secret_header = "secret",
      auth_mappings_json = '{"id:secret":{"client_secret":"only-secret"}}', -- Missing client_id
    })
    assert.is_truthy(ok) -- Schema validation passes
    assert.is_nil(err)
  end)

  it("accepts malformed JSON (validation happens at runtime)", function()
    -- Schema only validates it's a string - JSON parsing happens in handler
    local ok, err = validate({
      client_id_header = "id",
      client_secret_header = "secret",
      auth_mappings_json = '{"invalid": json}', -- Malformed JSON
    })
    assert.is_truthy(ok) -- Schema validation passes
    assert.is_nil(err)
  end)

  it("rejects when auth_mappings_json is missing", function()
    local ok, err = validate({
      client_id_header = "id",
      client_secret_header = "secret",
      -- auth_mappings_json is required
    })
    assert.is_falsy(ok)
    assert.is_not_nil(err)
  end)

  it("rejects when required top level fields are missing", function()
    local ok, err = validate({
      client_secret_header = "secret",
      auth_mappings_json = '{"test":{"client_id":"a", "client_secret":"b"}}',
    })
    -- client_id_header should use default, so this should pass
    assert.is_truthy(ok)
    assert.is_nil(err)

    ok, err = validate({
      client_id_header = "id",
      auth_mappings_json = '{"test":{"client_id":"a", "client_secret":"b"}}',
    })
    -- client_secret_header should use default, so this should pass
    assert.is_truthy(ok)
    assert.is_nil(err)

    ok, err = validate({
      client_id_header = "id",
      client_secret_header = "secret",
    })
    -- auth_mappings_json is required
    assert.is_falsy(ok)
    assert.is_not_nil(err)
  end)

  it("accepts vault references in auth_mappings_json", function()
    local ok, err = validate({
      client_id_header = "client_id",
      client_secret_header = "client_secret",
      auth_mappings_json = "{vault://env/AUTH_MAPPINGS}", -- Vault reference
    })
    assert.is_truthy(ok)
    assert.is_nil(err)
  end)
end)
