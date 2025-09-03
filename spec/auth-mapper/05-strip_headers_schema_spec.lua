-- spec/auth-mapper/05-strip_headers_schema_spec.lua
local PLUGIN_NAME = "auth-mapper"

local validate
do
  local validate_entity = require("spec.helpers").validate_plugin_config_schema
  local plugin_schema = require("kong.plugins." .. PLUGIN_NAME .. ".schema")

  function validate(data)
    return validate_entity(data, plugin_schema)
  end
end

describe(PLUGIN_NAME .. ": strip headers schema", function()
  it("accepts configuration with strip_original_headers = true", function()
    local ok, err = validate({
      client_id_header = "client_id",
      client_secret_header = "client_secret",
      concat_glue = ":",
      match_mode = "both",
      strip_original_headers = true,
      auth_mappings_json = '{"test:key":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
    })
    assert.is_nil(err)
    assert.is_truthy(ok)
  end)

  it("accepts configuration with strip_original_headers = false", function()
    local ok, err = validate({
      client_id_header = "client_id",
      client_secret_header = "client_secret",
      concat_glue = ":",
      match_mode = "both",
      strip_original_headers = false,
      auth_mappings_json = '{"test:key":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
    })
    assert.is_nil(err)
    assert.is_truthy(ok)
  end)

  it("uses default false when strip_original_headers is not specified", function()
    local ok, err = validate({
      client_id_header = "client_id",
      client_secret_header = "client_secret",
      concat_glue = ":",
      match_mode = "both",
      -- strip_original_headers not specified - should default to false
      auth_mappings_json = '{"test:key":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
    })
    assert.is_nil(err)
    assert.is_truthy(ok)
    local config = ok.config
    -- Check that the default value is applied
    assert.equal(false, config.strip_original_headers)
  end)

  it("accepts strip_original_headers with client_id_only mode", function()
    local ok, err = validate({
      client_id_header = "client_id",
      client_secret_header = "client_secret",
      match_mode = "client_id_only",
      strip_original_headers = true,
      auth_mappings_json = '{"test-app":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
    })
    assert.is_nil(err)
    assert.is_truthy(ok)
  end)

  it("accepts strip_original_headers with custom headers", function()
    local ok, err = validate({
      client_id_header = "x-app-id",
      client_secret_header = "x-app-secret",
      concat_glue = ":",
      match_mode = "both",
      strip_original_headers = true,
      auth_mappings_json = '{"custom:app":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
    })
    assert.is_nil(err)
    assert.is_truthy(ok)
  end)

  it("accepts strip_original_headers with caching enabled", function()
    local ok, err = validate({
      client_id_header = "client_id",
      client_secret_header = "client_secret",
      concat_glue = ":",
      match_mode = "both",
      strip_original_headers = true,
      cache_enabled = true,
      cache_ttl = 600,
      auth_mappings_json = '{"test:key":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
    })
    assert.is_nil(err)
    assert.is_truthy(ok)
  end)

  it("accepts strip_original_headers with caching disabled", function()
    local ok, err = validate({
      client_id_header = "client_id",
      client_secret_header = "client_secret",
      concat_glue = ":",
      match_mode = "both",
      strip_original_headers = true,
      cache_enabled = false,
      auth_mappings_json = '{"test:key":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
    })
    assert.is_nil(err)
    assert.is_truthy(ok)
  end)

  it("accepts strip_original_headers with vault references", function()
    local ok, err = validate({
      client_id_header = "client_id",
      client_secret_header = "client_secret",
      concat_glue = ":",
      match_mode = "both",
      strip_original_headers = true,
      auth_mappings_json = "{vault://env/auth-mappings}",
    })
    assert.is_nil(err)
    assert.is_truthy(ok)
  end)

  it("rejects invalid strip_original_headers type", function()
    local ok, err = validate({
      client_id_header = "client_id",
      client_secret_header = "client_secret",
      concat_glue = ":",
      match_mode = "both",
      strip_original_headers = "invalid", -- Should be boolean
      auth_mappings_json = '{"test:key":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
    })
    assert.is_falsy(ok)
    assert.is_not_nil(err)
  end)

  it("rejects strip_original_headers with number value", function()
    local ok, err = validate({
      client_id_header = "client_id",
      client_secret_header = "client_secret",
      concat_glue = ":",
      match_mode = "both",
      strip_original_headers = 1, -- Should be boolean, not number
      auth_mappings_json = '{"test:key":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
    })
    assert.is_falsy(ok)
    assert.is_not_nil(err)
  end)

  it("works with all configuration options together", function()
    local ok, err = validate({
      client_id_header = "x-client-id",
      client_secret_header = "x-client-secret",
      concat_glue = "|",
      match_mode = "client_id_only",
      strip_original_headers = true,
      cache_enabled = true,
      cache_ttl = 1800,
      auth_mappings_json = '{"app1":{"client_id":"mapped-app1","client_secret":"mapped-secret1"}}',
    })
    assert.is_nil(err)
    assert.is_truthy(ok)
    local config = ok.config

    -- Verify all values are set correctly
    assert.equal("x-client-id", config.client_id_header)
    assert.equal("x-client-secret", config.client_secret_header)
    assert.equal("|", config.concat_glue)
    assert.equal("client_id_only", config.match_mode)
    assert.equal(true, config.strip_original_headers)
    assert.equal(true, config.cache_enabled)
    assert.equal(1800, config.cache_ttl)
  end)
end)
