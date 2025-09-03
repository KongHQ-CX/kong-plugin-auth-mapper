-- spec/auth-mapper/04-strip_headers_unit_spec.lua
local PLUGIN_NAME = "auth-mapper"
describe(PLUGIN_NAME .. ": strip headers (unit)", function()
  local plugin
  local header_name, header_value
  local cleared_headers = {}

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
            return "test-app"
          elseif name == "client_secret" then
            return "test-secret"
          elseif name == "x-app-id" then
            return "custom-app"
          elseif name == "x-app-secret" then
            return "custom-secret"
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
          clear_header = function(name)
            table.insert(cleared_headers, name)
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
    cleared_headers = {}
  end)

  describe("strip_original_headers = false (default)", function()
    it("does not strip headers when strip_original_headers is false", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        strip_original_headers = false,
        auth_mappings_json = '{"test-app:test-secret":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
      }

      plugin:access(conf)

      -- Should set Authorization header
      local expected = "Basic " .. ngx.encode_base64("mapped-id:mapped-secret")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)

      -- Should not clear any headers
      assert.equal(0, #cleared_headers)
    end)

    it("does not strip headers when strip_original_headers is not specified (default)", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        -- strip_original_headers not specified - should default to false
        auth_mappings_json = '{"test-app:test-secret":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
      }

      plugin:access(conf)

      -- Should set Authorization header
      local expected = "Basic " .. ngx.encode_base64("mapped-id:mapped-secret")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)

      -- Should not clear any headers
      assert.equal(0, #cleared_headers)
    end)
  end)

  describe("strip_original_headers = true", function()
    it("strips both client_id and client_secret headers in both mode", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        strip_original_headers = true,
        auth_mappings_json = '{"test-app:test-secret":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
      }

      plugin:access(conf)

      -- Should set Authorization header
      local expected = "Basic " .. ngx.encode_base64("mapped-id:mapped-secret")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)

      -- Should clear both headers
      assert.equal(2, #cleared_headers)
      assert.are.same({"client_id", "client_secret"}, cleared_headers)
    end)

    it("strips both headers in client_id_only mode", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        match_mode = "client_id_only",
        strip_original_headers = true,
        auth_mappings_json = '{"test-app":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
      }

      plugin:access(conf)

      -- Should set Authorization header using mapped credentials
      local expected = "Basic " .. ngx.encode_base64("mapped-id:mapped-secret")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)

      -- Should still clear both headers (both are always required)
      assert.equal(2, #cleared_headers)
      assert.are.same({"client_id", "client_secret"}, cleared_headers)
    end)

    it("strips custom header names", function()
      local conf = {
        client_id_header = "x-app-id",
        client_secret_header = "x-app-secret",
        concat_glue = ":",
        match_mode = "both",
        strip_original_headers = true,
        auth_mappings_json = '{"custom-app:custom-secret":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
      }

      plugin:access(conf)

      -- Should set Authorization header
      local expected = "Basic " .. ngx.encode_base64("mapped-id:mapped-secret")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)

      -- Should clear custom headers
      assert.equal(2, #cleared_headers)
      assert.are.same({"x-app-id", "x-app-secret"}, cleared_headers)
    end)

    it("strips headers even when using fallback credentials", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        strip_original_headers = true,
        auth_mappings_json = '{"different:mapping":{"client_id":"other-id","client_secret":"other-secret"}}',
      }

      plugin:access(conf)

      -- Should use fallback credentials (original)
      local expected = "Basic " .. ngx.encode_base64("test-app:test-secret")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)

      -- Should still strip headers
      assert.equal(2, #cleared_headers)
      assert.are.same({"client_id", "client_secret"}, cleared_headers)
    end)

    it("does not strip headers when processing is skipped (missing client_id)", function()

      local conf = {
        client_id_header = "client_id_missing",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        strip_original_headers = true,
        auth_mappings_json = '{"test-app:test-secret":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
      }

      plugin:access(conf)

      -- Should not set Authorization header
      assert.is_nil(header_name)
      assert.is_nil(header_value)

      -- Should not clear any headers since processing was skipped
      assert.equal(0, #cleared_headers)
    end)

    it("does not strip headers when processing is skipped (missing client_secret)", function()

      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret_missing",
        concat_glue = ":",
        match_mode = "both",
        strip_original_headers = true,
        auth_mappings_json = '{"test-app:test-secret":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
      }

      plugin:access(conf)

      -- Should not set Authorization header
      assert.is_nil(header_name)
      assert.is_nil(header_value)

      -- Should not clear any headers since processing was skipped
      assert.equal(0, #cleared_headers)
    end)
  end)

  describe("error conditions with strip headers", function()
    it("strips headers even when JSON parsing fails", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        strip_original_headers = true,
        auth_mappings_json = '{"invalid": json}', -- Malformed JSON
      }

      plugin:access(conf)

      -- Should fallback to original credentials when JSON parsing fails
      local expected = "Basic " .. ngx.encode_base64("test-app:test-secret")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)

      -- Should still strip headers even on JSON error
      assert.equal(2, #cleared_headers)
      assert.are.same({"client_id", "client_secret"}, cleared_headers)
    end)

    it("strips headers when mapped credentials are null", function()
      local conf = {
        client_id_header = "client_id",
        client_secret_header = "client_secret",
        concat_glue = ":",
        match_mode = "both",
        strip_original_headers = true,
        auth_mappings_json = '{"test-app:test-secret":{"client_id":null,"client_secret":"mapped-secret"}}', -- Null client_id
      }

      plugin:access(conf)

      -- Should fallback to original credentials when mapped values are null
      local expected = "Basic " .. ngx.encode_base64("test-app:test-secret")
      assert.equal("Authorization", header_name)
      assert.equal(expected, header_value)

      -- Should still strip headers
      assert.equal(2, #cleared_headers)
      assert.are.same({"client_id", "client_secret"}, cleared_headers)
    end)
  end)
end)
