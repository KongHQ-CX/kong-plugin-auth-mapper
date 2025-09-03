-- spec/auth-mapper/13-strip_headers_integration_spec.lua
local helpers = require("spec.helpers")

local function purge_cache()
  local admin = helpers.admin_client()
  assert(admin:send({
    method = "DELETE",
    path = "/cache",
  }))
  admin:close()
end

local PLUGIN_NAME = "auth-mapper"

for _, strategy in helpers.all_strategies() do
  if strategy ~= "cassandra" then
    describe(PLUGIN_NAME .. ": strip headers integration [#" .. strategy .. "]", function()
      local client

      lazy_setup(function()
        local bp = helpers.get_db_utils(strategy == "off" and "postgres" or strategy, nil, { PLUGIN_NAME })

        -- Route 1: Strip headers enabled with both mode
        local route1 = bp.routes:insert({
          hosts = { "strip-both.com" },
        })

        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route1.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            concat_glue = ":",
            match_mode = "both",
            strip_original_headers = true, -- Enable stripping
            auth_mappings_json = '{"app1:secret1":{"client_id":"mapped-app1","client_secret":"mapped-secret1"},"app2:secret2":{"client_id":"mapped-app2","client_secret":"mapped-secret2"}}',
          },
        })

        -- Route 2: Strip headers disabled (default)
        local route2 = bp.routes:insert({
          hosts = { "no-strip.com" },
        })

        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route2.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            concat_glue = ":",
            match_mode = "both",
            strip_original_headers = false, -- Explicitly disabled
            auth_mappings_json = '{"app1:secret1":{"client_id":"mapped-app1","client_secret":"mapped-secret1"}}',
          },
        })

        -- Route 3: Strip headers with client_id_only mode
        local route3 = bp.routes:insert({
          hosts = { "strip-client-id.com" },
        })

        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route3.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            match_mode = "client_id_only",
            strip_original_headers = true, -- Enable stripping
            auth_mappings_json = '{"app1":{"client_id":"client-mapped-1","client_secret":"client-secret-1"},"app2":{"client_id":"client-mapped-2","client_secret":"client-secret-2"}}',
          },
        })

        -- Route 4: Strip headers with custom header names
        local route4 = bp.routes:insert({
          hosts = { "strip-custom.com" },
        })

        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route4.id },
          config = {
            client_id_header = "x-app-id",
            client_secret_header = "x-app-secret",
            concat_glue = ":",
            match_mode = "both",
            strip_original_headers = true, -- Enable stripping
            auth_mappings_json = '{"custom:app":{"client_id":"custom-mapped","client_secret":"custom-secret"}}',
          },
        })

        -- Route 5: Strip headers with fallback scenario
        local route5 = bp.routes:insert({
          hosts = { "strip-fallback.com" },
        })

        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route5.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            concat_glue = ":",
            match_mode = "both",
            strip_original_headers = true, -- Enable stripping
            auth_mappings_json = '{"different:mapping":{"client_id":"other-id","client_secret":"other-secret"}}', -- Won't match our test
          },
        })

        -- Route 6: Default behavior (strip_original_headers not specified)
        local route6 = bp.routes:insert({
          hosts = { "default-strip.com" },
        })

        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route6.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            concat_glue = ":",
            match_mode = "both",
            -- strip_original_headers not specified - should default to false
            auth_mappings_json = '{"app1:secret1":{"client_id":"mapped-app1","client_secret":"mapped-secret1"}}',
          },
        })

        local kong_config = {
          database = strategy,
          nginx_conf = "spec/fixtures/custom_nginx.template",
          plugins = "bundled," .. PLUGIN_NAME,
          declarative_config = strategy == "off" and helpers.make_yaml_file() or nil,
        }

        if strategy == "off" then
          kong_config.lmdb_environment_path = "/tmp/kong_tests"
          kong_config.lmdb_map_size = "128m"
        end

        assert(helpers.start_kong(kong_config))
      end)

      lazy_teardown(function()
        helpers.stop_kong(nil, true)
      end)

      before_each(function()
        client = helpers.proxy_client()
        purge_cache()
      end)

      after_each(function()
        if client then
          client:close()
        end
      end)

      describe("strip_original_headers = true", function()
        it("strips both headers in both mode with mapping hit", function()
          local r = client:get("/request", {
            headers = {
              host = "strip-both.com",
              ["client_id"] = "app1",
              ["client_secret"] = "secret1",
            },
          })

          assert.response(r).has.status(200)

          -- Should use mapped credentials in Authorization header
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("mapped-app1:mapped-secret1")
          assert.equal(expected, auth_header)

          -- Original headers should be stripped (not present in upstream request)
          assert.request(r).has.no.header("client_id")
          assert.request(r).has.no.header("client_secret")
        end)

        it("strips both headers in both mode with different mapping", function()
          local r = client:get("/request", {
            headers = {
              host = "strip-both.com",
              ["client_id"] = "app2",
              ["client_secret"] = "secret2",
            },
          })

          assert.response(r).has.status(200)

          -- Should use second mapping
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("mapped-app2:mapped-secret2")
          assert.equal(expected, auth_header)

          -- Headers should be stripped
          assert.request(r).has.no.header("client_id")
          assert.request(r).has.no.header("client_secret")
        end)

        it("strips headers in client_id_only mode", function()
          local r = client:get("/request", {
            headers = {
              host = "strip-client-id.com",
              ["client_id"] = "app1",
              ["client_secret"] = "any-secret-ignored", -- Ignored for lookup but still stripped
            },
          })

          assert.response(r).has.status(200)

          -- Should use mapped credentials based on client_id only
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("client-mapped-1:client-secret-1")
          assert.equal(expected, auth_header)

          -- Both headers should be stripped
          assert.request(r).has.no.header("client_id")
          assert.request(r).has.no.header("client_secret")
        end)

        it("strips custom header names", function()
          local r = client:get("/request", {
            headers = {
              host = "strip-custom.com",
              ["x-app-id"] = "custom",
              ["x-app-secret"] = "app",
            },
          })

          assert.response(r).has.status(200)

          -- Should use mapped credentials
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("custom-mapped:custom-secret")
          assert.equal(expected, auth_header)

          -- Custom headers should be stripped
          assert.request(r).has.no.header("x-app-id")
          assert.request(r).has.no.header("x-app-secret")
        end)

        it("strips headers even when using fallback credentials", function()
          local r = client:get("/request", {
            headers = {
              host = "strip-fallback.com",
              ["client_id"] = "unknown",
              ["client_secret"] = "credentials",
            },
          })

          assert.response(r).has.status(200)

          -- Should fallback to original credentials (no mapping match)
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("unknown:credentials")
          assert.equal(expected, auth_header)

          -- Headers should still be stripped
          assert.request(r).has.no.header("client_id")
          assert.request(r).has.no.header("client_secret")
        end)
      end)

      describe("strip_original_headers = false", function()
        it("preserves headers when stripping is disabled", function()
          local r = client:get("/request", {
            headers = {
              host = "no-strip.com",
              ["client_id"] = "app1",
              ["client_secret"] = "secret1",
            },
          })

          assert.response(r).has.status(200)

          -- Should use mapped credentials in Authorization header
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("mapped-app1:mapped-secret1")
          assert.equal(expected, auth_header)

          -- Original headers should be preserved
          assert.equal("app1", assert.request(r).has.header("client_id"))
          assert.equal("secret1", assert.request(r).has.header("client_secret"))
        end)

        it("preserves headers when strip_original_headers not specified (default)", function()
          local r = client:get("/request", {
            headers = {
              host = "default-strip.com",
              ["client_id"] = "app1",
              ["client_secret"] = "secret1",
            },
          })

          assert.response(r).has.status(200)

          -- Should use mapped credentials
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("mapped-app1:mapped-secret1")
          assert.equal(expected, auth_header)

          -- Headers should be preserved (default behavior)
          assert.equal("app1", assert.request(r).has.header("client_id"))
          assert.equal("secret1", assert.request(r).has.header("client_secret"))
        end)
      end)

      describe("error conditions with strip headers", function()
        it("does not strip headers when client_id is missing", function()
          local r = client:get("/request", {
            headers = {
              host = "strip-both.com",
              ["client_secret"] = "secret1",
              -- client_id missing - should skip processing
            },
          })

          assert.response(r).has.status(200)

          -- Should not set Authorization header
          assert.request(r).has.no.header("authorization")

          -- client_secret should still be present (not stripped due to skipped processing)
          assert.equal("secret1", assert.request(r).has.header("client_secret"))
        end)

        it("does not strip headers when client_secret is missing", function()
          local r = client:get("/request", {
            headers = {
              host = "strip-both.com",
              ["client_id"] = "app1",
              -- client_secret missing - should skip processing
            },
          })

          assert.response(r).has.status(200)

          -- Should not set Authorization header
          assert.request(r).has.no.header("authorization")

          -- client_id should still be present (not stripped due to skipped processing)
          assert.equal("app1", assert.request(r).has.header("client_id"))
        end)

        it("strips headers even with malformed JSON", function()
          -- We can't easily test JSON parsing errors in integration tests since
          -- the JSON is parsed during Kong startup. This would be better tested
          -- in unit tests, but for completeness, we can test the behavior when
          -- no mapping matches (which is similar)
          local r = client:get("/request", {
            headers = {
              host = "strip-fallback.com",
              ["client_id"] = "nomatch",
              ["client_secret"] = "credentials",
            },
          })

          assert.response(r).has.status(200)

          -- Should fallback to original credentials
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("nomatch:credentials")
          assert.equal(expected, auth_header)

          -- Headers should still be stripped
          assert.request(r).has.no.header("client_id")
          assert.request(r).has.no.header("client_secret")
        end)
      end)

      describe("caching behavior with strip headers", function()
        it("strips headers consistently across cached requests", function()
          -- First request (should cache)
          local r1 = client:get("/request", {
            headers = {
              host = "strip-both.com",
              ["client_id"] = "app1",
              ["client_secret"] = "secret1",
            },
          })

          assert.response(r1).has.status(200)

          -- Should use mapped credentials
          local auth_header1 = assert.request(r1).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("mapped-app1:mapped-secret1")
          assert.equal(expected, auth_header1)

          -- Headers should be stripped
          assert.request(r1).has.no.header("client_id")
          assert.request(r1).has.no.header("client_secret")

          -- Second request (should use cache and still strip)
          local r2 = client:get("/request", {
            headers = {
              host = "strip-both.com",
              ["client_id"] = "app1",
              ["client_secret"] = "secret1",
            },
          })

          assert.response(r2).has.status(200)

          -- Should still use same mapped credentials
          local auth_header2 = assert.request(r2).has.header("authorization")
          assert.equal(expected, auth_header2)

          -- Headers should still be stripped
          assert.request(r2).has.no.header("client_id")
          assert.request(r2).has.no.header("client_secret")
        end)
      end)
    end)
  end
end
