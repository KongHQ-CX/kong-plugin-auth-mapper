-- spec/auth-mapper/12-client_id_only_spec.lua
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
    describe(PLUGIN_NAME .. ": client_id_only mode [#" .. strategy .. "]", function()
      local client

      lazy_setup(function()
        local bp = helpers.get_db_utils(strategy == "off" and "postgres" or strategy, nil, { PLUGIN_NAME })

        -- Route 1: Basic client_id_only mode
        local route1 = bp.routes:insert({
          hosts = { "client-id-basic.com" },
        })

        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route1.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            match_mode = "client_id_only",
            auth_mappings_json = '{"app1":{"client_id":"mapped-app1-id","client_secret":"mapped-app1-secret"},"app2":{"client_id":"mapped-app2-id","client_secret":"mapped-app2-secret"}}',
          },
        })

        -- Route 2: Custom headers with client_id_only mode
        local route2 = bp.routes:insert({
          hosts = { "client-id-custom.com" },
        })

        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route2.id },
          config = {
            client_id_header = "x-app-id",
            client_secret_header = "x-app-secret",
            match_mode = "client_id_only",
            auth_mappings_json = '{"custom-app":{"client_id":"custom-mapped-id","client_secret":"custom-mapped-secret"}}',
          },
        })

        -- Route 3: Client_id_only with concat_glue (should be ignored)
        local route3 = bp.routes:insert({
          hosts = { "client-id-glue.com" },
        })

        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route3.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            concat_glue = "|", -- Should be ignored in client_id_only mode
            match_mode = "client_id_only",
            auth_mappings_json = '{"test-app":{"client_id":"test-mapped-id","client_secret":"test-mapped-secret"}}',
          },
        })

        -- Route 4: Client_id_only with mixed mappings
        local route4 = bp.routes:insert({
          hosts = { "client-id-mixed.com" },
        })

        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route4.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            match_mode = "client_id_only",
            auth_mappings_json = '{"prod-app":{"client_id":"prod-mapped-id","client_secret":"prod-mapped-secret"},"dev-app":{"client_id":"dev-mapped-id","client_secret":"dev-mapped-secret"},"staging-app":{"client_id":"staging-mapped-id","client_secret":"staging-mapped-secret"}}',
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

      describe("client_id lookup behavior", function()
        it("maps client_id to different credentials ignoring client_secret in lookup", function()
          local r = client:get("/request", {
            headers = {
              host = "client-id-basic.com",
              ["client_id"] = "app1",
              ["client_secret"] = "any-secret-value", -- Should be ignored for lookup
            },
          })

          assert.response(r).has.status(200)

          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("mapped-app1-id:mapped-app1-secret")
          assert.equal(expected, auth_header)

          -- Original headers should still be present
          assert.equal("app1", assert.request(r).has.header("client_id"))
          assert.equal("any-secret-value", assert.request(r).has.header("client_secret"))
        end)

        it("maps different client_ids to different credentials", function()
          -- Test app1
          local r1 = client:get("/request", {
            headers = {
              host = "client-id-basic.com",
              ["client_id"] = "app1",
              ["client_secret"] = "secret1",
            },
          })

          assert.response(r1).has.status(200)

          local auth_header1 = assert.request(r1).has.header("authorization")
          local expected1 = "Basic " .. ngx.encode_base64("mapped-app1-id:mapped-app1-secret")
          assert.equal(expected1, auth_header1)

          -- Test app2
          local r2 = client:get("/request", {
            headers = {
              host = "client-id-basic.com",
              ["client_id"] = "app2",
              ["client_secret"] = "secret2", -- Different secret, but only client_id used for lookup
            },
          })

          assert.response(r2).has.status(200)

          local auth_header2 = assert.request(r2).has.header("authorization")
          local expected2 = "Basic " .. ngx.encode_base64("mapped-app2-id:mapped-app2-secret")
          assert.equal(expected2, auth_header2)
        end)

        it("same client_id with different secrets uses same mapping", function()
          -- First request
          local r1 = client:get("/request", {
            headers = {
              host = "client-id-basic.com",
              ["client_id"] = "app1",
              ["client_secret"] = "original-secret",
            },
          })

          assert.response(r1).has.status(200)

          -- Check first request uses mapped credentials
          local auth_header1 = assert.request(r1).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("mapped-app1-id:mapped-app1-secret")
          assert.equal(expected, auth_header1)

          -- Second request with same client_id but different secret
          local r2 = client:get("/request", {
            headers = {
              host = "client-id-basic.com",
              ["client_id"] = "app1",
              ["client_secret"] = "completely-different-secret",
            },
          })

          assert.response(r2).has.status(200)

          -- Second request should also use the same mapped credentials (client_id lookup ignores secret)
          local auth_header2 = assert.request(r2).has.header("authorization")
          assert.equal(expected, auth_header2)
        end)

        it("falls back to original credentials when client_id not found", function()
          local r = client:get("/request", {
            headers = {
              host = "client-id-basic.com",
              ["client_id"] = "unknown-app",
              ["client_secret"] = "fallback-secret",
            },
          })

          assert.response(r).has.status(200)

          -- Should fallback to original credentials
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("unknown-app:fallback-secret")
          assert.equal(expected, auth_header)
        end)

        it("works with custom header names", function()
          local r = client:get("/request", {
            headers = {
              host = "client-id-custom.com",
              ["x-app-id"] = "custom-app",
              ["x-app-secret"] = "ignored-for-lookup",
            },
          })

          assert.response(r).has.status(200)

          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("custom-mapped-id:custom-mapped-secret")
          assert.equal(expected, auth_header)
        end)

        it("ignores concat_glue configuration in client_id_only mode", function()
          local r = client:get("/request", {
            headers = {
              host = "client-id-glue.com",
              ["client_id"] = "test-app",
              ["client_secret"] = "secret|with|pipes", -- Pipes in secret shouldn't affect lookup
            },
          })

          assert.response(r).has.status(200)

          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("test-mapped-id:test-mapped-secret")
          assert.equal(expected, auth_header)
        end)
      end)

      describe("multiple client applications", function()
        it("handles production, development, and staging environments", function()
          -- Production app
          local r_prod = client:get("/request", {
            headers = {
              host = "client-id-mixed.com",
              ["client_id"] = "prod-app",
              ["client_secret"] = "prod-secret",
            },
          })

          assert.response(r_prod).has.status(200)
          local auth_header_prod = assert.request(r_prod).has.header("authorization")
          local expected_prod = "Basic " .. ngx.encode_base64("prod-mapped-id:prod-mapped-secret")
          assert.equal(expected_prod, auth_header_prod)

          -- Development app
          local r_dev = client:get("/request", {
            headers = {
              host = "client-id-mixed.com",
              ["client_id"] = "dev-app",
              ["client_secret"] = "dev-secret",
            },
          })

          assert.response(r_dev).has.status(200)
          local auth_header_dev = assert.request(r_dev).has.header("authorization")
          local expected_dev = "Basic " .. ngx.encode_base64("dev-mapped-id:dev-mapped-secret")
          assert.equal(expected_dev, auth_header_dev)

          -- Staging app
          local r_staging = client:get("/request", {
            headers = {
              host = "client-id-mixed.com",
              ["client_id"] = "staging-app",
              ["client_secret"] = "staging-secret",
            },
          })

          assert.response(r_staging).has.status(200)
          local auth_header_staging = assert.request(r_staging).has.header("authorization")
          local expected_staging = "Basic " .. ngx.encode_base64("staging-mapped-id:staging-mapped-secret")
          assert.equal(expected_staging, auth_header_staging)
        end)

        it("handles mixed success and fallback scenarios", function()
          -- Known app - should use mapping
          local r_known = client:get("/request", {
            headers = {
              host = "client-id-mixed.com",
              ["client_id"] = "prod-app",
              ["client_secret"] = "any-secret",
            },
          })

          assert.response(r_known).has.status(200)
          local auth_header_known = assert.request(r_known).has.header("authorization")
          local expected_known = "Basic " .. ngx.encode_base64("prod-mapped-id:prod-mapped-secret")
          assert.equal(expected_known, auth_header_known)

          -- Unknown app - should fallback
          local r_unknown = client:get("/request", {
            headers = {
              host = "client-id-mixed.com",
              ["client_id"] = "legacy-app",
              ["client_secret"] = "legacy-secret",
            },
          })

          assert.response(r_unknown).has.status(200)
          local auth_header_unknown = assert.request(r_unknown).has.header("authorization")
          local expected_unknown = "Basic " .. ngx.encode_base64("legacy-app:legacy-secret")
          assert.equal(expected_unknown, auth_header_unknown)
        end)
      end)

      describe("error handling in client_id_only mode", function()
        it("skips processing when client_id header is missing", function()
          local r = client:get("/request", {
            headers = {
              host = "client-id-basic.com",
              ["client_secret"] = "secret-present",
              -- client_id header is missing
            },
          })

          assert.response(r).has.status(200)

          -- Should not set Authorization header
          assert.request(r).has.no.header("authorization")
        end)

        it("skips processing when client_secret header is missing", function()
          local r = client:get("/request", {
            headers = {
              host = "client-id-basic.com",
              ["client_id"] = "app1",
              -- client_secret header is missing
            },
          })

          assert.response(r).has.status(200)

          -- Should not set Authorization header (both headers required)
          assert.request(r).has.no.header("authorization")
        end)

        it("handles empty client_id header", function()
          local r = client:get("/request", {
            headers = {
              host = "client-id-basic.com",
              ["client_id"] = "", -- Empty client_id
              ["client_secret"] = "secret",
            },
          })

          assert.response(r).has.status(200)

          -- Should not set Authorization header
          assert.request(r).has.no.header("authorization")
        end)

        it("handles whitespace-only client_id header", function()
          local r = client:get("/request", {
            headers = {
              host = "client-id-basic.com",
              ["client_id"] = "   \t   ", -- Whitespace-only
              ["client_secret"] = "secret",
            },
          })

          assert.response(r).has.status(200)

          -- Should not set Authorization header
          assert.request(r).has.no.header("authorization")
        end)

        it("trims whitespace from client_id before lookup", function()
          local r = client:get("/request", {
            headers = {
              host = "client-id-basic.com",
              ["client_id"] = "  app1  ", -- Whitespace around client_id
              ["client_secret"] = "secret",
            },
          })

          assert.response(r).has.status(200)

          -- Should still match "app1" after trimming
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("mapped-app1-id:mapped-app1-secret")
          assert.equal(expected, auth_header)
        end)

        it("handles multi-value client_id header", function()
          local r = client:get("/request", {
            headers = {
              host = "client-id-basic.com",
              ["client_id"] = { "app1", "app2" }, -- Multi-value header, should use first
              ["client_secret"] = "secret",
            },
          })

          assert.response(r).has.status(200)

          -- Should use first value "app1"
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("mapped-app1-id:mapped-app1-secret")
          assert.equal(expected, auth_header)
        end)
      end)
    end)
  end
end
