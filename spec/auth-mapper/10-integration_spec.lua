-- spec/auth-mapper/10-integration_spec.lua
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
    describe(PLUGIN_NAME .. ": (access) [#" .. strategy .. "]", function()
      local client

      lazy_setup(function()
        local bp = helpers.get_db_utils(strategy == "off" and "postgres" or strategy, nil, { PLUGIN_NAME })

        -- Route 1: Default both mode
        local route1 = bp.routes:insert({
          hosts = { "test1.com" },
        })

        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route1.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            concat_glue = ":",
            match_mode = "both", -- Explicit both mode
            auth_mappings_json = '{"acme:s3cr3t":{"client_id":"entra-id-1","client_secret":"entra-secret-1"}}',
          },
        })

        -- Route 2: Custom header names (both mode)
        local route2 = bp.routes:insert({
          hosts = { "custom-headers.com" },
        })
        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route2.id },
          config = {
            client_id_header = "x-client-id",
            client_secret_header = "x-client-secret",
            concat_glue = ":",
            match_mode = "both",
            auth_mappings_json = '{"acme:s3cr3t":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
          },
        })

        -- Route 3: custom concat_glue (both mode)
        local route3 = bp.routes:insert({
          hosts = { "empty-glue.com" },
        })
        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route3.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            concat_glue = " ",
            match_mode = "both",
            auth_mappings_json = '{"acme s3cr3t":{"client_id":"entra-id-1","client_secret":"entra-secret-1"}}',
          },
        })

        -- Route 4: Custom concat_glue character 2 (both mode)
        local route4 = bp.routes:insert({
          hosts = { "pipe-glue.com" },
        })
        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route4.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            concat_glue = "|", -- Pipe separator
            match_mode = "both",
            auth_mappings_json = '{"acme|s3cr3t":{"client_id":"entra-id-1","client_secret":"entra-secret-1"}}',
          },
        })

        -- Route 5: Multiple auth_mappings_json entries (both mode)
        local route5 = bp.routes:insert({
          hosts = { "multi-map.com" },
        })
        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route5.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            concat_glue = ":",
            match_mode = "both",
            auth_mappings_json = '{"acme:s3cr3t":{"client_id":"mapped-1","client_secret":"secret-1"},"other:creds":{"client_id":"mapped-2","client_secret":"secret-2"}}',
          },
        })

        -- Route 6: No matching mapping (both mode)
        local route6 = bp.routes:insert({
          hosts = { "no-map.com" },
        })
        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route6.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            concat_glue = ":",
            match_mode = "both",
            auth_mappings_json = '{"different:key":{"client_id":"mapped-id","client_secret":"mapped-secret"}}',
          },
        })

        -- Route 7: Client ID only mode
        local route7 = bp.routes:insert({
          hosts = { "client-id-only.com" },
        })
        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route7.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            match_mode = "client_id_only",
            auth_mappings_json = '{"acme":{"client_id":"client-id-mapped","client_secret":"client-id-secret"},"other":{"client_id":"other-mapped","client_secret":"other-secret"}}',
          },
        })

        -- Route 8: Client ID only mode with fallback
        local route8 = bp.routes:insert({
          hosts = { "client-id-fallback.com" },
        })
        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route8.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            match_mode = "client_id_only",
            auth_mappings_json = '{"different":{"client_id":"mapped-id","client_secret":"mapped-secret"}}', -- Won't match "acme"
          },
        })

        -- Route 9: Default mode (should be "both")
        local route9 = bp.routes:insert({
          hosts = { "default-mode.com" },
        })
        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route9.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            concat_glue = ":",
            -- match_mode not specified - should default to "both"
            auth_mappings_json = '{"acme:s3cr3t":{"client_id":"default-mapped","client_secret":"default-secret"}}',
          },
        })

        local kong_config = {
          database = strategy,
          nginx_conf = "spec/fixtures/custom_nginx.template",
          plugins = "bundled," .. PLUGIN_NAME,
          declarative_config = strategy == "off" and helpers.make_yaml_file() or nil,
        }

        -- Add LMDB-specific config for macOS
        if strategy == "off" then
          kong_config.lmdb_environment_path = "/tmp/kong_tests"
          kong_config.lmdb_map_size = "128m"
        end
        -- Start Kong
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

      describe("both mode (default and explicit)", function()
        it("injects mapped Basic Authorization on mapping hit", function()
          local r = client:get("/request", {
            headers = {
              host = "test1.com",
              ["client_id"] = "acme",
              ["client_secret"] = "s3cr3t",
            },
          })

          assert.response(r).has.status(200)

          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("entra-id-1:entra-secret-1")
          assert.equal(expected, auth_header)

          assert.equal("acme", assert.request(r).has.header("client_id"))
          assert.equal("s3cr3t", assert.request(r).has.header("client_secret"))
        end)

        it("falls back to original credentials when no mapping found", function()
          local r = client:get("/request", {
            headers = {
              host = "test1.com",
              ["client_id"] = "unknown",
              ["client_secret"] = "credentials",
            },
          })

          assert.response(r).has.status(200)

          -- Should use original credentials since "unknown:credentials" doesn't match any mapping
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("unknown:credentials")
          assert.equal(expected, auth_header)

          -- Original headers should still be present
          assert.equal("unknown", assert.request(r).has.header("client_id"))
          assert.equal("credentials", assert.request(r).has.header("client_secret"))
        end)

        it("uses default both mode when match_mode not specified", function()
          local r = client:get("/request", {
            headers = {
              host = "default-mode.com",
              ["client_id"] = "acme",
              ["client_secret"] = "s3cr3t",
            },
          })

          assert.response(r).has.status(200)

          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("default-mapped:default-secret")
          assert.equal(expected, auth_header)
        end)

        it("works with custom header names", function()
          local r = client:get("/request", {
            headers = {
              host = "custom-headers.com",
              ["x-client-id"] = "acme",
              ["x-client-secret"] = "s3cr3t",
            },
          })

          assert.response(r).has.status(200)

          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("mapped-id:mapped-secret")
          assert.equal(expected, auth_header)
        end)

        it("works with space concat_glue", function()
          local r = client:get("/request", {
            headers = {
              host = "empty-glue.com",
              ["client_id"] = "acme",
              ["client_secret"] = "s3cr3t",
            },
          })

          assert.response(r).has.status(200)

          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("entra-id-1:entra-secret-1")
          assert.equal(expected, auth_header)
        end)

        it("works with custom concat_glue character", function()
          local r = client:get("/request", {
            headers = {
              host = "pipe-glue.com",
              ["client_id"] = "acme",
              ["client_secret"] = "s3cr3t",
            },
          })

          assert.response(r).has.status(200)

          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("entra-id-1:entra-secret-1")
          assert.equal(expected, auth_header)
        end)

        it("works with multiple auth_mappings_json entries", function()
          local r = client:get("/request", {
            headers = {
              host = "multi-map.com",
              ["client_id"] = "other",
              ["client_secret"] = "creds",
            },
          })

          assert.response(r).has.status(200)

          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("mapped-2:secret-2")
          assert.equal(expected, auth_header)
        end)

        it("skips processing when client_id header missing", function()
          local r = client:get("/request", {
            headers = {
              host = "test1.com",
              ["client_secret"] = "s3cr3t",
              -- client_id header is missing
            },
          })

          assert.response(r).has.status(200)

          -- Should not set Authorization header
          assert.request(r).has.no.header("authorization")

          -- client_secret should still be present
          assert.equal("s3cr3t", assert.request(r).has.header("client_secret"))
        end)

        it("skips processing when client_secret header missing", function()
          local r = client:get("/request", {
            headers = {
              host = "test1.com",
              ["client_id"] = "acme",
              -- client_secret header is missing
            },
          })

          assert.response(r).has.status(200)

          -- Should not set Authorization header
          assert.request(r).has.no.header("authorization")

          -- client_id should still be present
          assert.equal("acme", assert.request(r).has.header("client_id"))
        end)
      end)

      describe("client_id_only mode", function()
        it("injects mapped Basic Authorization on client_id mapping hit", function()
          local r = client:get("/request", {
            headers = {
              host = "client-id-only.com",
              ["client_id"] = "acme",
              ["client_secret"] = "any-secret", -- Should be ignored for lookup but used for Basic auth
            },
          })

          assert.response(r).has.status(200)

          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("client-id-mapped:client-id-secret")
          assert.equal(expected, auth_header)

          assert.equal("acme", assert.request(r).has.header("client_id"))
          assert.equal("any-secret", assert.request(r).has.header("client_secret"))
        end)

        it("maps different client_ids to different credentials", function()
          local r = client:get("/request", {
            headers = {
              host = "client-id-only.com",
              ["client_id"] = "other",
              ["client_secret"] = "ignored-for-lookup",
            },
          })

          assert.response(r).has.status(200)

          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("other-mapped:other-secret")
          assert.equal(expected, auth_header)
        end)

        it("falls back to original credentials when no client_id mapping found", function()
          local r = client:get("/request", {
            headers = {
              host = "client-id-fallback.com",
              ["client_id"] = "acme", -- Won't match "different" in mapping
              ["client_secret"] = "original-secret",
            },
          })

          assert.response(r).has.status(200)

          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("acme:original-secret")
          assert.equal(expected, auth_header)
        end)

        it("skips processing when client_id header missing", function()
          local r = client:get("/request", {
            headers = {
              host = "client-id-only.com",
              ["client_secret"] = "some-secret",
              -- client_id header is missing
            },
          })

          assert.response(r).has.status(200)

          -- Should not set Authorization header
          assert.request(r).has.no.header("authorization")
        end)

        it("skips processing when client_secret header missing (needed for Basic auth)", function()
          local r = client:get("/request", {
            headers = {
              host = "client-id-only.com",
              ["client_id"] = "acme",
              -- client_secret header is missing - both headers are required regardless of mode
            },
          })

          assert.response(r).has.status(200)

          -- Should not set Authorization header because both headers are required
          assert.request(r).has.no.header("authorization")
        end)
      end)

      describe("common behavior across modes", function()
        it("skips processing when both headers missing", function()
          local r = client:get("/request", {
            headers = {
              host = "test1.com",
              -- Both client headers are missing
            },
          })

          assert.response(r).has.status(200)

          -- Should not set Authorization header
          assert.request(r).has.no.header("authorization")
        end)

        it("handles empty string headers", function()
          local r = client:get("/request", {
            headers = {
              host = "test1.com",
              ["client_id"] = "", -- Empty string
              ["client_secret"] = "s3cr3t",
            },
          })

          assert.response(r).has.status(200)

          -- Should not set Authorization header since client_id is empty
          assert.request(r).has.no.header("authorization")
        end)

        it("handles multi-value headers", function()
          local r = client:get("/request", {
            headers = {
              host = "test1.com",
              ["client_id"] = { "acme", "second-value" },
              ["client_secret"] = "s3cr3t",
            },
          })

          assert.response(r).has.status(200)

          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("entra-id-1:entra-secret-1")
          assert.equal(expected, auth_header)
        end)

        it("trims whitespace from headers", function()
          local r = client:get("/request", {
            headers = {
              host = "test1.com",
              ["client_id"] = "  acme  ",
              ["client_secret"] = "\ts3cr3t\t  ",
            },
          })

          assert.response(r).has.status(200)
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("entra-id-1:entra-secret-1")
          assert.equal(expected, auth_header)
        end)

        it("handles missing auth_mappings_json configuration gracefully", function()
          local r = client:get("/request", {
            headers = {
              host = "no-map.com",
              ["client_id"] = "acme",
              ["client_secret"] = "s3cr3t",
            },
          })

          assert.response(r).has.status(200)

          -- Should fall back to original credentials since "acme:s3cr3t" doesn't match "different:key"
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("acme:s3cr3t")
          assert.equal(expected, auth_header)
        end)
      end)
    end)
  end
end
