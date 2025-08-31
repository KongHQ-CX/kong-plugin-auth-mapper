-- spec/auth-mapper/11-vault_integration_spec.lua
local helpers = require("spec.helpers")

local PLUGIN_NAME = "auth-mapper"

for _, strategy in helpers.all_strategies() do
  if strategy ~= "cassandra" then
    describe(PLUGIN_NAME .. ": vault integration [#" .. strategy .. "]", function()
      local client

      lazy_setup(function()
        -- Set environment variables for the entire JSON mappings before Kong starts
        helpers.setenv(
          "AUTH_MAPPINGS_1",
          '{"acme:s3cr3t":{"client_id":"vault-mapped-id","client_secret":"vault-mapped-secret"}}'
        )
        helpers.setenv(
          "AUTH_MAPPINGS_2",
          '{"other:creds":{"client_id":"vault-other-id","client_secret":"vault-other-secret"},"regular:mapping":{"client_id":"regular-id","client_secret":"regular-secret"}}'
        )

        local bp = helpers.get_db_utils(strategy == "off" and "postgres" or strategy, nil, { PLUGIN_NAME })

        -- Route 1: Full JSON vault reference
        local route1 = bp.routes:insert({
          hosts = { "vault-test.com" },
        })
        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route1.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            concat_glue = ":",
            auth_mappings_json = "{vault://env/auth-mappings-1}", -- Entire JSON from vault
          },
        })

        -- Route 2:
        local route2 = bp.routes:insert({
          hosts = { "vault-mixed.com" },
        })
        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route2.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            concat_glue = ":",
            auth_mappings_json = "{vault://env/auth-mappings-2}", -- Multiple mappings from vault
          },
        })

        -- Start Kong with vault enabled
        local kong_config = {
          database = strategy,
          nginx_conf = "spec/fixtures/custom_nginx.template",
          plugins = "bundled," .. PLUGIN_NAME,
          vaults = "env", -- Enable environment variable vault
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
        -- Clean up environment variables
        os.execute("unset AUTH_MAPPINGS_1")
        os.execute("unset AUTH_MAPPINGS_2")
      end)

      before_each(function()
        client = helpers.proxy_client()
      end)

      after_each(function()
        if client then
          client:close()
        end
      end)

      describe("environment vault resolution", function()
        it("resolves full JSON mapping from vault", function()
          local r = client:get("/request", {
            headers = {
              host = "vault-test.com",
              ["client_id"] = "acme",
              ["client_secret"] = "s3cr3t",
            },
          })

          assert.response(r).has.status(200)

          -- Should use credentials resolved from vault JSON mapping
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("vault-mapped-id:vault-mapped-secret")
          assert.equal(expected, auth_header)

          -- Original headers should still be present
          assert.equal("acme", assert.request(r).has.header("client_id"))
          assert.equal("s3cr3t", assert.request(r).has.header("client_secret"))
        end)

        it("resolves different mappings from multi-entry vault JSON", function()
          local r = client:get("/request", {
            headers = {
              host = "vault-mixed.com",
              ["client_id"] = "other",
              ["client_secret"] = "creds",
            },
          })

          assert.response(r).has.status(200)

          -- Should use vault-defined credentials for "other:creds" mapping
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("vault-other-id:vault-other-secret")
          assert.equal(expected, auth_header)
        end)

        it("works with mixed credentials in vault JSON", function()
          local r = client:get("/request", {
            headers = {
              host = "vault-mixed.com",
              ["client_id"] = "regular",
              ["client_secret"] = "mapping",
            },
          })

          assert.response(r).has.status(200)

          -- Should use regular credentials defined in the vault JSON
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("regular-id:regular-secret")
          assert.equal(expected, auth_header)
        end)

        it("falls back to original when vault-resolved mapping not found", function()
          local r = client:get("/request", {
            headers = {
              host = "vault-test.com",
              ["client_id"] = "nomatch",
              ["client_secret"] = "credentials",
            },
          })

          assert.response(r).has.status(200)

          -- Should fall back to original since "nomatch:credentials" not in vault JSON
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("nomatch:credentials")
          assert.equal(expected, auth_header)
        end)
      end)
    end)
  end
end
