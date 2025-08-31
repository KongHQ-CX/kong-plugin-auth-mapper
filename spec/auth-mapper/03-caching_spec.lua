-- spec/auth-mapper/03-caching_spec.lua
local helpers = require("spec.helpers")

local PLUGIN_NAME = "auth-mapper"

for _, strategy in helpers.all_strategies() do
  if strategy ~= "cassandra" then
    describe(PLUGIN_NAME .. ": caching [#" .. strategy .. "]", function()
      local client

      lazy_setup(function()
        local bp = helpers.get_db_utils(strategy == "off" and "postgres" or strategy, nil, { PLUGIN_NAME })

        -- Route with caching enabled
        local route1 = bp.routes:insert({
          hosts = { "cache-test.com" },
        })

        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route1.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            concat_glue = ":",
            cache_enabled = true,
            cache_ttl = 60, -- Short TTL for testing
            auth_mappings_json = '{"cache-test:secret":{"client_id":"cached-id","client_secret":"cached-secret"}}',
          },
        })

        -- Route with caching disabled
        local route2 = bp.routes:insert({
          hosts = { "no-cache-test.com" },
        })

        bp.plugins:insert({
          name = PLUGIN_NAME,
          route = { id = route2.id },
          config = {
            client_id_header = "client_id",
            client_secret_header = "client_secret",
            concat_glue = ":",
            cache_enabled = false,
            auth_mappings_json = '{"no-cache:secret":{"client_id":"no-cache-id","client_secret":"no-cache-secret"}}',
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
      end)

      after_each(function()
        if client then
          client:close()
        end
      end)

      describe("cache functionality", function()
        it("caches resolved credentials on first request", function()
          local r = client:get("/request", {
            headers = {
              host = "cache-test.com",
              ["client_id"] = "cache-test",
              ["client_secret"] = "secret",
            },
          })

          assert.response(r).has.status(200)

          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("cached-id:cached-secret")
          assert.equal(expected, auth_header)
        end)

        it("uses cached credentials on subsequent requests", function()
          -- First request (should cache)
          local r1 = client:get("/request", {
            headers = {
              host = "cache-test.com",
              ["client_id"] = "cache-test",
              ["client_secret"] = "secret",
            },
          })

          assert.response(r1).has.status(200)

          -- Second request (should use cache)
          local r2 = client:get("/request", {
            headers = {
              host = "cache-test.com",
              ["client_id"] = "cache-test",
              ["client_secret"] = "secret",
            },
          })

          assert.response(r2).has.status(200)

          -- Both should return same result
          local auth_header1 = assert.request(r1).has.header("authorization")
          local auth_header2 = assert.request(r2).has.header("authorization")
          assert.equal(auth_header1, auth_header2)

          local expected = "Basic " .. ngx.encode_base64("cached-id:cached-secret")
          assert.equal(expected, auth_header1)
        end)

        it("works correctly with caching disabled", function()
          local r = client:get("/request", {
            headers = {
              host = "no-cache-test.com",
              ["client_id"] = "no-cache",
              ["client_secret"] = "secret",
            },
          })

          assert.response(r).has.status(200)

          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("no-cache-id:no-cache-secret")
          assert.equal(expected, auth_header)
        end)

        it("caches fallback credentials when no mapping exists", function()
          local r = client:get("/request", {
            headers = {
              host = "cache-test.com",
              ["client_id"] = "unmapped",
              ["client_secret"] = "credentials",
            },
          })

          assert.response(r).has.status(200)

          -- Should fallback to original credentials
          local auth_header = assert.request(r).has.header("authorization")
          local expected = "Basic " .. ngx.encode_base64("unmapped:credentials")
          assert.equal(expected, auth_header)
        end)

        it("handles different credential combinations independently", function()
          -- First credential set
          local r1 = client:get("/request", {
            headers = {
              host = "cache-test.com",
              ["client_id"] = "cache-test",
              ["client_secret"] = "secret",
            },
          })

          assert.response(r1).has.status(200)

          -- First should use mapping
          local auth_header1 = assert.request(r1).has.header("authorization")
          local expected1 = "Basic " .. ngx.encode_base64("cached-id:cached-secret")
          assert.equal(expected1, auth_header1)

          -- Second credential set (should be cached separately)
          local r2 = client:get("/request", {
            headers = {
              host = "cache-test.com",
              ["client_id"] = "different",
              ["client_secret"] = "creds",
            },
          })

          assert.response(r2).has.status(200)

          -- Second should fallback to original
          local auth_header2 = assert.request(r2).has.header("authorization")
          local expected2 = "Basic " .. ngx.encode_base64("different:creds")
          assert.equal(expected2, auth_header2)
        end)
      end)
    end)
  end
end
