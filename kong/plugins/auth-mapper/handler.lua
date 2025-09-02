-- kong/plugins/auth-mapper/handler.lua
local cjson = require("cjson")
local plugin = {
  PRIORITY = 1060, -- before oidc runs
  VERSION = "0.1.0",
}

local set_header = kong.service.request.set_header
local get_header = kong.request.get_header
local encode_base64 = ngx.encode_base64

-- Safe header get, returns nil if blank or whitespace-only
local function header_value(name)
  if not name or name == "" then
    return nil
  end
  local v = get_header(name)
  if not v or v == "" then
    return nil
  end
  if type(v) == "table" then
    -- If multiple values are present, use the first one
    v = v[1]
  end
  -- Trim whitespace
  v = string.match(v, "^%s*(.-)%s*$")
  if v == "" then
    return nil
  end
  return v
end

-- Resolve credentials with JSON parsing (used for caching)
local function resolve_credentials(lookup_key, auth_mappings_json, fallback_id, fallback_secret, match_mode)
  kong.log.debug("resolving credentials for key: ", lookup_key, " (mode: ", match_mode, ")")

  -- Parse JSON (this gets cached)
  local auth_map
  local ok, result = pcall(cjson.decode, auth_mappings_json)
  if not ok then
    kong.log.error("failed to parse auth_mappings_json: ", result)
    -- Fallback to original credentials on JSON parse error
    auth_map = {}
  else
    auth_map = result
  end

  -- Lookup mapping in the parsed dictionary
  local mapping = auth_map[lookup_key]

  -- Choose credentials
  local out_id, out_secret
  if mapping and mapping.client_id and mapping.client_secret then
    -- Handle cjson.null values - convert to nil for proper fallback
    local mapped_id = mapping.client_id
    local mapped_secret = mapping.client_secret

    if mapped_id == cjson.null then mapped_id = nil end
    if mapped_secret == cjson.null then mapped_secret = nil end

    if mapped_id and mapped_secret then
      out_id = mapped_id
      out_secret = mapped_secret
      kong.log.debug("using mapped credentials")
    else
      out_id = fallback_id
      out_secret = fallback_secret
      kong.log.debug("using fallback credentials (mapped values were null)")
    end
  else
    out_id = fallback_id
    out_secret = fallback_secret
    kong.log.debug("using fallback credentials")
  end

  if not out_id or not out_secret then
    return nil, "incomplete credentials"
  end

  -- Return the resolved credentials
  return {
    client_id = out_id,
    client_secret = out_secret,
  }
end

function plugin:access(conf)
  -- Pull original client id and secret from configurable headers
  local orig_id = header_value(conf.client_id_header)
  local orig_secret = header_value(conf.client_secret_header)

  -- Both headers are required regardless of match mode (needed for Basic auth generation)
  if not orig_id or not orig_secret then
    kong.log.debug("missing client headers, skipping")
    return
  end

  -- Determine match mode, default to "both" for backward compatibility
  local match_mode = conf.match_mode or "both"

  -- Build the lookup key based on match mode
  local lookup_key
  if match_mode == "client_id_only" then
    lookup_key = tostring(orig_id)
  else
    local glue = conf.concat_glue or ":"
    lookup_key = tostring(orig_id) .. glue .. tostring(orig_secret)
  end

  -- Fallback credentials
  local fallback_id = orig_id
  local fallback_secret = orig_secret

  local credentials, err

  if conf.cache_enabled then
    -- Use cache with configured TTL
    local cache_opts = { ttl = conf.cache_ttl }
    local cache_key = "auth-mapper:" .. match_mode .. ":" .. lookup_key

    credentials, err = kong.cache:get(
      cache_key,
      cache_opts,
      resolve_credentials,
      lookup_key,
      conf.auth_mappings_json,
      fallback_id,
      fallback_secret,
      match_mode
    )

    if err then
      kong.log.warn("cache error: ", err)
      return
    end
  else
    -- Direct resolution without caching
    credentials, err = resolve_credentials(
      lookup_key,
      conf.auth_mappings_json,
      fallback_id,
      fallback_secret,
      match_mode
    )

    if err then
      kong.log.warn("credential resolution error: ", err)
      return
    end
  end

  if not credentials then
    kong.log.warn("failed to resolve credentials")
    return
  end

  local out_id = credentials.client_id
  local out_secret = credentials.client_secret

  -- Build and set the Basic Authorization header
  local basic_token = encode_base64(out_id .. ":" .. out_secret)
  local basic_value = "Basic " .. basic_token

  -- Set on the request so subsequent plugins, including OIDC, can read it
  set_header("Authorization", basic_value)

  kong.log.debug("Authorization header set successfully (mode: ", match_mode, ")")
end

return plugin
