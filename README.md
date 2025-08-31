# Kong Auth Mapper Plugin

A Kong plugin that maps incoming client credentials to different credentials and injects a Basic Authorization header for downstream services. This plugin is particularly useful for integrating with identity providers like Azure Entra ID or other OAuth systems that require specific client credentials.

## Features

- **Credential Mapping**: Transform incoming client credentials to different credentials based on configurable JSON mappings
- **Vault Integration**: Support for Kong Vault references to securely store sensitive credential mappings
- **Performance Caching**: Built-in LRU caching for resolved credentials to improve performance
- **Flexible Headers**: Configure custom header names for client ID and secret
- **Custom Separators**: Configure the glue character used to concatenate credentials for lookup
- **Fallback Behavior**: Uses original credentials when no mapping is found
- **Basic Auth Generation**: Automatically generates and injects Basic Authorization headers

## How It Works

1. The plugin reads client credentials from configurable request headers
2. Concatenates them using a configurable glue character to create a lookup key
3. If caching is enabled, checks the cache for previously resolved credentials
4. If not cached, parses the JSON mappings and searches for the lookup key
5. If found, uses the mapped credentials; otherwise falls back to original credentials
6. Caches the resolved credentials (if caching is enabled) for future requests
7. Generates a Basic Authorization header and injects it into the request

## Configuration

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `client_id_header` | string | `"client_id"` | No | Header name containing the client ID |
| `client_secret_header` | string | `"client_secret"` | No | Header name containing the client secret |
| `concat_glue` | string | `":"` | No | Character(s) used to concatenate client_id and client_secret for lookup |
| `auth_mappings_json` | string | - | Yes | JSON string mapping input credentials to output credentials |
| `cache_enabled` | boolean | `true` | No | Enable caching of resolved credentials |
| `cache_ttl` | number | `300` | No | Cache TTL in seconds (must be > 0) |

### Auth Mappings JSON Structure

The `auth_mappings_json` is a JSON string where:
- **Keys**: Concatenated client credentials (client_id + concat_glue + client_secret)
- **Values**: Objects containing the mapped credentials

```json
{
  "input_id:input_secret": {
    "client_id": "mapped_id",
    "client_secret": "mapped_secret"
  }
}
```

## Installation

1. Place the plugin files in your Kong plugins directory:
   ```
   kong/plugins/auth-mapper/
   ├── handler.lua
   └── schema.lua
   ```

2. Add the plugin to your Kong configuration:
   ```bash
   export KONG_PLUGINS=bundled,auth-mapper
   ```

3. Restart Kong

## Usage Examples

### Basic Configuration

```yaml
plugins:
  - name: auth-mapper
    config:
      client_id_header: "client_id"
      client_secret_header: "client_secret"
      concat_glue: ":"
      cache_enabled: true
      cache_ttl: 300  # 5 minutes
      auth_mappings_json: |
        {
          "acme:s3cr3t": {
            "client_id": "entra-id-1",
            "client_secret": "entra-secret-1"
          },
          "company:password": {
            "client_id": "azure-app-id",
            "client_secret": "azure-app-secret"
          }
        }
```

### Custom Headers

```yaml
plugins:
  - name: auth-mapper
    config:
      client_id_header: "x-app-id"
      client_secret_header: "x-app-secret"
      concat_glue: ":"
      auth_mappings_json: |
        {
          "legacy-id:legacy-pass": {
            "client_id": "modern-client-id",
            "client_secret": "modern-client-secret"
          }
        }
```

### Custom Separator

```yaml
plugins:
  - name: auth-mapper
    config:
      client_id_header: "client_id"
      client_secret_header: "client_secret"
      concat_glue: "|"  # Use pipe instead of colon
      cache_enabled: true
      cache_ttl: 300
      auth_mappings_json: |
        {
          "user|pass": {
            "client_id": "mapped-user",
            "client_secret": "mapped-pass"
          }
        }
```

### Caching Configuration

```yaml
plugins:
  - name: auth-mapper
    config:
      # Enable caching with 10-minute TTL
      cache_enabled: true
      cache_ttl: 600
      auth_mappings_json: "{vault://env/auth-mappings}"
```

### Disable Caching

```yaml
plugins:
  - name: auth-mapper
    config:
      # Disable caching for debugging or low-traffic scenarios
      cache_enabled: false
      auth_mappings_json: |
        {
          "debug:mode": {
            "client_id": "debug-client-id",
            "client_secret": "debug-client-secret"
          }
        }
```

## Vault Integration

The plugin supports Kong Vault references for secure credential storage. With the JSON approach, you can store the entire credential mapping in a vault, providing complete security for all sensitive data including lookup keys.

### Environment Variable Vault

```yaml
plugins:
  - name: auth-mapper
    config:
      client_id_header: "client_id"
      client_secret_header: "client_secret"
      concat_glue: ":"
      auth_mappings_json: "{vault://env/auth-mappings}"
```

### Environment Setup for Vault

Set the entire JSON mapping as an environment variable before starting Kong:

```bash
export AUTH_MAPPINGS='{
  "acme:s3cr3t": {
    "client_id": "your-actual-client-id",
    "client_secret": "your-actual-client-secret"
  },
  "other:creds": {
    "client_id": "another-client-id",
    "client_secret": "another-client-secret"
  }
}'
```

### Kong Configuration with Vault

Enable the environment vault in your Kong configuration:

```yaml
_format_version: "3.0"
_transform: true

services:
  - name: example-service
    url: https://api.example.com
    routes:
      - name: example-route
        paths: ["/api"]

plugins:
  - name: auth-mapper
    config:
      auth_mappings_json: "{vault://env/auth-mappings}"
```

Kong configuration:
```bash
export KONG_VAULTS=env  # Enable environment variable vault
```

### Multiple Vault References

You can use different vault references for different routes:

```yaml
# Route 1: Production mappings
plugins:
  - name: auth-mapper
    route: production-route
    config:
      auth_mappings_json: "{vault://env/prod-auth-mappings}"

# Route 2: Staging mappings
plugins:
  - name: auth-mapper
    route: staging-route
    config:
      auth_mappings_json: "{vault://env/staging-auth-mappings}"
```

## Behavior

### Header Processing

- **Missing Headers**: If either client ID or secret header is missing, the plugin skips processing
- **Empty Values**: Empty strings or whitespace-only values are treated as missing
- **Multiple Values**: If a header has multiple values, the first value is used
- **Whitespace**: Leading and trailing whitespace is automatically trimmed

### Credential Resolution

1. **JSON Parsing**: Parses the `auth_mappings_json` string into a lookup dictionary
2. **Mapping Found**: Uses the mapped credentials from the parsed JSON
3. **No Mapping**: Falls back to the original incoming credentials
4. **Invalid JSON**: Falls back to original credentials and logs an error

### Authorization Header

The plugin generates a Basic Authorization header in the format:
```
Authorization: Basic <base64(client_id:client_secret)>
```

The authorization header is set on the service request, making it available to downstream plugins and the upstream service.

## Request Flow Example

### Input Request
```http
GET /api/data HTTP/1.1
Host: api.example.com
client_id: acme
client_secret: s3cr3t
```

### With Mapping Configuration
```yaml
auth_mappings_json: |
  {
    "acme:s3cr3t": {
      "client_id": "azure-app-123",
      "client_secret": "azure-secret-456"
    }
  }
```

### Resulting Upstream Request
```http
GET /api/data HTTP/1.1
Host: api.example.com
client_id: acme
client_secret: s3cr3t
Authorization: Basic YXp1cmUtYXBwLTEyMzphenVyZS1zZWNyZXQtNDU2
```

## Performance and Caching

### Cache Behavior

The plugin uses Kong's built-in caching system to store resolved credentials:

- **Cache Key Format**: `auth-mapper:creds:{client_id}{glue}{client_secret}`
- **Cache Hit**: Returns cached credentials immediately without parsing JSON
- **Cache Miss**: Parses JSON, resolves vault references, and caches the result
- **TTL Management**: Cached entries expire after the configured `cache_ttl` seconds
- **Memory Efficient**: Uses Kong's LRU cache implementation

### Cache Benefits

1. **Performance**: Subsequent requests with the same credentials are processed faster
2. **JSON Parsing Efficiency**: Reduces JSON parsing overhead for repeated credentials
3. **Vault Efficiency**: Reduces vault reference resolution calls
4. **Scalability**: Handles high-traffic scenarios with repeated credential patterns

### Cache Considerations

- **Memory Usage**: Cached credentials consume memory proportional to unique credential combinations
- **Security**: Credentials are cached in memory only (not persisted to disk)
- **Consistency**: Cache invalidation happens automatically after TTL expiry
- **JSON Size**: Large JSON mappings may impact parsing performance on cache misses

## Use Cases

### Azure Entra ID Integration
Map legacy application credentials to Azure Entra ID application credentials:

```bash
export AZURE_MAPPINGS='{
  "legacy-app:legacy-pass": {
    "client_id": "12345678-1234-1234-1234-123456789abc",
    "client_secret": "your-azure-app-secret"
  }
}'
```

```yaml
auth_mappings_json: "{vault://env/azure-mappings}"
```

### Multi-Tenant Applications
Route different client applications to their respective backend credentials:

```bash
export TENANT_MAPPINGS='{
  "tenant-a:key123": {
    "client_id": "tenant-a-backend-id",
    "client_secret": "tenant-a-secret"
  },
  "tenant-b:key456": {
    "client_id": "tenant-b-backend-id",
    "client_secret": "tenant-b-secret"
  }
}'
```

### API Gateway Credential Translation
Transform API keys to OAuth client credentials:

```bash
export API_MAPPINGS='{
  "api-key-123:shared-secret": {
    "client_id": "oauth-client-for-api-123",
    "client_secret": "oauth-secret-123"
  }
}'
```

## Security Considerations

1. **Use Vault References**: Always use Kong Vault references for sensitive credential mappings in production
2. **Environment Variables**: Ensure environment variables containing JSON mappings are properly secured
3. **Logging**: The plugin logs JSON parsing errors - avoid enabling debug logging in production
4. **Original Headers**: Original client headers remain in the request and are passed to upstream services
5. **Complete Encryption**: The JSON approach allows encrypting all sensitive data including lookup keys

## Plugin Priority

The plugin runs with priority `1060`, which places it before the OIDC plugin (priority 1000) in Kong's execution order. This ensures that the Basic Authorization header is available for subsequent authentication plugins.

## Error Handling

The plugin is designed to be non-breaking:
- Missing or invalid input headers result in skipped processing, not request failures
- Invalid JSON results in fallback to original credentials with error logging
- Missing vault references will cause Kong startup failures (fail-fast behavior)
- Malformed JSON gracefully falls back to original credentials

## Testing

The plugin includes comprehensive test suites:

- **Unit Tests**: Test core functionality, JSON parsing, and edge cases
- **Integration Tests**: Test real Kong request processing with JSON mappings
- **Vault Integration Tests**: Test vault reference resolution for complete JSON mappings
- **Schema Tests**: Validate configuration schema and JSON string requirements

Run tests with:
```bash
busted spec/auth-mapper/
```

## Compatibility

- Kong Gateway 3.0+
- Supports all Kong deployment strategies (postgres, off/declarative)
- Compatible with Kong's vault system
- Requires `cjson` library (included with Kong)

## License

This plugin follows Kong's plugin development guidelines and is compatible with Kong Gateway's plugin architecture.
