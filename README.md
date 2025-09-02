# Kong Auth Mapper Plugin

A Kong plugin that maps incoming client credentials to different credentials and injects a Basic Authorization header for downstream services. This plugin is particularly useful for integrating with identity providers like Azure Entra ID or other OAuth systems that require specific client credentials.

## Features

- **Credential Mapping**: Transform incoming client credentials to different credentials based on configurable JSON mappings
- **Flexible Matching Modes**: Support both full credential matching (`both`) and client ID-only matching (`client_id_only`)
- **Vault Integration**: Support for Kong Vault references to securely store sensitive credential mappings
- **Performance Caching**: Built-in LRU caching for resolved credentials to improve performance
- **Flexible Headers**: Configure custom header names for client ID and secret
- **Custom Separators**: Configure the glue character used to concatenate credentials for lookup
- **Fallback Behavior**: Uses original credentials when no mapping is found
- **Basic Auth Generation**: Automatically generates and injects Basic Authorization headers

## How It Works

1. The plugin reads client credentials from configurable request headers
2. Based on the matching mode, creates a lookup key:
   - **Both mode**: Concatenates client_id and client_secret using a configurable glue character
   - **Client ID only mode**: Uses only the client_id for lookup
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
| `concat_glue` | string | `":"` | No | Character(s) used to concatenate client_id and client_secret for lookup (ignored in client_id_only mode) |
| `match_mode` | string | `"both"` | No | Matching mode: `"both"` (client_id + client_secret) or `"client_id_only"` |
| `auth_mappings_json` | string | - | Yes | JSON string mapping input credentials to output credentials |
| `cache_enabled` | boolean | `true` | No | Enable caching of resolved credentials |
| `cache_ttl` | number | `300` | No | Cache TTL in seconds (must be > 0) |

### Matching Modes

#### Both Mode (Default)
Uses both client_id and client_secret for credential lookup. This is the original behavior and provides enhanced security by requiring both credentials to match.

**Lookup Key Format**: `client_id + concat_glue + client_secret`

#### Client ID Only Mode
Uses only the client_id for credential lookup, ignoring the client_secret in the mapping process. This is useful for scenarios where the client_id is stable but the client_secret may vary across environments or change frequently.

**Lookup Key Format**: `client_id` (concat_glue is ignored)

**Note**: Both client_id and client_secret headers are still required in both modes for Basic Authorization header generation.

### Auth Mappings JSON Structure

The `auth_mappings_json` structure varies based on the matching mode:

#### Both Mode JSON Structure
```json
{
  "input_id:input_secret": {
    "client_id": "mapped_id",
    "client_secret": "mapped_secret"
  }
}
```

#### Client ID Only Mode JSON Structure
```json
{
  "input_id": {
    "client_id": "mapped_id",
    "client_secret": "mapped_secret"
  }
}
```

## Installation

### Option 1: Using Pre-built Rock File (Recommended for Golden Images)

The easiest way to install the plugin is using the pre-built rock file from the GitHub releases:

1. Download the rock file from the latest release:
   ```bash
   # Replace X.X.X with the desired version
   wget https://github.com/KongHQ-CX/kong-plugin-auth-mapper/releases/download/vX.X.X/kong-plugin-auth-mapper-X.X.X-1.all.rock
   ```

2. Install the rock file:
   ```bash
   luarocks install kong-plugin-auth-mapper-X.X.X-1.all.rock
   ```

3. Add the plugin to your Kong configuration:
   ```bash
   export KONG_PLUGINS=bundled,auth-mapper
   ```

4. Restart Kong

### Option 2: Manual Installation from Source

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

### Docker/Golden Image Installation

For Docker images or golden image builds, you can install the plugin during the image build process:

**Option A: Download during build (requires internet access)**
```dockerfile
FROM kong:3.9.1-ubuntu

USER root
# Download and install the auth-mapper plugin
RUN wget -O /tmp/kong-plugin-auth-mapper-0.1.0-1.all.rock https://github.com/KongHQ-CX/kong-plugin-auth-mapper/releases/download/v0.1.0/kong-plugin-auth-mapper-0.1.0-1.all.rock && \
    /usr/local/bin/luarocks install /tmp/kong-plugin-auth-mapper-0.1.0-1.all.rock && \
    rm /tmp/kong-plugin-auth-mapper-0.1.0-1.all.rock
USER kong

# Set environment variable to enable the plugin
ENV KONG_PLUGINS=bundled,auth-mapper

# Continue with your Docker image configuration...
```

**Option B: Copy pre-downloaded rock file (for air-gapped environments)**
```dockerfile
FROM kong:3.9.1-ubuntu

# Copy the pre-downloaded rock file from build context
COPY kong-plugin-auth-mapper-0.1.0-1.all.rock /tmp/kong-plugin-auth-mapper-0.1.0-1.all.rock

USER root
# Install the plugin and clean up
RUN /usr/local/bin/luarocks install /tmp/kong-plugin-auth-mapper-0.1.0-1.all.rock && \
    rm /tmp/kong-plugin-auth-mapper-0.1.0-1.all.rock
USER kong

# Set environment variable to enable the plugin
ENV KONG_PLUGINS=bundled,auth-mapper

# Continue with your Docker image configuration...
```

For Option B, ensure the rock file is in your Docker build context:
```bash
# Download the rock file locally first
wget https://github.com/KongHQ-CX/kong-plugin-auth-mapper/releases/download/v0.1.0/kong-plugin-auth-mapper-0.1.0-1.all.rock

# Then build your Docker image
docker build -t my-kong-with-auth-mapper .
```

### Verification

After installation, verify the plugin is available:

```bash
kong plugins list | grep auth-mapper
```

Or check if it's loaded in Kong:

```bash
curl -X GET http://localhost:8001/plugins/enabled
```

## Usage Examples

### Both Mode Configuration (Default)

```yaml
plugins:
  - name: auth-mapper
    config:
      client_id_header: "client_id"
      client_secret_header: "client_secret"
      concat_glue: ":"
      match_mode: "both"  # Default mode
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

### Client ID Only Mode Configuration

```yaml
plugins:
  - name: auth-mapper
    config:
      client_id_header: "client_id"
      client_secret_header: "client_secret"
      match_mode: "client_id_only"
      cache_enabled: true
      cache_ttl: 300
      auth_mappings_json: |
        {
          "legacy-app-id": {
            "client_id": "modern-app-id",
            "client_secret": "modern-app-secret"
          },
          "mobile-app-id": {
            "client_id": "mobile-backend-id",
            "client_secret": "mobile-backend-secret"
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
      match_mode: "both"
      auth_mappings_json: |
        {
          "legacy-id:legacy-pass": {
            "client_id": "modern-client-id",
            "client_secret": "modern-client-secret"
          }
        }
```

### Custom Separator (Both Mode Only)

```yaml
plugins:
  - name: auth-mapper
    config:
      client_id_header: "client_id"
      client_secret_header: "client_secret"
      concat_glue: "|"  # Use pipe instead of colon
      match_mode: "both"
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
      match_mode: "client_id_only"
      auth_mappings_json: "{vault://env/auth-mappings}"
```

### Disable Caching

```yaml
plugins:
  - name: auth-mapper
    config:
      # Disable caching for debugging or low-traffic scenarios
      cache_enabled: false
      match_mode: "both"
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
      match_mode: "both"
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
      match_mode: "client_id_only"
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
      match_mode: "both"
      auth_mappings_json: "{vault://env/prod-auth-mappings}"

# Route 2: Staging mappings
plugins:
  - name: auth-mapper
    route: staging-route
    config:
      match_mode: "client_id_only"
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

## Request Flow Examples

### Both Mode Example

#### Input Request
```http
GET /api/data HTTP/1.1
Host: api.example.com
client_id: acme
client_secret: s3cr3t
```

#### With Both Mode Configuration
```yaml
match_mode: "both"
auth_mappings_json: |
  {
    "acme:s3cr3t": {
      "client_id": "azure-app-123",
      "client_secret": "azure-secret-456"
    }
  }
```

#### Resulting Upstream Request
```http
GET /api/data HTTP/1.1
Host: api.example.com
client_id: acme
client_secret: s3cr3t
Authorization: Basic YXp1cmUtYXBwLTEyMzphenVyZS1zZWNyZXQtNDU2
```

### Client ID Only Mode Example

#### Input Request
```http
GET /api/data HTTP/1.1
Host: api.example.com
client_id: mobile-app
client_secret: dev-secret-123
```

#### With Client ID Only Mode Configuration
```yaml
match_mode: "client_id_only"
auth_mappings_json: |
  {
    "mobile-app": {
      "client_id": "backend-service-id",
      "client_secret": "backend-service-secret"
    }
  }
```

#### Resulting Upstream Request
```http
GET /api/data HTTP/1.1
Host: api.example.com
client_id: mobile-app
client_secret: dev-secret-123
Authorization: Basic YmFja2VuZC1zZXJ2aWNlLWlkOmJhY2tlbmQtc2VydmljZS1zZWNyZXQ=
```

**Note**: In client_id_only mode, the client_secret (`dev-secret-123`) is ignored for mapping lookup, but the mapped credentials (`backend-service-id:backend-service-secret`) are used for the Authorization header.

## Performance and Caching

### Cache Behavior

The plugin uses Kong's built-in caching system to store resolved credentials:

- **Cache Key Format**:
  - Both mode: `auth-mapper:both:{client_id}{glue}{client_secret}`
  - Client ID only mode: `auth-mapper:client_id_only:{client_id}`
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
- **Mode Separation**: Different cache keys prevent conflicts between matching modes

## Use Cases

### Both Mode Use Cases

#### Azure Entra ID Integration
Map legacy application credentials to Azure Entra ID application credentials:

```bash
export AZURE_MAPPINGS='{
  "legacy-app:legacy-pass": {
    "client_id": "12345678-1234-1234-1234-123456789abc",
    "client_secret": "your-azure-app-secret"
  }
}'
```

#### Multi-Tenant Applications
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

### Client ID Only Mode Use Cases

#### Multi-Environment Applications
Same client application across different environments with varying secrets:

```bash
export APP_MAPPINGS='{
  "mobile-app": {
    "client_id": "mobile-backend-prod-id",
    "client_secret": "mobile-backend-prod-secret"
  },
  "web-app": {
    "client_id": "web-backend-prod-id",
    "client_secret": "web-backend-prod-secret"
  }
}'
```

#### Legacy System Integration
When only client IDs are stable across system migrations:

```bash
export LEGACY_MAPPINGS='{
  "legacy-system-1": {
    "client_id": "modern-service-1-id",
    "client_secret": "modern-service-1-secret"
  },
  "legacy-system-2": {
    "client_id": "modern-service-2-id",
    "client_secret": "modern-service-2-secret"
  }
}'
```

#### API Gateway Credential Translation
Transform API keys to OAuth client credentials:

```bash
export API_MAPPINGS='{
  "api-key-123": {
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
6. **Header Requirements**: Both client_id and client_secret headers are required regardless of matching mode

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

- **Unit Tests**: Test core functionality, JSON parsing, and edge cases for both matching modes
- **Integration Tests**: Test real Kong request processing with JSON mappings in both modes
- **Vault Integration Tests**: Test vault reference resolution for complete JSON mappings
- **Schema Tests**: Validate configuration schema and JSON string requirements
- **Caching Tests**: Validate cache behavior for both matching modes

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
