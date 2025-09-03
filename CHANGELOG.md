# Changelog

All notable changes to the Kong Auth Mapper Plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-09-03

### Added

#### Header Security Enhancement
- **Strip Original Headers**: New `strip_original_headers` configuration option to remove original client credential headers from upstream requests
- **Enhanced Security**: Prevents sensitive original credentials from reaching upstream services after credential mapping
- **Flexible Control**: Optional feature with default `false` to maintain backward compatibility

#### Documentation
- **Updated README**: Complete documentation for header stripping feature with examples
- **Request Flow Examples**: Before/after examples showing header removal behavior

### Technical Details

#### Schema Changes
- Added `strip_original_headers` boolean field with default `false`
- Maintains full backward compatibility with existing configurations
- Works with all existing match modes and configuration options

#### Handler Changes
- Added header removal logic using `kong.service.request.clear_header()`
- Header stripping occurs after Authorization header generation
- Applies to both `client_id_header` and `client_secret_header` regardless of match mode

## [0.2.0] - 2025-09-02

### Added

#### Flexible Matching Modes
- **Client ID Only Mode**: New `client_id_only` matching mode that uses only the client ID for credential lookup
- **Match Mode Configuration**: New `match_mode` parameter supporting `both` (default) and `client_id_only` options
- **Backward Compatibility**: Default `both` mode maintains full compatibility with existing configurations

#### Documentation
- **Updated README**: Complete documentation for both matching modes with examples
- **Configuration Guide**: Clear guidance on when to use each matching mode
- **Request Flow Examples**: Before/after examples showing behavior differences

### Technical Details

#### Schema Changes
- Added `match_mode` field with `one_of` validation
- Maintains all existing field defaults and validation rules
- Full backward compatibility with existing configurations


## [0.1.0] - 2025-09-02

### Added

#### Core Features
- **Credential Mapping**: Transform incoming client credentials to different credentials based on configurable JSON mappings
- **Basic Authorization Generation**: Automatically generates and injects Basic Authorization headers for downstream services
- **Flexible Header Configuration**: Configure custom header names for client ID and secret extraction
- **Custom Separator Support**: Configure the glue character used to concatenate credentials for lookup keys

#### Security & Vault Integration
- **Kong Vault Integration**: Full support for Kong Vault references to securely store credential mappings
- **Complete JSON Vault Support**: Store entire credential mapping JSON in vault for maximum security
- **Environment Variable Vault**: Support for environment variable vault backend
- **Sensitive Data Protection**: All credential mappings can be stored securely outside of Kong configuration

#### Performance & Caching
- **Built-in LRU Caching**: Performance caching for resolved credentials using Kong's cache system
- **Configurable Cache TTL**: Adjustable time-to-live for cached credential mappings
- **Cache Enable/Disable**: Option to disable caching for debugging or low-traffic scenarios
- **Memory Efficient**: Uses Kong's built-in cache implementation for optimal resource usage

#### Configuration Options
- `client_id_header`: Configurable header name for client ID (default: "client_id")
- `client_secret_header`: Configurable header name for client secret (default: "client_secret")
- `concat_glue`: Configurable separator for credential concatenation (default: ":")
- `auth_mappings_json`: JSON string mapping input credentials to output credentials (required)
- `cache_enabled`: Enable/disable credential caching (default: true)
- `cache_ttl`: Cache time-to-live in seconds (default: 300)

#### Robust Error Handling
- **Graceful Fallback**: Uses original credentials when no mapping is found
- **JSON Parsing Protection**: Handles malformed JSON gracefully with fallback behavior
- **Missing Header Handling**: Skips processing when required headers are missing
- **Non-breaking Design**: Plugin failures do not break request processing
- **Comprehensive Logging**: Debug and error logging for troubleshooting

#### Request Processing Features
- **Header Value Trimming**: Automatic whitespace trimming from header values
- **Multi-value Header Support**: Uses first value when headers contain multiple values
- **Empty Value Detection**: Treats empty strings and whitespace-only values as missing
- **Null Value Handling**: Properly handles JSON null values in credential mappings

#### Schema Validation
- **Configuration Validation**: Comprehensive schema validation for all plugin parameters
- **Header Name Uniqueness**: Prevents identical client_id_header and client_secret_header
- **Required Field Enforcement**: Ensures all required configuration fields are provided
- **JSON String Validation**: Validates that auth_mappings_json is a non-empty string
- **Vault Reference Support**: Schema support for vault reference strings

#### Testing & Quality Assurance
- **Comprehensive Test Suite**: Full unit, integration, and vault integration tests
- **Schema Testing**: Complete configuration schema validation tests
- **Caching Tests**: Thorough testing of cache functionality and performance
- **Error Condition Testing**: Tests for all error handling scenarios
- **Multi-strategy Database Support**: Tests for PostgreSQL and off/declarative modes

### Technical Details

#### Plugin Architecture
- **Priority**: 1060 (runs before OIDC plugin at priority 1000)
- **Version**: 0.1.0
- **Kong Compatibility**: Kong Gateway 3.0+
- **Database Support**: PostgreSQL, off/declarative (LMDB)
- **Deployment Support**: All Kong deployment strategies

#### Dependencies
- Kong Gateway 3.0 or higher
- `cjson` library (included with Kong)
- Kong Vault system (for vault integration)

#### Performance Characteristics
- Minimal overhead for cached credential lookups
- JSON parsing only on cache misses or when caching disabled
- Efficient Base64 encoding for Authorization header generation
- Memory-efficient caching using Kong's LRU implementation

### Use Cases Supported

#### Identity Provider Integration
- **Azure Entra ID**: Map legacy credentials to Azure application credentials
- **OAuth Systems**: Transform API keys to OAuth client credentials
- **Multi-tenant Applications**: Route different clients to respective backend credentials

#### Enterprise Scenarios
- **Legacy System Integration**: Bridge old authentication systems with modern ones
- **Credential Centralization**: Centralize credential management through Kong
- **Security Compliance**: Secure credential storage through vault integration
- **Performance Optimization**: Cache frequently used credential mappings

### Breaking Changes
- None (initial release)

### Migration Guide
- Not applicable (initial release)

### Known Limitations
- Requires manual JSON mapping configuration (no dynamic discovery)
- Cache invalidation requires TTL expiry (no manual invalidation API)
- Original client headers remain in request (not removed by default)

### Security Notes
- All sensitive credential mappings should use Kong Vault references in production
- Original client headers are preserved and passed to upstream services
- JSON parsing errors are logged (avoid debug logging in production with sensitive data)
- Complete credential security achieved through vault integration

---

**Note**: This changelog documents all releases of the Kong Auth Mapper Plugin following semantic versioning.
