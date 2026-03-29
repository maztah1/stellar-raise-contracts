# Rate Limiting Smart Contract

## Overview

The `RateLimiting` smart contract provides DoS protection through configurable rate limiting. It enforces per-address request limits within sliding time windows, preventing rapid-fire transaction attacks and resource exhaustion.

## Features

- **Per-Address Rate Limiting**: Independent limits for each address
- **Configurable Limits**: Adjustable max requests and time windows
- **Sliding Windows**: Time-based window management
- **Safe Arithmetic**: Overflow/underflow protection with saturating operations
- **State Management**: Efficient storage of rate limit states
- **Query Functions**: Check remaining requests and reset times

## Constants

```rust
// Default configuration
pub const DEFAULT_MAX_REQUESTS: u32 = 10;      // 10 requests per window
pub const DEFAULT_WINDOW_SECONDS: u64 = 60;    // 60 second window

// Validation bounds
pub const MIN_WINDOW_SECONDS: u64 = 1;         // Minimum 1 second
pub const MAX_WINDOW_SECONDS: u64 = 86_400;    // Maximum 1 day
pub const MIN_MAX_REQUESTS: u32 = 1;           // Minimum 1 request
pub const MAX_MAX_REQUESTS: u32 = 1_000;       // Maximum 1000 requests
```

## Data Structures

### RateLimit

Configuration for rate limiting:

```rust
pub struct RateLimit {
    pub max_requests: u32,      // Maximum requests per window
    pub window_seconds: u64,    // Time window in seconds
}
```

### RateLimitState

Per-address rate limit state:

```rust
pub struct RateLimitState {
    pub request_count: u32,     // Requests in current window
    pub window_start: u64,      // Window start timestamp
}
```

## Functions

### init(env: Env)

Initialize rate limiting with default configuration.

```rust
RateLimitingContract::init(env);
```

**Default Configuration**:
- Max Requests: 10
- Window: 60 seconds

### set_rate_limit(env: Env, max_requests: u32, window_seconds: u64)

Set custom rate limit configuration.

```rust
RateLimitingContract::set_rate_limit(env, 20, 120);
```

**Parameters**:
- `max_requests`: 1-1000 requests per window
- `window_seconds`: 1-86400 seconds

**Panics**:
- If `max_requests` outside valid range
- If `window_seconds` outside valid range

### get_rate_limit(env: Env) -> RateLimit

Get current rate limit configuration.

```rust
let config = RateLimitingContract::get_rate_limit(env);
println!("Max: {}, Window: {}", config.max_requests, config.window_seconds);
```

### check_rate_limit(env: Env, address: Address) -> bool

Check if address is within rate limit and increment counter.

```rust
if RateLimitingContract::check_rate_limit(env, address) {
    // Request allowed
} else {
    // Rate limit exceeded
}
```

**Returns**:
- `true` if request is allowed
- `false` if rate limit exceeded

**Side Effects**:
- Increments request counter
- Resets window if expired

### get_remaining_requests(env: Env, address: Address) -> u32

Get remaining requests for address in current window.

```rust
let remaining = RateLimitingContract::get_remaining_requests(env, address);
println!("Remaining requests: {}", remaining);
```

**Returns**:
- Number of remaining requests (0 if limit exceeded)

### get_reset_time(env: Env, address: Address) -> u64

Get seconds until rate limit window resets.

```rust
let reset_seconds = RateLimitingContract::get_reset_time(env, address);
println!("Reset in {} seconds", reset_seconds);
```

**Returns**:
- Seconds until window resets (0 if already reset)

### reset_rate_limit(env: Env, address: Address)

Reset rate limit for specific address.

```rust
RateLimitingContract::reset_rate_limit(env, address);
```

**Effect**:
- Clears rate limit state for address
- Restores full request quota

### clear_all_rate_limits(env: Env)

Clear all rate limit states.

```rust
RateLimitingContract::clear_all_rate_limits(env);
```

**Note**: In production, restrict to admin only.

## Usage Examples

### Basic Rate Limiting

```rust
// Initialize with defaults (10 requests per 60 seconds)
RateLimitingContract::init(env.clone());

let address = Address::random(&env);

// Check rate limit
if RateLimitingContract::check_rate_limit(env.clone(), address.clone()) {
    // Process request
} else {
    // Return error: rate limit exceeded
}
```

### Custom Configuration

```rust
// Set custom limits: 50 requests per 5 minutes
RateLimitingContract::init(env.clone());
RateLimitingContract::set_rate_limit(env.clone(), 50, 300);

let address = Address::random(&env);

// Check remaining requests
let remaining = RateLimitingContract::get_remaining_requests(env.clone(), address.clone());
println!("Remaining: {}", remaining);

// Get reset time
let reset_time = RateLimitingContract::get_reset_time(env.clone(), address.clone());
println!("Reset in {} seconds", reset_time);
```

### Rate Limit Recovery

```rust
// Check if rate limited
if !RateLimitingContract::check_rate_limit(env.clone(), address.clone()) {
    // Get reset time
    let reset_time = RateLimitingContract::get_reset_time(env.clone(), address.clone());
    
    if reset_time == 0 {
        // Window expired, try again
        RateLimitingContract::check_rate_limit(env.clone(), address.clone());
    } else {
        // Wait and retry
        println!("Please wait {} seconds", reset_time);
    }
}
```

## Security Considerations

### DoS Protection

- **Per-Address Limits**: Prevents single address from exhausting resources
- **Time Windows**: Sliding windows prevent sustained attacks
- **Configurable Limits**: Adjust based on network conditions

### Arithmetic Safety

- **Saturating Operations**: Prevents overflow/underflow panics
- **Validated Inputs**: Configuration bounds prevent invalid states
- **Safe State Transitions**: Atomic updates prevent inconsistencies

### Storage Efficiency

- **Per-Address State**: Only stores active rate limit states
- **Lazy Initialization**: States created on first request
- **Window Expiration**: Automatic cleanup on window reset

## Performance Characteristics

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| `init` | O(1) | Single storage write |
| `set_rate_limit` | O(1) | Single storage write |
| `get_rate_limit` | O(1) | Single storage read |
| `check_rate_limit` | O(1) | Storage read/write |
| `get_remaining_requests` | O(1) | Storage read |
| `get_reset_time` | O(1) | Storage read |
| `reset_rate_limit` | O(1) | Storage delete |

## Testing

The contract includes 31 comprehensive test cases covering:

- **Initialization**: Default configuration setup
- **Configuration**: Valid/invalid parameter validation
- **Rate Limit Checking**: Request allowance and denial
- **Remaining Requests**: Quota tracking
- **Reset Time**: Window expiration calculation
- **Reset Functionality**: State clearing
- **Multiple Addresses**: Independent limit enforcement
- **Edge Cases**: Boundary conditions and overflow handling
- **Persistence**: Configuration durability

Test coverage: **≥ 95%**

## Integration with Crowdfund Contract

### Protect Contribute Function

```rust
pub fn contribute(env: Env, contributor: Address, amount: i128) {
    // Check rate limit
    if !RateLimitingContract::check_rate_limit(env.clone(), contributor.clone()) {
        panic!("Rate limit exceeded");
    }
    
    // Process contribution
    // ...
}
```

### Protect Withdraw Function

```rust
pub fn withdraw(env: Env, creator: Address) {
    // Check rate limit
    if !RateLimitingContract::check_rate_limit(env.clone(), creator.clone()) {
        panic!("Rate limit exceeded");
    }
    
    // Process withdrawal
    // ...
}
```

### Protect Refund Function

```rust
pub fn refund_single(env: Env, contributor: Address) {
    // Check rate limit
    if !RateLimitingContract::check_rate_limit(env.clone(), contributor.clone()) {
        panic!("Rate limit exceeded");
    }
    
    // Process refund
    // ...
}
```

## Configuration Recommendations

### Conservative (High Security)

```rust
// 5 requests per 60 seconds
RateLimitingContract::set_rate_limit(env, 5, 60);
```

**Use Case**: High-value transactions, sensitive operations

### Moderate (Balanced)

```rust
// 20 requests per 60 seconds
RateLimitingContract::set_rate_limit(env, 20, 60);
```

**Use Case**: Standard crowdfunding operations

### Permissive (High Throughput)

```rust
// 100 requests per 60 seconds
RateLimitingContract::set_rate_limit(env, 100, 60);
```

**Use Case**: High-volume operations, public endpoints

## Troubleshooting

### Rate Limit Exceeded

**Problem**: Getting "rate limit exceeded" errors

**Solution**:
1. Check remaining requests: `get_remaining_requests()`
2. Check reset time: `get_reset_time()`
3. Wait for window to expire or request reset

### Configuration Not Applied

**Problem**: Custom configuration not taking effect

**Solution**:
1. Verify `set_rate_limit()` was called
2. Check configuration with `get_rate_limit()`
3. Ensure no initialization after configuration

### Unexpected Resets

**Problem**: Rate limit resets unexpectedly

**Solution**:
1. Check window duration configuration
2. Verify ledger timestamp is advancing
3. Review reset_rate_limit() calls

## Related Components

- `RateLimitingContract`: Core rate limiting implementation
- `CrowdfundContract`: Integration with crowdfunding operations
- `SecurityMonitoring`: Security event tracking

## License

This contract is part of the Stellar Raise Contracts project and is licensed under the MIT License.
