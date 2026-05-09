# splunklib_rust

A high-performance Rust library for integrating with Splunk, providing utilities for file logging, configuration processing, and HTTP event collection.

## Overview

`splunklib_rust` is a comprehensive Rust library for Splunk integration, designed for use in Splunk apps and external applications. It provides:

- **Splunk Location Detection**: Automatically discover Splunk installation paths
- **Configuration Processing**: Parse and cache Splunk .conf files with full spec support
- **File Logger**: High-performance, thread-safe logging with rotation and batching
- **HTTP Event Sender**: Send events to Splunk HEC with gzip compression and batching

## Features

- 🚀 **High Performance**: Asynchronous I/O, connection pooling, zero-copy optimizations
- 🔒 **Thread-Safe**: All components are safe for concurrent access
- 📝 **Splunk-Native**: Matches Splunk's configuration format and behavior
- 🎯 **Type-Safe**: Rust's type system ensures compile-time correctness
- 🔧 **Configurable**: Extensive options for logging, compression, timeouts, etc.
- 📊 **Observable**: Built-in statistics and debug logging

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
splunklib_rust = "0.2.0"
```

## Modules

### [`get_splunk_hostname`](lib/get_splunk_hostname.rs)

Retrieve hostnames from Splunk configuration or system.

```rust
use splunklib_rust::get_splunk_hostname;
use std::path::Path;

// Get hostname from Splunk config or system
let hostname = get_splunk_hostname(Path::new("/opt/splunk"));
println!("Hostname: {}", hostname);
```

### [`get_splunk_location`](lib/get_splunk_location.rs)

Detect Splunk installation directory structure.

```rust
use splunklib_rust::get_splunk_location;

match get_splunk_location() {
    Ok(loc) => {
        println!("Root: {:?}", loc.root);
        println!("App: {:?}", loc.app);
        println!("Bin: {:?}", loc.bin);
    }
    Err(e) => eprintln!("Failed to detect: {}", e),
}
```

### [`splunk_file_locator`](lib/splunk_file_locator.rs)

Recursively search for files in Splunk directories.

```rust
use splunklib_rust::splunk_file_locator;

let files = splunk_file_locator::find_files_default(
    "/opt/splunk",
    "inputs.conf"
).expect("Search failed");

for file in files {
    println!("Found: {:?}", file);
}
```

### [`splunk_config_processor`](lib/splunk_config_processor.rs)

Parse and cache Splunk configuration files.

```rust
use splunklib_rust::splunk_config_processor;

// Parse multiple files with merge semantics
let files = vec![
    "/opt/splunk/etc/system/default/inputs.conf",
    "/opt/splunk/etc/system/local/inputs.conf",
];

let config = splunk_config_processor::read_configs(&files);

// Access values
if let Some(default_stanza) = config.get("default") {
    if let Some(host) = default_stanza.get("host") {
        println!("Host: {}", host);
    }
}
```

#### Configuration Features

- **Stanza-based parsing**: `[stanza_name]` sections
- **Key-value pairs**: `key = value`
- **Multiline values**: Continue with backslash (`\`)
- **Comments**: Lines starting with `#` or `;`
- **LRU caching**: Configurable cache size (default: 50MB)
- **Merge semantics**: Earlier files override later ones (like Splunk)

#### Cache Management

```rust
use splunklib_rust::splunk_config_processor;

// Set cache size to 100MB
splunk_config_processor::set_cache_size_mb(100);

// Get cache statistics
let stats = splunk_config_processor::get_cache_stats();
println!("Cache hits: {}, misses: {}", stats.hits, stats.misses);

// Clear cache
splunk_config_processor::clear_cache();
```

### [`splunk_file_logger`](lib/splunk_file_logger.rs)

Thread-safe file logger with rotation and batching.

```rust
use splunklib_rust::splunk_file_logger::{FileLogger, FileLoggerConfig};
use std::time::Duration;

let config = FileLoggerConfig::new("/var/log/myapp.log")
    .with_rotate_size_bytes(Some(10 * 1024 * 1024)) // 10MB
    .with_max_rotate_files(5)
    .with_auto_flush_interval(Some(Duration::from_secs(5)))
    .with_queue_capacity(Some(1024));

let logger = FileLogger::new(config)?;

// Log messages
logger.log("Hello, world!")?;

// Batch log
let messages = vec!["First", "Second", "Third"];
logger.log_batch(messages)?;

// Flush and shutdown
logger.flush()?;
logger.shutdown()?;
```

#### File Logger Features

- **Asynchronous writes**: Non-blocking logging via worker thread
- **File rotation**: Automatic rotation by size with configurable history
- **Auto-flush**: Periodic flush to ensure data durability
- **Session tracking**: Session ID prefix on each log entry
- **Bounded queue**: Backpressure to prevent memory exhaustion
- **Statistics**: Track bytes written, flush count, uptime, etc.

#### Log Entry Format

```
time=<epoch>, sid=<session_id>, <your_message>
```

Example:
```
time=1735032800, sid=123456789, Application started successfully
```

### [`splunk_http_sender`](lib/splunk_http_sender.rs)

Send events to Splunk HTTP Event Collector (HEC).

```rust
use splunklib_rust::splunk_http_sender::{HttpEventSender, EventMetadata};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create sender
    let sender = HttpEventSender::new(
        "https://splunk:8088/services/collector/event",
        true // verify SSL
    )?;

    // Set metadata
    let metadata = EventMetadata::new(
        "main",        // index
        "myapp",       // source
        "json",        // sourcetype
        "localhost"     // host
    );

    // Send events
    let events = vec![
        serde_json::json!({"message": "First event"}),
        serde_json::json!({"message": "Second event"}),
    ];

    let (status, body) = sender.send_events(&metadata, &events).await?;
    println!("Status: {}, Body: {}", status, body);

    Ok(())
}
```

#### HTTP Sender Features

- **Async/await**: Tokio-based async interface
- **Connection pooling**: Efficient reuse of HTTP connections
- **Gzip compression**: Automatic compression for large payloads
- **Batch processing**: Automatic chunking for large event batches
- **Debug logging**: Configurable logging of requests, headers, payloads
- **Custom headers**: Add authentication or other headers easily
- **Metadata support**: Index, source, sourcetype, host as query params

#### Builder Pattern

```rust
use splunklib_rust::splunk_http_sender::HttpEventSenderBuilder;
use std::time::Duration;

let sender = HttpEventSenderBuilder::new(
        "https://splunk:8088/services/collector/event"
    )
    .verify_ssl(true)
    .connect_timeout(Duration::from_secs(10))
    .request_timeout(Duration::from_secs(30))
    .enable_gzip(true, 1024) // Enable gzip for payloads >= 1024 bytes
    .build()
    .await?;
```

#### Authentication

```rust
// Add HEC token
sender.add_extra_header(
    "Authorization".to_string(),
    "Splunk <your-hec-token>".to_string()
).await;
```

## Error Handling

All components return `Result` types for proper error handling:

```rust
use splunklib_rust::splunk_http_sender::SplunkError;

match sender.send_events(&metadata, &events).await {
    Ok((status, body)) => println!("Success: {}", status),
    Err(SplunkError::HttpError(e)) => eprintln!("HTTP error: {}", e),
    Err(SplunkError::HttpStatus { code, body }) => {
        eprintln!("Splunk returned {}: {}", code, body);
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

## Thread Safety

All components are thread-safe and can be shared across threads:

```rust
use std::sync::Arc;

let logger = Arc::new(FileLogger::new(config)?);

let handles: Vec<_> = (0..10)
    .map(|i| {
        let logger = Arc::clone(&logger);
        std::thread::spawn(move || {
            logger.log(format!("Message from thread {}", i)).unwrap();
        })
    })
    .collect();

for handle in handles {
    handle.join().unwrap();
}
```

## Performance Considerations

### File Logger

- Use [`log_batch`] instead of individual [`log`] calls for high-volume logging
- Pre-allocate [`Vec`] capacity when using iterators
- Tune [`queue_capacity`] based on your production load
- Set [`auto_flush_interval`] for durability vs throughput tradeoff

### HTTP Sender

- Enable gzip for large payloads (>= 1KB)
- Use [`send_events_batched`] for large event sets
- Batch events to reduce HTTP overhead
- Configure appropriate timeouts for your network

### Config Processor

- LRU cache is shared globally across all reads
- Set appropriate cache size for your workload
- Cache statistics can help tune `CACHE_SIZE_MB`

## Examples

See `src/main.rs` for a complete example demonstrating file logger usage.

## Testing

```bash
cargo test
```

