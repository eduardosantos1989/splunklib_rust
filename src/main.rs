use splunklib_rust::splunk_file_logger::FileLoggerConfig;
use splunklib_rust::splunk_http_sender::IngestMode;
use splunklib_rust::splunk_json_logger::{HttpLogConfig, JsonLogger, JsonLoggerConfig};
use splunklib_rust::{EventMetadata, get_splunk_location};

fn main() {
    let log_path = match get_splunk_location() {
        Ok(loc) => loc
            .root
            .join("var")
            .join("log")
            .join("splunk")
            .join("my_rust_app.log"),
        Err(_) => std::env::temp_dir().join("splunklib_rust_demo.log"),
    };

    let file = FileLoggerConfig::new(&log_path)
        .with_rotate_size_bytes(Some(3 * 1024 * 1024))
        .with_max_rotate_files(1)
        .with_auto_flush_interval(Some(std::time::Duration::from_secs(5)));

    let config = match std::env::var("SPLUNK_LOG_URL") {
        Ok(url) if !url.is_empty() => {
            let mode = std::env::var("SPLUNK_LOG_INGEST")
                .ok()
                .as_deref()
                .and_then(IngestMode::parse)
                .unwrap_or(IngestMode::Custom);
            let mut http = HttpLogConfig::new(url, mode).with_metadata(EventMetadata::new(
                "main",
                "splunklib_rust",
                "_json",
                "localhost",
            ));
            if let Ok(token) = std::env::var("SPLUNK_HEC_TOKEN")
                && !token.is_empty()
            {
                http = http.with_token(token);
            }
            JsonLoggerConfig::http_with_file_fallback(http, file)
        }
        _ => JsonLoggerConfig::file_only(file),
    };

    let logger = JsonLogger::new(config).expect("json logger");
    for i in 0..10 {
        logger
            .info(format!("Hello, Splunk! This is log message #{i}"))
            .expect("log");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    logger.flush().expect("flush");
}
