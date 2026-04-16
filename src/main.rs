use splunklib_rust::get_splunk_location;
use splunklib_rust::splunk_file_logger::{FileLogger, FileLoggerConfig};

fn main() {
    let splunklo: Result<get_splunk_location::SplunkLocation, std::io::Error> =
        get_splunk_location::get_splunk_location();
    let root = splunklo.unwrap().root;

    let filelogger = FileLogger::new(
        FileLoggerConfig::new(root.join("splunkton/var/log/splunk/my_rust_app.log"))
            .with_rotate_size_bytes(Some(3 * 1024 * 1024)) // 3 MB
            .with_max_rotate_files(1)
            .with_auto_flush_interval(Some(std::time::Duration::from_secs(5))),
    )
    .unwrap();

    for i in 0..10 {
        filelogger
            .log(format!("Hello, Splunk! This is log message #{}", i))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    filelogger.flush().unwrap();
}
