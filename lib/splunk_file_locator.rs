//! File searching utilities for Splunk directories.
//!
//! This module provides recursive file search capabilities for locating files
//! within Splunk directory structures, with control over search depth.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

/// Recursively search for files matching a specific filename.
///
/// Traverses the directory tree starting from `root` and collects all files
/// whose filename exactly matches `target_name`. Search depth is limited to
/// `max_depth` levels (where root = depth 0).
///
/// # Search behavior
///
/// - Does not follow symlinks
/// - Skips directories that cannot be read
/// - Returns empty vector if root doesn't exist or isn't a directory
/// - Returns `NotFound` error if root exists but no matches found
///
/// # Arguments
///
/// * `root` - The directory to start searching from
/// * `target_name` - The filename to search for (full match required)
/// * `max_depth` - Maximum directory depth to search (root = 0)
///
/// # Returns
///
/// `io::Result<Vec<PathBuf>>` - Vector of matching file paths, or error.
///
/// # Examples
///
/// ```rust,no_run
/// use splunklib_rust::splunk_file_locator;
///
/// match splunk_file_locator::find_files("/opt/splunk", "inputs.conf", 6) {
///     Ok(files) => println!("Found {} config files", files.len()),
///     Err(e) => eprintln!("Search failed: {}", e),
/// }
/// ```
pub fn find_files<P, S>(root: P, target_name: S, max_depth: usize) -> io::Result<Vec<PathBuf>>
where
    P: AsRef<Path>,
    S: AsRef<OsStr>,
{
    let root = root.as_ref();

    // If root doesn't exist or isn't a directory, mimic C++ early-return with empty hits.
    if !root.try_exists()? {
        return Ok(Vec::new());
    }
    if !fs::metadata(root)?.is_dir() {
        return Ok(Vec::new());
    }

    let needle = target_name.as_ref();
    let mut hits = Vec::new();

    // walkdir counts the root as depth=1; C++ counts depth=0 at root.
    // So we add 1 to the requested depth.
    let walker = WalkDir::new(root)
        .follow_links(false)
        .max_depth(max_depth.saturating_add(1));

    for entry in walker.into_iter().filter_map(Result::ok) {
        let ft = entry.file_type();

        // Do not follow or consider symlinks (parity with C++ is_regular_file).
        if ft.is_symlink() {
            continue;
        }
        if !ft.is_file() {
            continue;
        }

        if entry.file_name() == needle {
            hits.push(entry.into_path());
        }
    }

    if hits.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "No files found matching {} in {}",
                needle.to_string_lossy(),
                root.display()
            ),
        ))
    } else {
        Ok(hits)
    }
}

/// Convenience function with default search depth of 6.
///
/// This is a wrapper around [`find_files`] that uses the default maximum depth
/// of 6 directory levels, which is the conventional depth used in Splunk
/// installations.
///
/// # Arguments
///
/// * `root` - The directory to start searching from
/// * `target_name` - The filename to search for
///
/// # Returns
///
/// `io::Result<Vec<PathBuf>>` - Vector of matching file paths, or error.
///
/// # Examples
///
/// ```rust,no_run
/// use splunklib_rust::splunk_file_locator;
///
/// let files = splunk_file_locator::find_files_default("/opt/splunk", "server.conf")
///     .expect("Search failed");
/// ```
pub fn find_files_default<P, S>(root: P, target_name: S) -> io::Result<Vec<PathBuf>>
where
    P: AsRef<Path>,
    S: AsRef<OsStr>,
{
    find_files(root, target_name, 6)
}
