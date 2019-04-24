extern crate clap;
extern crate colored;
extern crate crypto;
extern crate regex;
extern crate stopwatch;

use {
    cli::thread_pool::ThreadPool,
    padd::{self, FormatJob, FormatJobRunner},
    std::{
        cmp,
        fs::{self, File, OpenOptions},
        io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
        path::{Path, PathBuf},
        str::FromStr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, SystemTime, UNIX_EPOCH},
    },
};

use self::{
    clap::{App, AppSettings, Arg, ArgMatches, SubCommand},
    colored::{ColoredString, Colorize},
    crypto::{
        digest::Digest,
        sha2::Sha256,
    },
    regex::Regex,
    stopwatch::Stopwatch,
};

const TRACKER_DIR: &str = ".padd";
const TRACKER_EXTENSION: &str = ".trk";

static FORMATTED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);
static TOTAL: AtomicUsize = AtomicUsize::new(0);

pub struct FormatCommand {
    fjr_arc: Arc<FormatJobRunner>,
    spec_sha: String,
    target_path: String,
    file_regex: Option<Regex>,
    thread_count: usize,
    no_skip: bool,
    no_track: bool,
    no_write: bool,
}

pub fn load_spec(spec_path: &str) -> Result<(FormatJobRunner, String), padd::BuildError> {
    let mut spec = String::new();

    let spec_file = File::open(spec_path);
    match spec_file {
        Ok(_) => {
            if let Err(err) = spec_file.unwrap().read_to_string(&mut spec) {
                logger::fatal(format!(
                    "Could not read specification file \"{}\": {}", &spec_path, err
                ));
            }
        }
        Err(err) => logger::fatal(format!(
            "Could not find specification file \"{}\": {}", &spec_path, err
        )),
    }

    let fjr = FormatJobRunner::build(&spec)?;

    let mut sha = Sha256::new();
    sha.input_str(&spec[..]);

    Ok((fjr, sha.result_str().to_string()))
}

pub fn fmt(cmd: FormatCommand) {
    let pool: ThreadPool<FormatPayload> = ThreadPool::spawn(
        thread_count,
        thread_count * 2,
        |payload: FormatPayload| {
            let file_path = payload.file_path.as_path();
            format_file(file_path, &payload.fjr_arc, payload.no_write);

            if !payload.no_track {
                track_file(file_path, &payload.spec_sha);
            }
        },
    );

    let fn_regex = match cmd.file_regex {
        Some(regex) => regex,
        None => Regex::new(r#".*"#).unwrap(),
    };

    let criteria = TargetSearchCriteria {
        fn_regex: &fn_regex,
        spec_sha: &spec_sha,
        no_skip: cmd.no_skip,
        no_track: cmd.no_track,
        no_write: cmd.no_write,
        fjr_arc: &cmd.fjr_arc,
        pool: &pool,
    };

    format_target(&cmd.target_path, &criteria);

    pool.terminate_and_join().unwrap();
}

fn format_target(
    target_path: &Path,
    criteria: &TargetSearchCriteria,
) {
    let path_string = target_path.to_string_lossy().to_string();
    let file_name = target_path.file_name().unwrap().to_str().unwrap();
    if target_path.is_dir() {
        if target_path.ends_with(TRACKER_DIR) {
            return; // Don't format tracker files
        }

        fs::read_dir(target_path).unwrap()
            .for_each(|res| {
                match res {
                    Ok(dir_item) => format_target(&dir_item.path(), criteria),
                    Err(err) => logger::err(format!(
                        "An error occurred while searching directory {}: {}", path_string, err
                    )),
                }
            });
    } else if criteria.fn_regex.is_match(file_name) {
        TOTAL.fetch_add(1, Ordering::SeqCst);

        if criteria.no_skip || needs_formatting(target_path, criteria.spec_sha) {
            criteria.pool.enqueue(FormatPayload {
                fjr_arc: criteria.fjr_arc.clone(),
                file_path: PathBuf::from(target_path),
                spec_sha: criteria.spec_sha.clone(),
                no_track: criteria.no_track,
                no_write: criteria.no_write,
            }).unwrap();
        }
    }
}

fn track_file(file_path: &Path, spec_sha: &str) {
    let tracker_path_buf = tracker_for(file_path);
    let tracker_path = tracker_path_buf.as_path();
    let tracker_path_string = tracker_path.to_string_lossy().to_string();

    let tracker_dir_path = tracker_path.parent().unwrap();
    if !tracker_dir_path.exists() {
        if let Err(err) = fs::create_dir(tracker_dir_path) {
            logger::err(format!(
                "Failed to create tracker directory for {}: {}", tracker_path_string, err
            ))
        }
    }

    match File::create(tracker_path) {
        Err(err) => logger::err(format!(
            "Failed to create tracker file {}: {}", tracker_path_string, err
        )),
        Ok(mut tracker_file) => {
            let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let elapsed_millis = since_epoch.as_secs() * 1000 +
                u64::from(since_epoch.subsec_nanos()) / 1_000_000;
            let line = format!("{}\n{}\n", spec_sha, elapsed_millis);

            if let Err(err) = tracker_file.write_all(line.as_bytes()) {
                logger::err(format!(
                    "Failed to write to tracker file {}: {}", tracker_path_string, err
                ))
            }
        }
    }
}

fn needs_formatting(file_path: &Path, spec_sha: &str) -> bool {
    if let Some(formatted_at) = formatted_at(file_path, spec_sha) {
        if let Some(modified_at) = modified_at(file_path) {
            let formatted_dur = formatted_at.duration_since(UNIX_EPOCH).unwrap();
            let modified_dur = modified_at.duration_since(UNIX_EPOCH).unwrap();

            if modified_dur.cmp(&formatted_dur) != cmp::Ordering::Greater {
                return false;
            }
        }
    }

    true
}

fn modified_at(file_path: &Path) -> Option<SystemTime> {
    let path_string = file_path.to_string_lossy().to_string();

    match fs::metadata(file_path) {
        Err(err) => logger::err(format!(
            "Failed to read metadata for {}: {}", path_string, err
        )),
        Ok(metadata) => match metadata.modified() {
            Err(err) => logger::err(format!(
                "Failed to read modified for {}: {}", path_string, err
            )),
            Ok(modified_at) => return Some(modified_at)
        }
    }

    None
}

fn formatted_at(file_path: &Path, spec_sha: &str) -> Option<SystemTime> {
    let tracker_path_buf = tracker_for(file_path);
    let tracker_path = tracker_path_buf.as_path();
    let tracker_path_string = tracker_path.to_string_lossy().to_string();

    if tracker_path.exists() {
        match File::open(tracker_path) {
            Err(err) => logger::err(format!(
                "Failed to open tracker file {}: {}", tracker_path_string, err
            )),
            Ok(tracker_file) => {
                let mut tracker_reader = BufReader::new(tracker_file);

                match read_tracker_line(&mut tracker_reader) {
                    Err(err) => logger::err(format!(
                        "Tracker missing spec sha {}: {}", tracker_path_string, err
                    )),
                    Ok(tracked_spec_sha) => if tracked_spec_sha == *spec_sha {
                        match read_tracker_line(&mut tracker_reader) {
                            Err(err) => logger::err(format!(
                                "Tracker missing timestamp {}: {}", tracker_path_string, err
                            )),
                            Ok(timestamp) => match u64::from_str(&timestamp[..]) {
                                Err(err) => logger::err(format!(
                                    "Failed to parse tracker timestamp {}: {}",
                                    tracker_path_string,
                                    err
                                )),
                                Ok(millis) => return Some(
                                    UNIX_EPOCH + Duration::from_millis(millis)
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

fn read_tracker_line(reader: &mut BufReader<File>) -> io::Result<String> {
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let line_len = line.len();
    line.truncate(line_len - 1);
    Ok(line)
}

fn tracker_for(file_path: &Path) -> PathBuf {
    let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();
    let mut tracker_dir_buf = file_path.parent().unwrap().to_path_buf();
    tracker_dir_buf.push(TRACKER_DIR);
    tracker_dir_buf.push(format!("{}{}", file_name, TRACKER_EXTENSION));
    tracker_dir_buf
}

fn term_loop(fjr_arc: &Arc<FormatJobRunner>) {
    loop {
        let mut target_path = String::new();

        if let Err(err) = io::stdin().read_line(&mut target_path) {
            logger::fmt_err(format!("Failed to read target file \"{}\": {}", target_path, err));
            continue;
        }

        target_path.pop();

        format_file(&Path::new(&target_path), &fjr_arc, false);
    }
}

fn format_file(target_path: &Path, fjr: &FormatJobRunner, no_write: bool) {
    if format_file_internal(target_path, fjr, no_write) {
        FORMATTED.fetch_add(1, Ordering::SeqCst);
    } else {
        FAILED.fetch_add(1, Ordering::SeqCst);
    }
}

fn format_file_internal(target_path: &Path, fjr: &FormatJobRunner, no_write: bool) -> bool {
    logger::fmt(target_path.to_string_lossy().to_string());
    let target_file = OpenOptions::new().read(true).write(true).open(&target_path);
    let target_path_string = target_path.to_string_lossy().to_string();
    match target_file {
        Ok(_) => {
            let mut target = target_file.unwrap();

            let result = {
                let mut text = String::new();

                if let Err(err) = target.read_to_string(&mut text) {
                    logger::fatal(format!(
                        "Could not read target file \"{}\": {}", target_path_string, err
                    ));
                }

                fjr.format(FormatJob::from_text(text))
            };

            match result {
                Ok(res) => {
                    if no_write {
                        logger::fmt_ok(target_path_string);
                        return true;
                    }

                    if let Err(err) = target.seek(SeekFrom::Start(0)) {
                        logger::fmt_err(format!(
                            "Could not seek to start of target file \"{}\": {}",
                            target_path_string,
                            err
                        ));
                        return false;
                    }
                    if let Err(err) = target.set_len(0) {
                        logger::fmt_err(format!(
                            "Could not clear target file \"{}\": {}", target_path_string, err
                        ));
                        return false;
                    }
                    match target.write_all(res.as_bytes()) {
                        Ok(_) => logger::fmt_ok(target_path_string),
                        Err(err) => {
                            logger::fmt_err(format!(
                                "Could not write to target file \"{}\": {}", target_path_string, err
                            ));
                            return false;
                        }
                    }
                }
                Err(err) => {
                    logger::fmt_err(format!("Error formatting {}: {}", target_path_string, err));
                    return false;
                }
            }
        }
        Err(err) => {
            logger::fmt_err(format!(
                "Could not find target file \"{}\": {}", target_path_string, err
            ));
            return false;
        }
    }
    true
}

struct FormatPayload {
    fjr_arc: Arc<FormatJobRunner>,
    file_path: PathBuf,
    spec_sha: String,
    no_track: bool,
    no_write: bool,
}

struct TargetSearchCriteria<'outer> {
    fn_regex: &'outer Regex,
    spec_sha: &'outer String,
    no_skip: bool,
    no_track: bool,
    no_write: bool,
    fjr_arc: &'outer Arc<FormatJobRunner>,
    pool: &'outer ThreadPool<FormatPayload>,
}

fn clear_tracking(target_path: &Path) -> usize {
    let mut cleared: usize = 0;

    let path_string = target_path.to_string_lossy().to_string();
    if target_path.is_dir() {
        if target_path.ends_with(TRACKER_DIR) {
            if let Err(err) = fs::remove_dir_all(target_path) {
                logger::err(format!(
                    "Could not delete tracking directory {}: {}", path_string, err
                ))
            }
            cleared += 1;
        }

        fs::read_dir(target_path).unwrap()
            .for_each(|res| {
                match res {
                    Ok(dir_item) => cleared += clear_tracking(&dir_item.path()),
                    Err(err) => logger::err(format!(
                        "An error occurred while searching directory {}: {}", path_string, err
                    )),
                }
            });
    }

    cleared
}
