extern crate clap;
extern crate colored;
extern crate crypto;
extern crate regex;
extern crate stopwatch;

use {
    cli::{
        logger,
        thread_pool::ThreadPool,
    },
    padd::{self, FormatJob, FormatJobRunner},
    std::{
        cmp,
        error,
        fmt,
        fs::{self, File, OpenOptions},
        io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
        path::{Path, PathBuf},
        str::FromStr,
        sync::{Arc, Mutex},
        time::{Duration, SystemTime, UNIX_EPOCH},
    },
};

use self::{
    crypto::{
        digest::Digest,
        sha2::Sha256,
    },
    regex::Regex,
};

const TRACKER_DIR: &str = ".padd";
const TRACKER_EXTENSION: &str = ".trk";
const THREAD_POOL_QUEUE_LENGTH_PER_WORKER: usize = 2;

#[derive(Clone)]
pub struct Formatter {
    fjr_arc: Arc<FormatJobRunner>,
    spec_sha: String,
}

pub struct FormatCommand<'path> {
    pub formatter: Formatter,
    pub target_path: &'path Path,
    pub file_regex: Option<Regex>,
    pub thread_count: usize,
    pub no_skip: bool,
    pub no_track: bool,
    pub no_write: bool,
}

struct FormatInstance<'outer> {
    formatter: &'outer Formatter,
    pool: &'outer ThreadPool<FormatPayload>,
    criteria: FormatCriteria<'outer>,
    metrics: Arc<Mutex<FormatMetrics>>,
}

struct FormatCriteria<'outer> {
    fn_regex: &'outer Regex,
    no_skip: bool,
    no_track: bool,
    no_write: bool,
}

pub struct FormatMetrics {
    pub formatted: usize,
    pub failed: usize,
    pub total: usize,
}

impl FormatMetrics {
    fn new() -> Self {
        FormatMetrics {
            formatted: 0,
            failed: 0,
            total: 0,
        }
    }

    fn copy(&self) -> Self {
        FormatMetrics {
            formatted: self.formatted,
            failed: self.failed,
            total: self.total,
        }
    }

    fn inc_formatted(&mut self) {
        self.formatted += 1;
    }

    fn inc_failed(&mut self) {
        self.failed += 1;
    }

    fn inc_total(&mut self) {
        self.total += 1;
    }
}

struct FormatPayload {
    formatter: Formatter,
    file_path: PathBuf,
    no_track: bool,
    no_write: bool,
    metrics: Arc<Mutex<FormatMetrics>>,
}

impl FormatPayload {
    fn from(path: &Path, instance: &FormatInstance) -> Self {
        FormatPayload {
            file_path: PathBuf::from(path),
            formatter: instance.formatter.clone(),
            no_track: instance.criteria.no_track,
            no_write: instance.criteria.no_write,
            metrics: instance.metrics.clone(),
        }
    }
}

pub fn generate_formatter(spec_path: &str) -> Result<Formatter, GenerationError> {
    logger::info(&format!("Loading specification {} ...", spec_path));

    let mut spec = String::new();

    let spec_file = File::open(spec_path);
    match spec_file {
        Ok(_) => {
            if let Err(err) = spec_file.unwrap().read_to_string(&mut spec) {
                return Err(GenerationError::FileErr(format!(
                    "Could not read specification file \"{}\": {}", &spec_path, err
                )));
            }
        }
        Err(err) => return Err(GenerationError::FileErr(format!(
            "Could not find specification file \"{}\": {}", &spec_path, err
        ))),
    }

    let fjr = FormatJobRunner::build(&spec)?;

    let mut sha = Sha256::new();
    sha.input_str(&spec[..]);

    logger::info(&format!("Successfully loaded specification: sha256: {}", &sha.result_str()));

    Ok(Formatter {
        fjr_arc: Arc::new(fjr),
        spec_sha: sha.result_str().to_string(),
    })
}

#[derive(Debug)]
pub enum GenerationError {
    FileErr(String),
    BuildErr(padd::BuildError),
}

impl fmt::Display for GenerationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GenerationError::FileErr(ref err) => write!(f, "{}", err),
            GenerationError::BuildErr(ref err) => write!(f, "{}", err),
        }
    }
}

impl error::Error for GenerationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            GenerationError::FileErr(_) => None,
            GenerationError::BuildErr(ref err) => Some(err),
        }
    }
}

impl From<padd::BuildError> for GenerationError {
    fn from(err: padd::BuildError) -> GenerationError {
        GenerationError::BuildErr(err)
    }
}

pub fn fmt(cmd: FormatCommand) -> FormatMetrics {
    let pool: ThreadPool<FormatPayload> = ThreadPool::spawn(
        cmd.thread_count,
        cmd.thread_count * THREAD_POOL_QUEUE_LENGTH_PER_WORKER,
        |payload: FormatPayload| {
            let file_path = payload.file_path.as_path();
            let file_path_string = file_path.to_string_lossy().to_string();

            logger::fmt(&file_path_string);

            match format_file(file_path, &payload.formatter.fjr_arc, payload.no_write) {
                Ok(_) => {
                    logger::fmt_ok(&file_path_string);
                    payload.metrics.lock().unwrap().inc_formatted();
                },
                Err(err) => {
                    logger::fmt_err(&format!("{}", err));
                    payload.metrics.lock().unwrap().inc_failed();
                }
            }

            if !payload.no_track {
                track_file(file_path, &payload.formatter.spec_sha);
            }
        },
    );

    let fn_regex = match cmd.file_regex {
        Some(regex) => regex,
        None => Regex::new(r#".*"#).unwrap(),
    };

    let mut instance = FormatInstance {
        formatter: &cmd.formatter,
        pool: &pool,
        criteria: FormatCriteria {
            fn_regex: &fn_regex,
            no_skip: cmd.no_skip,
            no_track: cmd.no_track,
            no_write: cmd.no_write,
        },
        metrics: Arc::new(Mutex::new(FormatMetrics::new())),
    };

    format_target(&cmd.target_path, &mut instance);

    pool.terminate_and_join().unwrap();

    let metrics = instance.metrics.lock().unwrap();
    metrics.copy()
}

fn format_target(
    target_path: &Path,
    instance: &mut FormatInstance,
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
                    Ok(dir_item) => format_target(&dir_item.path(), instance),
                    Err(err) => logger::err(&format!(
                        "An error occurred while searching directory {}: {}", path_string, err
                    )),
                }
            });
    } else if instance.criteria.fn_regex.is_match(file_name) {
        instance.metrics.lock().unwrap().inc_total();

        if instance.criteria.no_skip || needs_formatting(target_path, &instance.formatter.spec_sha) {
            let payload = FormatPayload::from(target_path, instance);
            instance.pool.enqueue(payload).unwrap();
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
            logger::err(&format!(
                "Failed to create tracker directory for {}: {}", tracker_path_string, err
            ))
        }
    }

    match File::create(tracker_path) {
        Err(err) => logger::err(&format!(
            "Failed to create tracker file {}: {}", tracker_path_string, err
        )),
        Ok(mut tracker_file) => {
            let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let elapsed_millis = since_epoch.as_secs() * 1000 +
                u64::from(since_epoch.subsec_nanos()) / 1_000_000;
            let line = format!("{}\n{}\n", spec_sha, elapsed_millis);

            if let Err(err) = tracker_file.write_all(line.as_bytes()) {
                logger::err(&format!(
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
        Err(err) => logger::err(&format!(
            "Failed to read metadata for {}: {}", path_string, err
        )),
        Ok(metadata) => match metadata.modified() {
            Err(err) => logger::err(&format!(
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
            Err(err) => logger::err(&format!(
                "Failed to open tracker file {}: {}", tracker_path_string, err
            )),
            Ok(tracker_file) => {
                let mut tracker_reader = BufReader::new(tracker_file);

                match read_tracker_line(&mut tracker_reader) {
                    Err(err) => logger::err(&format!(
                        "Tracker missing spec sha {}: {}", tracker_path_string, err
                    )),
                    Ok(tracked_spec_sha) => if tracked_spec_sha == *spec_sha {
                        match read_tracker_line(&mut tracker_reader) {
                            Err(err) => logger::err(&format!(
                                "Tracker missing timestamp {}: {}", tracker_path_string, err
                            )),
                            Ok(timestamp) => match u64::from_str(&timestamp[..]) {
                                Err(err) => logger::err(&format!(
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

fn format_file(
    target_path: &Path,
    fjr: &FormatJobRunner,
    no_write: bool,
) -> Result<(), FormattingError> {
    let target_file = OpenOptions::new().read(true).write(true).open(&target_path);
    let target_path_string = target_path.to_string_lossy().to_string();
    match target_file {
        Ok(_) => {
            let mut target = target_file.unwrap();

            let result = {
                let mut text = String::new();

                if let Err(err) = target.read_to_string(&mut text) {
                    return Err(FormattingError::FileErr(format!(
                        "Could not read target file \"{}\": {}", target_path_string, err
                    )));
                }

                fjr.format(FormatJob::from_text(text))
            };

            match result {
                Ok(res) => {
                    if no_write {
                        return Ok(());
                    }

                    if let Err(err) = target.seek(SeekFrom::Start(0)) {
                        return Err(FormattingError::FileErr(format!(
                            "Could not seek to start of target file \"{}\": {}",
                            target_path_string,
                            err
                        )));
                    }
                    if let Err(err) = target.set_len(0) {
                        return Err(FormattingError::FileErr(format!(
                            "Could not clear target file \"{}\": {}", target_path_string, err
                        )));
                    }

                    match target.write_all(res.as_bytes()) {
                        Ok(_) => Ok(()),
                        Err(err) => Err(FormattingError::FileErr(format!(
                            "Could not write to target file \"{}\": {}", target_path_string, err
                        )))
                    }
                }
                Err(err) => Err(FormattingError::FormatErr(err, target_path_string))
            }
        }
        Err(err) => Err(FormattingError::FileErr(format!(
            "Could not find target file \"{}\": {}", target_path_string, err
        )))
    }
}

#[derive(Debug)]
pub enum FormattingError {
    FileErr(String),
    FormatErr(padd::FormatError, String),
}

impl fmt::Display for FormattingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FormattingError::FileErr(ref err) => write!(f, "{}", err),
            FormattingError::FormatErr(ref err, ref target) => write!(
                f, "Error formatting {}: {}", target, err
            ),
        }
    }
}

impl error::Error for FormattingError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            FormattingError::FileErr(_) => None,
            FormattingError::FormatErr(ref err, _) => Some(err),
        }
    }
}

pub fn clear_tracking(target_path: &Path) -> usize {
    let mut cleared: usize = 0;

    let path_string = target_path.to_string_lossy().to_string();
    if target_path.is_dir() {
        if target_path.ends_with(TRACKER_DIR) {
            if let Err(err) = fs::remove_dir_all(target_path) {
                logger::err(&format!(
                    "Could not delete tracking directory {}: {}", path_string, err
                ))
            }
            cleared += 1;
        }

        fs::read_dir(target_path).unwrap()
            .for_each(|res| {
                match res {
                    Ok(dir_item) => cleared += clear_tracking(&dir_item.path()),
                    Err(err) => logger::err(&format!(
                        "An error occurred while searching directory {}: {}", path_string, err
                    )),
                }
            });
    }

    cleared
}
