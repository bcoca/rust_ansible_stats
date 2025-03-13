/// Returns stat and other info about a file
extern crate chrono;
extern crate checksums;
extern crate exitcode;
extern crate filetime;
extern crate nix;
extern crate phf;
extern crate serde;
extern crate users;

use checksums::{Algorithm, hash_file};
use chrono::Local;
use filetime::FileTime;
use nix::unistd::{AccessFlags, access};
use nix::sys::stat::{FileStat,lstat,stat};
use phf::phf_map;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;
use std::env;
use std::os::linux::fs::MetadataExt; // TODO: mac/win?
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::ops::Not;
use std::path::{Path, PathBuf};
use std::process;
use std::process::Command;
use std::str::FromStr;
use users::{get_user_by_uid, get_group_by_gid};

// used for debug stamp
const DATE_FORMAT_STR: &str = "%Y-%m-%d  %H:%M:%S";

// TODO: move to common lib
fn d_true() -> bool {true}
fn d_false() -> bool {false}
fn d_sha1() -> String {"sha1".to_string()}
// fn d_selinux_fs() -> Vec<str> {return vec!["fuse", "nfs", "vboxsf", "ramfs", "9p", "vfat"];}
fn d_shell() -> String {"/bin/sh".to_string()}
fn d_syslog_facility() -> String {"INFO".to_string()}
fn d_v() -> u32 {0}
fn d_version() -> String {"0.0".to_string()}

#[derive(Deserialize, Default)] // AnsibleModuleArgs macro!
#[allow(dead_code)]
struct ModuleArgs {
    // common
    #[serde(alias = "_ansible_check_mode", default = "d_false")]
    check_mode: bool,
    #[serde(alias = "_ansible_debug", default = "d_false")]
    debug: bool,
    #[serde(alias = "_ansible_diff", default = "d_false")]
    diff: bool,
    #[serde(alias = "_ansible_keep_remote_files", default = "d_false")]
    keep_remote_files: bool,
    #[serde(alias = "_ansible_ignore_unknown_opts", default = "d_false")]
    ignore_unknown_opts: bool, // normally use #[serde(deny_unknown_fields)] but we want this at runtime?
    #[serde(alias = "_ansible_module_name")]
    module_name: String,
    #[serde(alias = "_ansible_no_log", default = "d_false")]
    no_log: bool,
    #[serde(alias = "_ansible_remote_tmp")]
    remote_tmp: Option<String>,
    #[serde(alias = "_ansible_target_log_info")]
    target_log_info: Option<String>,
//    #[serde(alias = "_ansible_selinux_special_fs", default = "d_selinux_fs")]
//    selinux_special_fs: Vec<str>,
    #[serde(alias = "_ansible_shell_executable", default = "d_shell")]
    shell_executable: String,
    #[serde(alias = "_ansible_socket_path")]
    socket: Option<String>,
    #[serde(alias = "_ansible_syslog_facility", default = "d_syslog_facility")]
    syslog_facility: String,
    #[serde(alias = "_ansible_tmpdir")]
    tmpdir: Option<String>,
    #[serde(alias = "_ansible_verbosity", default = "d_v")]
    verbosity: u32,
    #[serde(alias = "_ansible_version", default = "d_version")]
    version: String,

    // Local/Module specific
    #[serde(alias = "name", alias = "dest")]
    path: String,
    #[serde(default = "d_false")]
    follow: bool,

    #[serde(alias = "checksum_algo", default = "d_sha1")]
    checksum_algorithim: String,
    #[serde(alias = "attr", alias = "attributes", default = "d_true")]
    get_attributes: bool,
    #[serde(alias = "checksum", default = "d_true")]
    get_checksum: bool,
    #[serde(alias = "mime", alias = "mime_type", alias = "mime-type", default = "d_true")]
    get_mime: bool,
}

impl ModuleArgs {

    // TODO: also move to 'trait'/common lib
    fn debug(&self, msg: String) {
        if self.debug {
            eprintln!(" [DEBUG] {} (pid:{:?}) [{}]: {:?}", self.module_name, process::id(), Local::now().format(DATE_FORMAT_STR), msg);
        }
    }

    fn from_argsfile(path: &Path) -> ModuleArgs {
        match std::fs::read_to_string(path) {
            Ok(file_contents) => {
                let args: ModuleArgs = match serde_json::from_str(&file_contents) {
                    Ok(data) => { data },
                    Err(e) => {panic!("Unable to parse the provided arguments file ({:?}) as JSON: {:?}", path, e)},
                };
                return args;
            },
            Err(e) => {
                // TODO: fail_json/raise error?
                panic!("Unable to read the provided arguments file({:?}): {:?} !", path, e);
            },
        };
    }
}

// TODO: move all 4 to lib
// used to set unix perms booleans
const EXEC: [char;4] = ['1','3','5','7'];
const WRITE: [char;4] = ['2','3','6','7'];
const READ: [char;4] = ['4','5','6','7'];

// used to turn attribute flags to list, using phf to create constant/static hashmap
static FILE_ATTRIBUTES: phf::Map<&'static str, &'static str> = phf_map! {
    "A" => "noatime",
    "a" => "append",
    "c" => "compressed",
    "C" => "nocow",
    "d" => "nodump",
    "D" => "dirsync",
    "e" => "extents",
    "E" => "encrypted",
    "h" => "blocksize",
    "i" => "immutable",
    "I" => "indexed",
    "j" => "journalled",
    "N" => "inline",
    "s" => "zero",
    "S" => "synchronous",
    "t" => "notail",
    "T" => "blockroot",
    "u" => "undelete",
    "X" => "compressedraw",
    "Z" => "compresseddirty",
};

#[derive(Serialize, Debug, Default)] // TODO: gen from Ansible::ModuleResult macro
struct StatResult {

    // common, move to macro
    warnings: HashSet<String>,
    deprecations: HashSet<String>,
    #[serde(skip_serializing)]
    debug: bool, // just here so we dont need to pass args/from args

    pub changed: bool,
    pub failed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traceback: Option<String>,

    // module specific
    #[serde(skip_serializing_if = "Option::is_none")]
    pub atime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attr_flags: Option<String>,
    pub attributes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<bool>,
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gr_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inode: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isblk: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ischr: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isdir: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isfifo: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isgid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub islnk: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isreg: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issock: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isuid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lnk_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lnk_target: Option<String>, // NOTE: use Path/Display?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mimetype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nlink: Option<u64>,
    pub path: String, // NOTE: use Path/Display?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pw_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rgrp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roth: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rusr: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wgrp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub woth: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wusr: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xgrp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xoth: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xusr: Option<bool>,
}

impl StatResult {
// TODO: move common methods to AnsibleResult trait/macro

    // TODO:: add deprecations + log
    fn warn(&mut self, warning: String) {
        if self.debug {
            eprintln!("[WARNING] {}", warning);
        }
        self.warnings.insert(warning);
    }

    fn exit_json(&mut self, msg: Option<String>) {
        self.return_result(msg);
        process::exit(exitcode::OK);
    }

    fn fail_json(&mut self, msg: String) {
        // TODO: populate traceback?
        if self.debug {
            eprintln!("{:?}", msg);
        }
        if self.failed.not() {
            self.failed = true;
        }
        self.return_result(Some(msg));
        process::exit(1);
    }

    fn return_result(&mut self, msg: Option<String>) {
        self.msg = msg;
        if self.debug {
            println!("{}", serde_json::to_string_pretty(&self).unwrap());
        } else {
            println!("{}", serde_json::to_string(&self).unwrap());
        }
    }

// LOCAL //

	fn format_attributes(&mut self) {
    // Set 'list of attribute strings' from attibute flags
		self.attributes = Vec::new();
		for flag in self.attr_flags.clone().unwrap().chars() {
		    self.attributes.push(FILE_ATTRIBUTES[flag.to_string().as_str()].to_string());
        }
	}

    fn set_mimeinfo_from_file(&mut self, path: &Path) {
        // TODO: pass through the error, check stderr
        let output = Command::new("file")
            .args(["--mime-type", "--mime-encoding", path.to_str().unwrap()])
            .output()
            .expect("failed to execute 'file'");

        let mime_string = std::str::from_utf8(&output.stdout)
            .unwrap()
            .split(':')
            .last()
            .unwrap()
            .to_string();

        let mime_info: Vec<&str> = mime_string
            .split(';')
            .map(|x| x.trim())
            .collect();

        if mime_info.len() == 2 {
            self.mimetype = Some(mime_info[0].to_string());
            self.charset = Some(mime_info[1]
                .strip_prefix("charset=")
                .expect("Missing expected string pattern in charset info")
                .to_string()
            );
        }else {
            self.warn(format!("Skipped mime info, invalid mime information: {:?}", mime_info));
        }
    }

    fn set_attr_from_file(&mut self, path: &Path) {
		let output = match Command::new("lsattr")
			.args(["-vd", path.to_str().unwrap()])
			.output() {
            Ok(o) => { o },
            Err(e) => {
                // lsattr didnt fail, but we failed on executing it
                self.fail_json(format!("Failed on executing lsattr: {:?}", e));
                panic!("should not get here, but compiler does not see end in fail_json");
            },
        };
        // lsattr executed, but failed
        if output.status.success() {
		    let res: Vec<&str> = std::str::from_utf8(&output.stdout)
                .unwrap()
                .split_whitespace()
                .collect();
            if res.len() == 3 {
		        self.version = Some(res[0].to_string());
		        self.attr_flags = Some(res[1].trim_matches('-').to_string());
		        self.format_attributes();
            } else {
                // lsattr succeded but output was not what we expected
                self.warn(
                    format!("Skipped attributes due to unexpected output from lsattr: {:?}",
                        res,
                    )
                );
            }
        } else {
            self.warn(
                format!("Skipped attributes dut to lsattr failing: rc={:?} stderr={:?}",
                    output.status.code().unwrap(),
                    std::str::from_utf8(&output.stderr).unwrap()
                )
            )
        }
    }
}
// TODO handle unix, mac, linux, windows (no wasi), special cases, below is mostly uniXy
// TODO: handle all errors so we can use next line
// fn main() -> StatResult {
fn main() {

    // Initialize result, TODO: move to new/init/default func in struct
    let mut sr = StatResult{
        //path : format!("{:?}", path),
        path : String::from(""),
        changed : false,
        failed : false,
        exists: false,
        warnings: HashSet::new(),
        deprecations: HashSet::new(),
        ..StatResult::default()
    };

    // Get inputs
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("Expected one argument, but got {:?}", args.len() - 1);
    }
    let args_file = Path::new(&args[1]);
    let params = ModuleArgs::from_argsfile(args_file);

    // result handles output, let it know debug status
    sr.debug = params.debug;
    params.debug("initalized".to_string());

    // Handle symlink
    let mut pb: PathBuf;
    let mut path = Path::new(&params.path);
    // save orig path
    sr.path = String::from_str(path.to_str().unwrap()).unwrap();
    if path.is_symlink() {
        pb = path.read_link().expect("Unable to follow symlink");
        // non normalized 'first target' of given link
        sr.lnk_target = Some(format!("{:?}", pb));
        if params.follow {
            path = pb.as_path();
            // resolve symlink chain for rest of info if 'follow'
            while path.is_symlink() {
                pb = path.read_link().expect("Unable to follow symlink");
                path = pb.as_path();
            }
        }
        // normalize final resolved file
        sr.lnk_source = Some(format!("{:?}", pb.canonicalize().unwrap()));
    }

    // Check if path exists, error if permissions issue
    let bad_path = |e| {sr.fail_json(format!("Cannot stat path ({:?}): {}", path, e)); false};
    sr.exists = path.try_exists().unwrap_or_else(bad_path);

    // return now if no path, no other info will be available
    if sr.exists.not() {
        sr.exit_json(Some(format!("Path ({:?}) does not exist.", path)));
    }

    // TODO: move to an sr.set_from_file(path)
    // now get info about path/link, using symlink cause its more complete in case we didn't 'follow' above.
    // TODO: handle stat errors more gracefully
    let stats = path.symlink_metadata().unwrap();
    let stats_ext: FileStat = if params.follow {stat(path).unwrap()} else {lstat(path).unwrap()};

    // file details
	sr.isdir = Some(stats.is_dir());
    sr.islnk = Some(path.is_symlink());
    sr.isreg = Some(stats.is_file());

    // moar deets (Ext)
    let ft = stats.file_type();
    sr.isblk = Some(ft.is_block_device());
    sr.ischr = Some(ft.is_char_device());
    sr.isfifo = Some(ft.is_fifo());
    sr.issock = Some(ft.is_socket());

    // extended file data
    sr.blocks = Some(stats_ext.st_blocks);
    sr.block_size = Some(stats_ext.st_blksize);
    sr.inode = Some(stats_ext.st_ino);
    sr.nlink = Some(stats_ext.st_nlink);
    sr.size = Some(stats.len());

    // file perms NOTE: move to stats_ext?
    {
        let fullmode: Vec<char> = format!("{:#o}", stats.permissions().mode()).drain(..).collect();
        let bound = fullmode.len() - 1;
        if ft.is_char_device().not() {
            let sid = &fullmode[bound - 3];
	        sr.isuid = Some(READ.contains(sid)); // suid has same values as read (stick == exec)
	        sr.isgid = Some(WRITE.contains(sid)); // guid has same values as write
        }
        {
            let usr = &fullmode[bound - 2];
            sr.rusr = Some(READ.contains(usr));
            sr.wusr = Some(WRITE.contains(usr));
            sr.xusr = Some(EXEC.contains(usr));
        }
        {
            let grp = &fullmode[bound - 1];
            sr.rgrp = Some(READ.contains(grp));
            sr.wgrp = Some(WRITE.contains(grp));
            sr.xgrp = Some(EXEC.contains(grp));
        }
        {
            let oth = &fullmode[bound];
            sr.roth = Some(READ.contains(oth));
            sr.woth = Some(WRITE.contains(oth));
            sr.xoth = Some(EXEC.contains(oth));
        }
        // drop 0-3 as most won't know meaning and just expect the 4
        sr.mode = Some(fullmode[bound - 3..].iter().collect::<String>());
    }
    // user/group info
    sr.pw_name = Some(format!("{:?}", get_user_by_uid(stats.st_uid()).unwrap().name()));
    sr.gr_name = Some(format!("{:?}", get_group_by_gid(stats.st_gid()).unwrap().name()));

    // 'my' permissions!
    sr.readable = Some(access(path, AccessFlags::R_OK).is_ok());
    sr.executable = Some(access(path, AccessFlags::X_OK).is_ok());
    sr.writable = Some(access(path, AccessFlags::W_OK).is_ok());

	// Time!!!
    let atime = FileTime::from_last_access_time(&stats);
    sr.atime = Some(format!("{:?}.{:?}", atime.unix_seconds(), atime.nanoseconds()));
    let ctime = FileTime::from_creation_time(&stats).unwrap();
    sr.ctime = Some(format!("{:?}.{:?}", ctime.unix_seconds(), ctime.nanoseconds()));
    let mtime = FileTime::from_last_modification_time(&stats);
    sr.mtime = Some(format!("{:?}.{:?}", mtime.unix_seconds(), mtime.nanoseconds()));

    // TODO: move each query to it's own thread?

    // get checksum if requested, avoid block/char/fifo/etc
    if params.get_checksum {
        if stats.is_file() {
            //TODO: on bsds this can work on dirs, switch to error handle,
            //      panic::catch_unwind won't get error, still printed, but will stop exit
            sr.checksum = Some(
                    hash_file(path,
                    Algorithm::from_str(&params.checksum_algorithim).unwrap()
                )
                .to_lowercase()
            );
        } else {
            sr.warn("Skipped checksum as the path was not a file.".to_string());
        }
    }

	if params.get_attributes {
        if params.follow || path.is_symlink().not() {
            sr.set_attr_from_file(path);
        } else {
            sr.warn("Skipped attributes as this is not supported on symlinks".to_string());
        }
	}

    if params.get_mime {
        sr.set_mimeinfo_from_file(path);
    }

    sr.exit_json(None);
}
