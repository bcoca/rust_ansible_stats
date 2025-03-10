/// Returns stat and other info about a file
extern crate chrono;
extern crate exitcode;

use checksums::{Algorithm, hash_file};
use chrono::Local;
use filetime::FileTime;
use phf::phf_map;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;
use std::env;
use std::os::linux::fs::MetadataExt; // TODO: mac/win?
//use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::fs::FileTypeExt;
use std::ops::Not;
use std::path::{Path, PathBuf};
use std::process;
use std::process::Command;
use std::str::FromStr;
use users::{get_user_by_uid, get_group_by_gid, get_effective_uid, get_effective_gid, Users, Groups}; //get_effective?

const DATE_FORMAT_STR: &'static str = "%Y-%m-%d  %H:%M:%S";

// TODO: try to get serde to set defaults
// fn True(){return Some(true);}
// fn False(){return Some(false);}
// fn sha1(){return Some("sha1");}


// #[serde(deny_unknown_fields)] // TODO: add once 'internal fields' are also added
#[derive(Deserialize, Default)] // AnsibleModuleArgs macro! (to include all hidden args
struct ModuleArgs {
    #[serde(alias = "name", alias = "dest")]
    path: String,

    #[serde(alias = "mime", alias = "mime_type", alias = "mime-type")] //, default = "True")]
    get_mime: Option<bool>,
    #[serde(alias = "attr", alias = "attributes")] //, default = "True")]
    get_attributes: Option<bool>,
    #[serde(alias = "checksum")] //, default = "True")]
    get_checksum: Option<bool>,
    #[serde(alias = "checksum_algo")] //, default = "sha1")]
    checksum_algorithim: Option<String>,
    follow: Option<bool>,
    #[serde(alias = "_ansible_debug")]

    debug: bool,
}

// TODO: move to lib/Ansible::ModuleArgs
fn debug(debug: String) {
    eprintln!("[DEBUG] stat (pid:{:?}) [{}]: {:?}", process::id(), Local::now().format(DATE_FORMAT_STR).to_string(), debug);
}

fn args_from_file(path: &Path) -> ModuleArgs {

    let args: ModuleArgs;
    let exists = path.try_exists();
    match exists {
        Ok(x) => {
            if x {
                let file_contents =  std::fs::read_to_string(path).unwrap();
                args = serde_json::from_str(&file_contents).expect("Invalid JSON args file for this module.");
            } else {
                panic!("Module arguments file provided ({:?}) is not accessible or does not exist!", path);
            }
            x
        },
        Err(e) => {
            // TODO: fail_json/raise error?
            // panic!("Cannot access args: {:?}", e);
            eprintln!("Cannot access args: {:?}", e);
            args = ModuleArgs {
                path:  String::from("/etc/hosts"),
                //path = String::from("/home/bcoca/testing123"),
                //path = String::from("/nofile"),
                follow: Some(true),
                get_mime: Some(true),
                get_attributes: Some(true),
                get_checksum: Some(true),
                checksum_algorithim: Some("sha1".to_string()),
                debug: true,
                ..ModuleArgs::default()
            };
            false
        },
    };
    return args;
}

// TODO: move to lib, using phf to create constant/static hashmap
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
    // debug: <String>,

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
    pub block_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks: Option<u32>,
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
    pub nlink: Option<u32>,
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

// TODO: move common methods to AnsibleResult trait/macro
impl StatResult {

    // TODO:: add deprecations + log
    fn warn(&mut self, warning: String) {
        eprintln!("[WARNING] {}", warning);
        self.warnings.insert(warning);
    }

    fn exit_json(&mut self, msg: Option<String>) {
        self.return_result(msg);
        process::exit(exitcode::OK);
    }

    fn fail_json(&mut self, msg: String) {
        // TODO: populate traceback?
        debug(format!("{:?}", msg));
        if self.failed.not() {
            self.failed = true;
        }
        self.return_result(Some(msg));
        process::exit(1);
    }

    fn return_result(&mut self, msg: Option<String>) {
        self.msg = msg;
        println!("{}", serde_json::to_string(&self).unwrap());
    }

// LOCAL

	fn format_attributes(&mut self) {
    // Set 'list of attribute strings' from attibute flags
		self.attributes = Vec::new();
		for flag in self.attr_flags.clone().unwrap().chars() {
		    self.attributes.push(FILE_ATTRIBUTES[flag.to_string().as_str()].to_string());
        }
	}

    fn set_mime_info(&mut self, path: &Path) {

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
                .expect("Missing expected string pattern in chareti info")
                .to_string()
            );
        }else {
            self.warn(format!("Skipping mime info, invalid mime information: {:?}", mime_info));
        }
    }

    fn set_file_attr(&mut self, path: &Path) {
		let output = Command::new("lsattr")
			.args(["-vd", path.to_str().unwrap()])
			.output()
			.expect("failed to execute process");
		let res: Vec<&str> = std::str::from_utf8(&output.stdout)
            .unwrap()
            .split_whitespace()
            .collect();
        if res.len() == 3 {
		    self.version = Some(res[0].to_string());
		    self.attr_flags = Some(res[1].trim_matches('-').to_string());
		    self.format_attributes();
        } else {
            self.warn(format!("Skipping attr info, unexpected lsattr output: {:?}", res));
        }
    }
}
// TODO handle unix, windows and find out what 'wasi' is, below works for Mac/Linux
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
    let args_file = Path::new(&args[1]);
    let m = args_from_file(args_file);

    // Handle symlink
    let pb: PathBuf;
    let mut path = Path::new(&m.path);
    // save orig path
    sr.path = String::from_str(path.to_str().unwrap()).unwrap();
    if path.is_symlink() {
        pb = path.read_link().expect("Unable to follow symlink"); //NOTE: resolve recursively? check py version
        sr.lnk_target = Some(format!("{:?}", pb));
        if pb.is_relative() {
            sr.lnk_source = Some(format!("{:?}", pb.canonicalize().unwrap()));
        } else {
            sr.lnk_source = sr.lnk_target.clone();
        }

        // resolve symlink for rest of info if 'follow'
        if m.follow.unwrap() {
            path = pb.as_path();
        }
    }

    // Check if path exists, error if permissions issue
    let bad_path = |e| {sr.fail_json(format!("Cannot stat path ({:?}): {}", path, e)); return false;};
    sr.exists = path.try_exists().unwrap_or_else(bad_path);

    // return now if no path, no other info will be available
    if sr.exists.not() {
        sr.exit_json(Some(format!("Path ({:?}) does not exist.", path)));
    }

    // now get info about path/link, using symlink cause its more complete in case we didn't 'follow' above.
    let stats = path.symlink_metadata().unwrap();
    if m.debug {
        debug(format!("{:?}", stats));
    }

    // TODO: move to an sr.update_from_stats(stats)
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
    // sr.blocks =
    // sr.block_size =
    // sr.inode =
    // sr.nlink
    sr.size = Some(stats.len());

    // file perms
    let perms = stats.permissions();
    //let fullmode sr.mode = format!("{:#o}", perms.mode());
    // sr.rusr =
    // sr.wusr =
    // sr.xusr =

    // sr.rgrp =
    // sr.wgrp =
    // sr.xgrp =

    // sr.roth =
    // sr.woth =
    // sr.xoth =
    // sr.mode = Some(format!"{sr.rusr}{sr.wusr}{sr.xusr}{sr.rgrp}{sr.wgrp}{sr.xgrp}{sr.roth}{sr.woth}{sr.xoth}");

    sr.pw_name = Some(format!("{:?}", get_user_by_uid(stats.st_uid()).unwrap().name()));
    sr.gr_name = Some(format!("{:?}", get_group_by_gid(stats.st_gid()).unwrap().name()));

    // 'my' user/group match?
	sr.isuid = Some(get_effective_uid() == stats.st_uid());
	sr.isgid = Some(get_effective_gid() == stats.st_gid());

    // 'my' permissions!
    // sr.readable =
    // sr.executable =
    // sr.writable =

	// Time!!!
    let atime = FileTime::from_last_access_time(&stats);
    sr.atime = Some(format!("{:?}.{:?}", atime.unix_seconds(), atime.nanoseconds()));
    let ctime = FileTime::from_creation_time(&stats).unwrap();
    sr.ctime = Some(format!("{:?}.{:?}", ctime.unix_seconds(), ctime.nanoseconds()));
    let mtime = FileTime::from_last_modification_time(&stats);
    sr.mtime = Some(format!("{:?}.{:?}", mtime.unix_seconds(), mtime.nanoseconds()));

    if m.get_checksum.expect("get_checksum should be a boolean") {
        //eprintln!("{:?}", stats.file_type().hash(Algorithm::from_str(&m.checksum_algorithim.unwrap()).expect("Invalid checksum algorithm specified")));
        sr.checksum = Some(
                hash_file(path,
                Algorithm::from_str(&m.checksum_algorithim.unwrap()).expect("Invalid checksum algorithm specified")
            )
            .to_lowercase()
        );
    }

	if m.get_attributes.expect("get_attributes should be a boolean") {
        sr.set_file_attr(path);
	}

    if m.get_mime.expect("get_mime hsould be a boolean") {
        sr.set_mime_info(path);
    }

    sr.exit_json(None);
}
