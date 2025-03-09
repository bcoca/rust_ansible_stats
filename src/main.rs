/// Returns stat and other info about a file
extern crate exitcode;

use checksums::{Algorithm, hash_file};
use phf::phf_map;
use serde::{Serialize, Deserialize};
// use serde_json;
// use std::fs;
// use std::os::linux::fs::MetadataExt as LinuxMetadata;
// use std::os::unix::fs::MetadataExt as Metadata;
use std::env;
use std::os::unix::fs::PermissionsExt;
use std::ops::Not;
use std::path::Path;
use std::process;
use std::process::Command;
use std::str::FromStr;

// TODO: move this to external lib (ansible_module)

// trait AnsibleResult {
//     msg: String,
//     changed: bool,
//     failed: bool,
// }

// TODO: datetime
// extern crate chrono;
// use chrono::prelude::DateTime;
// use chrono::Utc;
// use std::time::{SystemTime, UNIX_EPOCH, Duration};
//
// fn main(){
//     // Creates a new SystemTime from the specified number of whole seconds
//     let d = UNIX_EPOCH + Duration::from_secs(1524885322);
//     // Create DateTime from SystemTime
//     let datetime = DateTime::<Utc>::from(d);
//     // Formats the combined date and time with the specified format string.
//     let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S.%f").to_string();
//     println!{"{}",timestamp_str};
// }

// cause serde cannot currently use bools for default
// fn True(){return Some(true);}
// fn False(){return Some(false);}
// fn sha1(){return Some("sha1");}


// #[serde(deny_unknown_fields)] // TODO: add once 'internal fields' are also added
#[derive(Deserialize, Default)] // AnsibleModuleArgs macro! (to include all hidden args
#[allow(dead_code)] // TODO: remove once you read module args
struct ModuleArgs {
    #[serde(alias = "name", alias = "dest")]
    path: String,
    follow: Option<bool>,
    #[serde(alias = "mime", alias = "mime_type", alias = "mime-type")] //, default = "True")]
    get_mime: Option<bool>,
    #[serde(alias = "attr", alias = "attributes")] //, default = "True")]
    get_attributes: Option<bool>,
    #[serde(alias = "checksum")] //, default = "True")]
    get_checksum: Option<bool>,
    #[serde(alias = "checksum_algo")] //, default = "sha1")]
    checksum_algorithim: Option<String>,
}

// TODO: move to lib
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

#[derive(Serialize, Debug, Default)] // TODO: move to AnsibleResult macro
struct StatResult {

    // common, move to macro
    pub msg: Option<String>,
    pub changed: bool,
    pub failed: bool,
    pub traceback: Option<String>,

    // module specific
    pub atime: Option<String>,
    pub attr_flags: Option<String>,
    pub attributes: Vec<String>,
    // block_size
    // blocks
    pub charset: Option<String>,
    pub checksum: Option<String>,
    pub ctime: Option<String>,
    // dev
    // device_type
    // executable
    pub exists: bool,
    pub gid: Option<u32>,
    pub gr_name: Option<String>,
    // inode
    pub isblk: Option<bool>,
    pub ischr: Option<bool>,
    pub isdir: Option<bool>,
    pub isfifo: Option<bool>,
    // isgid
    pub islnk: bool,
    pub isreg: Option<bool>,
    // issock
    // isuid
    pub lnk_source: Option<String>,
    pub lnk_target: Option<String>, // TODO: use Path?
    pub mimetype: Option<String>,
    pub mode: Option<String>,
    pub mtime: Option<String>,
    // nlink
    pub path: String, // use Display?
    // pw_name
    pub readable: Option<bool>,
    // rgrp
    // roth
    // rusr
    pub size: Option<u64>,
    pub uid: Option<u32>,
    pub version: Option<String>,
    // wgrp
    // woth
    // writeable
    // wusr
    // xgrp
    // xoth
    // xusr
}

impl StatResult { // TODO: move to AnsibleResult trait

    fn exit_json(&mut self, msg: Option<String>) {
        self.return_result(msg);
        process::exit(exitcode::OK);
    }

    fn fail_json(&mut self, msg: String) {
        // TODO: populate traceback?
        eprintln!("{:?}", msg);
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

	fn format_attributes(&mut self) {
		self.attributes = Vec::new();
		for flag in self.attr_flags.clone().unwrap().chars() {
		    self.attributes.push(FILE_ATTRIBUTES[flag.to_string().as_str()].to_string());
        }
	}
}

fn get_file_mime(path: &Path) -> (Option<String>, Option<String>) {

    let output = Command::new("file")
        .args(["--mime-type", "--mime-encoding", path.to_str().unwrap()])
        .output()
        .expect("failed to execute process");

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
        return (
            Some(mime_info[0].to_string()),
            Some(mime_info[1]
                .strip_prefix("charset=")
                .expect("Missing expected string pattern")
                .to_string()
            )
        );
    }else {
        //return Err(format!("Invalid mime information returned: {:?}", mime_info));
        eprintln!("Invalid mime information returned: {:?}", mime_info);
        return (Some("".to_string()), Some("".to_string()));
    }
}

// TODO handle unix, windows and find out what 'wasi' is, below works for Mac/Linux
// TODO: handle all errors so we can use next line
// fn main() -> StatResult {
fn main() {

    // Initialize result
    let mut sr = StatResult{
        //path : format!("{:?}", path),
        path : String::from(""),
        changed : false,
        failed : false,
        exists: false,
        islnk: false,
        ..StatResult::default()
    };

    // Get inputs
    let args: Vec<String> = env::args().collect();
    let args_file = Path::new(&args[1]);
    let m = args_from_file(args_file);

    let path = Path::new(&m.path);
    sr.path = String::from_str(path.to_str().unwrap()).unwrap();

    // Check if path exists, error if permissions issue
    let bad_path = |e| {sr.fail_json(format!("Cannot stat path ({:?}): {}", path, e)); return false;};
    sr.exists = path.try_exists().unwrap_or_else(bad_path);

    // return now if no path, no other info will be available
    if sr.exists.not() {
        sr.exit_json(Some(format!("Path ({:?}) does not exist.", path)));
    }

    // now get info about path/link
    sr.islnk = path.is_symlink();
    let stats = if sr.islnk.not() || m.follow.unwrap() {
            path.metadata().unwrap()
        } else {
            path.symlink_metadata().unwrap()
        };

    //TODO debug
    // eprintln!("{:?}", stats);

    // TODO: sr.update_from_stats(stats)
    // sr.ischr
    // sr.isblk
    // sr.isreg
    // sr.isfifo
	// sr.uid = 
	// sr.gid = 
    // sr.readable
    // etc

	// TODO: fix times to match python output
    sr.atime = Some(stats
        .accessed()
        .unwrap()
        .elapsed()
        .expect("Invalid duration")
        .as_secs()
        .to_string()
    );
    sr.ctime = Some(stats.created().unwrap().elapsed().expect("Invalid duration").as_secs().to_string());
    sr.mtime = Some(stats.modified().unwrap().elapsed().expect("Invalid duration").as_secs().to_string());

	sr.isdir = Some(stats.is_dir());
    //TODO: cut to last 4 chars, use first 4 for other stat info
    sr.mode = Some(format!("{:#o}", stats.permissions().mode()));
    sr.size = Some(stats.len());

    if m.get_checksum.expect("Invalid boolean for get_checksum") {
        sr.checksum = Some(
                hash_file(path,
                Algorithm::from_str(&m.checksum_algorithim.unwrap()).expect("Invalid Algorithim")
            )
            .to_lowercase()
        );
    }

	if m.get_attributes.expect("Invalid boolean for get_attributes") {
        // TODO: (sr.version , sr.attr_flags) = get_file_attributes(path);
		let output = Command::new("lsattr")
			.args(["-vd", path.to_str().unwrap()])
			.output()
			.expect("failed to execute process");
		let res: Vec<&str> = std::str::from_utf8(&output.stdout)
            .unwrap()
            .split_whitespace()
            .collect();
		sr.version = Some(res[0].to_string());
		sr.attr_flags = Some(res[1].trim_matches('-').to_string());
		sr.format_attributes();
	}

    // get mimetype and charset
    if m.get_mime.expect("Invalid boolean for get_mime") {
        (sr.mimetype, sr.charset) = get_file_mime(path);
    }

    sr.exit_json(None);
}
