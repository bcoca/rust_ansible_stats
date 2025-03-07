/// Returns stat and other info about a file

use checksums::{Algorithm, hash_file};
use phf::phf_map;
use serde::{Serialize, Deserialize};
// use serde_json;
// use std::fs;
// use std::os::linux::fs::MetadataExt as LinuxMetadata;
// use std::os::unix::fs::MetadataExt as Metadata;
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

#[derive(Default, Deserialize)]
#[allow(non_camel_case_types)]
enum ChecksumAlgorithims {
    MD5,
    #[default]
    SHA1,
    SHA244,
    SHA256,
    SHA384,
    SHA512,
}

// #[serde(deny_unknown_fields)] // TODO: add once 'internal fields' are also added
#[derive(Deserialize, Default)] // AnsibleModuleArgs macro! (to include all hidden args
#[allow(dead_code)] // TODO: remove once you read module args
struct ModuleArgs {
    #[serde(alias = "name", alias = "dest")]
    path: String,
    follow: Option<bool>,
    #[serde(alias = "mime", alias = "mime_type", alias = "mime-type")]
    get_mime: Option<bool>,
    #[serde(alias = "attr", alias = "attributes")]
    get_attributes: Option<bool>,
    #[serde(alias = "checksum")]
    get_checksum: Option<bool>,
    #[serde(alias = "checksum_algo")]
    checksum_algorithim: Option<ChecksumAlgorithims>,
}

// impl Default for ModuleArgs {
//     fn default() -> Self {
//         ModuleArgs {
//             follow = false,
//             get_mime = true,
//             get_attributes = true,
//             get_checksum = true,
//             checksum_algorithim = "sha1",
//         }
//     }
// }

// TODO: move to lib
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
    pub msg: String,
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

    fn exit_json(&mut self, msg: String) {
        self.return_result(msg);
        process::exit(0);
    }

    fn fail_json(&mut self, msg: String) {
        // TODO: populate traceback?
        eprintln!("{:?}", msg);
        if self.failed.not() {
            self.failed = true;
        }
        self.return_result(msg);
        process::exit(1);
    }

    fn return_result(&mut self, msg: String) {
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

// TODO handle unix, windows and find out what 'wasi' is, below works for Mac/Linux
// TODO: handle all errors so we can use next line
// fn main() -> StatResult {
fn main() {

    // TODO: read from params
    let path = Path::new("/etc/hosts");
    //let path = Path::new("/home/bcoca/testing123");
    //let path = Path::new("/nofile");
    let follow = true;
    //let follow = false;
    let get_mime = true;
    //let get_mime = false;
    let get_attributes = true;
    //let attributes = false;
    let get_checksum = true;
    //let get_checksum = false;
    //let checksum_algorithim = "SHA1";
    let checksum_algorithim = "md5";
    //let checksum_algorithim = "sha1";

    // Initialize result
    let mut sr = StatResult{
        path : format!("{:?}", path),
        changed : false,
        failed : false,
        exists: false,
        islnk: false,
        ..StatResult::default()
    };

    // setup path error handler
    let bad_path = |e| {sr.fail_json(format!("Cannot stat path ({:?}): {}", path, e)); return false;};

    // Check if path exists, error if permissions issue
    sr.exists = path.try_exists().unwrap_or_else(bad_path);

    // return now if no path, no other info will be available
    if sr.exists.not() {
        sr.exit_json(format!("Path ({:?}) does not exist.", path));
    }

    // now get info about path/link
    sr.islnk = path.is_symlink();
    let stats = if sr.islnk.not() || follow {
            path.metadata().unwrap()
        } else {
            path.symlink_metadata().unwrap()
        };

    //TODO debug
    // eprintln!("{:?}", stats);

// Metadata { file_type: FileType { is_file: true, is_dir: false, is_symlink: false, .. }, permissions: Permissions(FilePermissions { mode: 0o100644 (-rw-r--r--) }), len: 71, modified: SystemTime { tv_sec: 1694268711, tv_nsec: 457442806 }, accessed: SystemTime { tv_sec: 1678297151, tv_nsec: 0 }, created: SystemTime { tv_sec: 1694268703, tv_nsec: 85442750 }, .. }

    // sr.ischr
    // sr.isblk
    // sr.isreg
    // sr.isfifo
	// sr.uid = 
	// sr.gid = 
    // sr.readable
    // etc

	// TODO: fix to match python output
    sr.atime = Some(stats
        .accessed()
        .unwrap()
        .elapsed()
        .expect("Invalid duration")
        .as_secs()
        .to_string()
    );
    sr.ctime = Some(stats.created().unwrap().elapsed().expect("Invalid duration").as_secs().to_string());
	sr.isdir = Some(stats.is_dir());
    sr.mode = Some(format!("{:#o}", stats.permissions().mode()));
    // let fullmode =format!("{:#o}", stats.permissions().mode()).chars().into_iter();
    // let head = String::from_iter(fullmode);
    // let bottom: String = fullmode.clone().take(4).collect();
    // eprintln!("{:?} {:?}", head, bottom);
    // sr.mode = Some(bottom);
    sr.mtime = Some(stats.modified().unwrap().elapsed().expect("Invalid duration").as_secs().to_string());

    sr.size = Some(stats.len());

    if get_checksum {
        sr.checksum = Some(
                hash_file(path,
                Algorithm::from_str(checksum_algorithim).expect("Invalid Algorithim")
            )
            .to_lowercase()
        );
    }

	if get_attributes {
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
    if get_mime {
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
		    sr.mimetype = Some(mime_info[0].to_string());
		    sr.charset = Some(mime_info[1]
                .strip_prefix("charset=")
                .expect("Missing expected string pattern")
                .to_string()
            );
		    // sr.charset = Some(mime_info[1].split('=').last().unwrap().to_string());
        }
    }

    sr.exit_json("".to_string());
    //sr.exit_json(format!("{:?}", stats));
}
