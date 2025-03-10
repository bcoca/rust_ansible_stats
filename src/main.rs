/// Returns stat and other info about a file
extern crate exitcode;

use checksums::{Algorithm, hash_file};
use phf::phf_map;
use serde::{Serialize, Deserialize};

use std::collections::HashSet;
use std::env;
use std::os::unix::fs::PermissionsExt;
use std::ops::Not;
use std::path::{Path, PathBuf};
use std::process;
use std::process::Command;
use std::str::FromStr;

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

// TODO: try to get serde to set defaults
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

#[derive(Serialize, Debug, Default)] // TODO: gen from AnsibleResult macro
struct StatResult {

    // common, move to macro
    warnings: HashSet<String>,

    pub msg: Option<String>,
    pub changed: bool,
    pub failed: bool,
    pub traceback: Option<String>,

    // module specific
    pub atime: Option<String>,
    pub attr_flags: Option<String>,
    pub attributes: Vec<String>,
    pub block_size: Option<u64>,
    pub blocks: Option<u32>,
    pub charset: Option<String>,
    pub checksum: Option<String>,
    pub ctime: Option<String>,
    pub dev: Option<u32>,
    pub device_type: Option<u32>,
    pub executable: Option<bool>,
    pub exists: bool,
    pub gid: Option<u32>,
    pub gr_name: Option<String>,
    pub inode: Option<u64>,
    pub isblk: Option<bool>,
    pub ischr: Option<bool>,
    pub isdir: Option<bool>,
    pub isfifo: Option<bool>,
    pub isgid: Option<bool>,
    pub islnk: Option<bool>,
    pub isreg: Option<bool>,
    pub issock: Option<bool>,
    pub isuid: Option<bool>,
    pub lnk_source: Option<String>,
    pub lnk_target: Option<String>, // NOTE: use Path/Display?
    pub mimetype: Option<String>,
    pub mode: Option<String>,
    pub mtime: Option<String>,
    pub nlink: Option<u32>,
    pub path: String, // NOTE: use Path/Display?
    pub pw_name: Option<String>,
    pub readable: Option<bool>,
    pub rgrp: Option<bool>,
    pub roth: Option<bool>,
    pub rusr: Option<bool>,
    pub size: Option<u64>,
    pub uid: Option<u32>,
    pub version: Option<String>,
    pub wgrp: Option<bool>,
    pub woth: Option<bool>,
    pub writable: Option<bool>,
    pub wusr: Option<bool>,
    pub xgrp: Option<bool>,
    pub xoth: Option<bool>,
    pub xusr: Option<bool>,
}

// TODO: move common methods to AnsibleResult trait/macro
impl StatResult {

    fn warn(&mut self, warning: String) {
            self.warnings.insert(warning);
    }

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
            self.mimetype = Some(mime_info[0].to_string());
            self.charset = Some(mime_info[1]
                .strip_prefix("charset=")
                .expect("Missing expected string pattern")
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
        if res.len() == 2 {
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
        ..StatResult::default()
    };

    // Get inputs
    let args: Vec<String> = env::args().collect();
    let args_file = Path::new(&args[1]);
    let m = args_from_file(args_file);

    // Handle symlink
    let pb: PathBuf;
    let mut path = Path::new(&m.path);
    sr.path = String::from_str(path.to_str().unwrap()).unwrap();
    if path.is_symlink() {
        pb = path.read_link().expect("Could not follow symlink"); //NOTE: resolve recursively? check py version
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
    sr.islnk = Some(path.is_symlink());

    // Check if path exists, error if permissions issue
    let bad_path = |e| {sr.fail_json(format!("Cannot stat path ({:?}): {}", path, e)); return false;};
    sr.exists = path.try_exists().unwrap_or_else(bad_path);

    // return now if no path, no other info will be available
    if sr.exists.not() {
        sr.exit_json(Some(format!("Path ({:?}) does not exist.", path)));
    }

    // now get info about path/link, using symlink cause its more complete in case we didn't 'follow' above.
    let stats = path.symlink_metadata().unwrap();

    //TODO debug
    eprintln!("{:?}", stats);
    // TODO: move to an sr.update_from_stats(stats)

    // extended file data
    // sr.ischr
    // sr.isblk
    // sr.isreg
    // sr.isfifo
    // nlink
    // blocks
    // block_size

	// sr.uid = 
	// sr.gid = 


    // user perms
    // sr.readable
    // sr.writable
    // rgrp
    // roth
    // rusr
    // wgrp
    // woth
    // wusr
    // xgrp
    // xoth
    // xusr

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
        sr.set_file_attr(path);
	}

    // get mimetype and charset
    if m.get_mime.expect("Invalid boolean for get_mime") {
        sr.set_mime_info(path);
    }

    sr.exit_json(None);
}
