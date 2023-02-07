// Flamingo - Peer-to-Peer VPN
// Copyright (C) 2023  John Lee
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{env, fs, path::Path, process::Command};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    // Process manpage using asciidoctor command
    println!("cargo:rerun-if-changed=flamingo.adoc");
    fs::create_dir_all(&out_dir).unwrap();
    fs::copy("flamingo.adoc", Path::new(&out_dir).join("flamingo.adoc")).unwrap();
    match Command::new("asciidoctor")
        .args(&["-b", "manpage", "flamingo.adoc"])
        .current_dir(&Path::new(&out_dir))
        .status()
    {
        Ok(_) => {
            Command::new("gzip").args(&["flamingo.1"]).current_dir(&Path::new(&out_dir)).status().unwrap();
            fs::copy(Path::new(&out_dir).join("flamingo.1.gz"), "target/flamingo.1.gz").unwrap();
        }
        Err(err) => {
            println!("cargo:warning=Error building manpage: {}", err);
            println!("cargo:warning=The manpage will not be build. Do you have 'asciidoctor'?");
        }
    }
}
