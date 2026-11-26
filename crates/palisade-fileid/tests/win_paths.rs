//! Path forms from the OS (#54): a mapped drive, a short name and a DFS
//! namespace path to one file on a local SMB share all normalise to the
//! key of its long UNC path. Runs only on Windows with `os-trust`, so on
//! the Windows CI runners, which run tests elevated (creating a share and
//! setting a short name need administrator rights; the tests fail rather
//! than skip without them).
//!
//! A DFS namespace needs a namespace server, which a hosted runner does not
//! have. The namespace here is a fake resolver behind the real
//! [`DfsCache`]; the OS lookup (`OsDfs`) is checked only for a path that is
//! not in a namespace. A real namespace waits on the VM harness (#26).

#![cfg(all(windows, feature = "os-trust"))]
#![allow(clippy::unwrap_used)]

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::process::Command;

use palisade_fileid::fsctx::dfs::{DfsCache, DfsOutcome, DfsReferral, DfsResolver};
use palisade_fileid::fsctx::{NormalizedPath, Root, normalize_win32};
use palisade_fileid::win::paths::{OsDfs, mapped_drive_unc, read_context, read_path_forms};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn plain(p: &std::path::Path) -> String {
    let s = p.to_str().unwrap();
    s.strip_prefix(r"\\?\").unwrap_or(s).to_owned()
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{cmd:?} failed: {text}");
    text
}

/// A local folder shared over SMB, with a mapped drive letter; both removed
/// when dropped.
struct Share {
    name: String,
    drive: Option<char>,
    _dir: Scratch,
}

impl Drop for Share {
    fn drop(&mut self) {
        if let Some(d) = self.drive {
            let _ = Command::new("net")
                .args(["use", &format!("{d}:"), "/delete", "/y"])
                .output();
        }
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg("Remove-SmbShare -Name $env:PALISADE_SHARE -Force")
            .env("PALISADE_SHARE", &self.name)
            .output();
    }
}

/// Shares a new folder holding `Long Sub Folder\tool.exe`, gives the
/// subfolder the short name `LONGSU~9`, and maps a free drive letter to the
/// share.
fn share(tag: &str) -> Share {
    let dir = std::env::temp_dir().join(format!("palisade-paths-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let dir = Scratch(std::fs::canonicalize(&dir).unwrap());
    let sub = dir.0.join("Long Sub Folder");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("tool.exe"), b"MZ").unwrap();
    let set_short = || {
        Command::new("fsutil")
            .args(["file", "setshortname"])
            .arg(plain(&sub))
            .arg("LONGSU~9")
            .output()
            .unwrap()
    };
    if !set_short().status.success() {
        // The volume may have short names turned off; turn them on for it
        // (the runner is discarded afterwards) and try again.
        let volume = plain(&dir.0).chars().take(2).collect::<String>();
        run(Command::new("fsutil").args(["8dot3name", "set", &volume, "0"]));
        let out = set_short();
        assert!(out.status.success(), "setshortname: {out:?}");
    }
    let name = format!("palisade-paths-{tag}-{}", std::process::id());
    run(Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        // Values go through the environment, never into the script source,
        // so a path with a `'` cannot break it.
        .arg("New-SmbShare -Name $env:PALISADE_SHARE -Path $env:PALISADE_PATH -ReadAccess 'Everyone' | Out-Null")
        .env("PALISADE_SHARE", &name)
        .env("PALISADE_PATH", plain(&dir.0)));
    let mut share = Share {
        name,
        drive: None,
        _dir: dir,
    };
    for d in ('M'..='Z').rev() {
        if std::path::Path::new(&format!("{d}:\\")).exists() {
            continue;
        }
        let ok = Command::new("net")
            .args([
                "use",
                &format!("{d}:"),
                &format!(r"\\localhost\{}", share.name),
            ])
            .output()
            .unwrap()
            .status
            .success();
        if ok {
            share.drive = Some(d);
            break;
        }
    }
    assert!(share.drive.is_some(), "no drive letter could be mapped");
    share
}

/// A fake namespace `\\corp\dfs\apps` whose one link leads to `target`.
struct FakeNamespace(NormalizedPath);

impl DfsResolver for FakeNamespace {
    fn referral(&self, path: &NormalizedPath) -> io::Result<Option<DfsReferral>> {
        let entry = normalize_win32(r"\\corp\dfs\apps").unwrap();
        Ok(path.starts_with(&entry).then(|| DfsReferral {
            entry,
            target: self.0.clone(),
        }))
    }
}

#[test]
fn mapped_drive_short_name_and_dfs_reach_one_canonical_form() {
    let s = share("canon");
    let drive = s.drive.unwrap();
    let long_unc = format!(r"\\localhost\{}\Long Sub Folder\tool.exe", s.name);
    let expected = normalize_win32(&long_unc).unwrap().match_key().unwrap();

    // The long UNC path itself.
    let f = File::open(&long_unc).unwrap();
    let forms = read_path_forms(&long_unc, &f, None);
    assert_eq!(forms.network_key().as_deref(), Some(expected.as_str()));
    assert!(matches!(
        forms.final_path.as_ref().unwrap().root(),
        Root::Unc { .. }
    ));

    // A short-name spelling of it.
    let short_unc = format!(r"\\localhost\{}\LONGSU~9\tool.exe", s.name);
    let f = File::open(&short_unc).unwrap();
    let forms = read_path_forms(&short_unc, &f, None);
    assert!(forms.normalized.as_ref().unwrap().match_key().is_err());
    assert_eq!(forms.network_key().as_deref(), Some(expected.as_str()));
    assert_eq!(forms.lexical_key().as_deref(), Some(expected.as_str()));

    // Through the mapped drive, in this process's logon session.
    let mapped = format!(r"{drive}:\Long Sub Folder\tool.exe");
    let n = normalize_win32(&mapped).unwrap();
    assert_eq!(mapped_drive_unc(&n).unwrap().match_key().unwrap(), expected);
    let f = File::open(&mapped).unwrap();
    let ctx = read_context(&mapped, &f, None);
    assert_eq!(ctx.path.network_key().as_deref(), Some(expected.as_str()));
    assert_eq!(
        ctx.path.dos_path.as_ref().unwrap().match_key().unwrap(),
        n.match_key().unwrap()
    );
    let vol = ctx.volume.unwrap();
    assert_eq!(
        vol.location_class(),
        palisade_fileid::fsctx::LocationClass::Network
    );

    // The mapped drive and a short name together.
    let both = format!(r"{drive}:\LONGSU~9\tool.exe");
    let f = File::open(&both).unwrap();
    let forms = read_path_forms(&both, &f, None);
    assert_eq!(forms.network_key().as_deref(), Some(expected.as_str()));

    // A DFS namespace path whose link leads to the share (fake namespace,
    // real cache).
    let target = normalize_win32(&format!(r"\\localhost\{}", s.name)).unwrap();
    let mut dfs = DfsCache::new(FakeNamespace(target));
    let ns = normalize_win32(r"\\corp\dfs\apps\Long Sub Folder\tool.exe").unwrap();
    match dfs.resolve(&ns) {
        DfsOutcome::Resolved(t) => assert_eq!(t.match_key().unwrap(), expected),
        other => panic!("{other:?}"),
    }
}

#[test]
fn local_paths_have_nt_and_guid_forms_and_no_network_form() {
    let dir = std::env::temp_dir();
    let file = dir.join(format!("palisade-paths-local-{}.txt", std::process::id()));
    std::fs::write(&file, b"x").unwrap();
    // `%TEMP%` on the runners holds an 8.3 short name.
    let text = file.to_str().unwrap().to_owned();
    let f = File::open(&file).unwrap();
    let ctx = read_context(&text, &f, None);
    let p = &ctx.path;
    assert!(p.nt_path.is_some() && p.volume_guid_path.is_some() && p.final_path.is_some());
    assert_eq!(p.lexical_key(), p.case_folded(), "{p:?}");
    assert_eq!(p.network_key(), None);
    assert!(ctx.volume.unwrap().fs_type.is_some());
    drop(f);
    let _ = std::fs::remove_file(file);
}

#[test]
fn the_os_dfs_lookup_reports_a_plain_share_as_not_dfs() {
    let s = share("dfs");
    let mut dfs = DfsCache::new(OsDfs);
    let p = normalize_win32(&format!(r"\\localhost\{}\Long Sub Folder\tool.exe", s.name)).unwrap();
    assert_eq!(dfs.resolve(&p), DfsOutcome::NotDfs);
}
