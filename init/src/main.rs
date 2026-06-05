//! RunixOS stage-0 init - the initramfs `/init`.
//!
//! This runs as PID 1 right after the kernel unpacks the initramfs, before the
//! real system exists. Its whole job is to turn a composefs deployment on the
//! data partition into a working `/Core` root and hand off to Rev:
//!
//!   1. mount the early virtual filesystems (/proc /sys /dev /run)
//!   2. read the kernel cmdline (which deployment, which data device)
//!   3. mount the data partition (holds the content-addressed repo)
//!   4. assemble the new root: /sysroot tmpfs + verity-sealed /Core (composefs)
//!      + the writable FHS dirs (/Vault /Space /Construct /Transit)
//!   5. switch_root into it and exec Rev as the real PID 1
//!
//! It shares the exact crates the updater uses: `runix-deployment` (mount the
//! composefs image) and `runix-bootctl` (version type). Rignite selects the
//! deployment and passes `runix.deploy=<version>` on the cmdline; this init
//! trusts that selection (boot-control accounting happens in Rignite).
//!
//! On any fatal error it does NOT exit (PID 1 exiting panics the kernel) - it
//! reports and parks. Dropping to the recovery environment is a future step.

use anyhow::{Context, Result, bail};
use rustix::mount::{MountFlags, UnmountFlags, mount, mount_bind, mount_move, unmount};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

/// No filesystem-specific mount data (the `data` arg of mount(2)).
const NODATA: Option<&core::ffi::CStr> = None;

const SYSROOT: &str = "/sysroot";
const DATA: &str = "/run/data";
const DEFAULT_INIT: &str = "/Core/Bin/rev";
const DEFAULT_DATAFS: &str = "btrfs";

fn main() {
    if let Err(e) = run() {
        log(&format!("FATAL: {e:#}"));
        park();
    }
}

fn run() -> Result<()> {
    log("RunixOS stage-0 init");
    early_mounts().context("early virtual filesystem mounts")?;
    let cmd = Cmdline::read().context("reading kernel cmdline")?;
    log(&format!(
        "deploy={} data={} datafs={} init={}",
        cmd.deploy, cmd.data, cmd.datafs, cmd.init
    ));
    mount_data(&cmd).context("mounting data partition")?;
    assemble_root(&cmd).context("assembling /Core root")?;
    switch_root_exec(&cmd).context("switch_root into the new root")?;
    bail!("switch_root returned without exec - unreachable");
}

// ---- cmdline ----

struct Cmdline {
    /// Deployment version to boot (e.g. "7.0.12"); selects the composefs image.
    deploy: String,
    /// Data partition device holding the repo (e.g. "/dev/sda2").
    data: String,
    /// Filesystem type of the data partition.
    datafs: String,
    /// Expected verity root hash (signed), if the cmdline carries it.
    #[allow(dead_code)]
    verity: Option<String>,
    /// Real init to exec after switch_root.
    init: String,
}

impl Cmdline {
    fn read() -> Result<Self> {
        let raw = std::fs::read_to_string("/proc/cmdline").context("reading /proc/cmdline")?;
        parse_cmdline(&raw)
    }

    /// The deployment version parsed into the boot-control Version type.
    fn version(&self) -> Result<runix_bootctl::Version> {
        let mut it = self.deploy.split('.');
        let mut next = || -> Result<u32> {
            it.next()
                .and_then(|s| s.parse().ok())
                .context("runix.deploy must be MAJOR.MINOR.PATCH")
        };
        let (a, b, c) = (next()?, next()?, next()?);
        Ok(runix_bootctl::Version::new(a, b, c))
    }
}

fn parse_cmdline(s: &str) -> Result<Cmdline> {
    let (mut deploy, mut data, mut datafs, mut verity, mut init) = (None, None, None, None, None);
    for tok in s.split_whitespace() {
        let Some((k, v)) = tok.split_once('=') else {
            continue;
        };
        match k {
            "runix.deploy" => deploy = Some(v.to_string()),
            "runix.data" => data = Some(v.to_string()),
            "runix.datafs" => datafs = Some(v.to_string()),
            "runix.verity" => verity = Some(v.to_string()),
            "init" => init = Some(v.to_string()),
            _ => {}
        }
    }
    Ok(Cmdline {
        deploy: deploy.context("missing runix.deploy on kernel cmdline")?,
        data: data.context("missing runix.data on kernel cmdline")?,
        datafs: datafs.unwrap_or_else(|| DEFAULT_DATAFS.to_string()),
        verity,
        init: init.unwrap_or_else(|| DEFAULT_INIT.to_string()),
    })
}

// ---- stages ----

fn early_mounts() -> Result<()> {
    mkdir("/proc")?;
    mkdir("/sys")?;
    mkdir("/dev")?;
    mkdir("/run")?;
    vfs("proc", "/proc", "proc")?;
    vfs("sysfs", "/sys", "sysfs")?;
    vfs("devtmpfs", "/dev", "devtmpfs")?;
    vfs("tmpfs", "/run", "tmpfs")?;
    Ok(())
}

fn mount_data(cmd: &Cmdline) -> Result<()> {
    mkdir(DATA)?;
    mount(&cmd.data, DATA, &cmd.datafs, MountFlags::empty(), NODATA)
        .with_context(|| format!("mount {} ({}) at {DATA}", cmd.data, cmd.datafs))
}

fn assemble_root(cmd: &Cmdline) -> Result<()> {
    vfs("tmpfs", SYSROOT, "tmpfs")?;
    for d in ["Core", "Vault", "Space", "Construct", "Transit", "proc", "sys", "dev", "run"] {
        mkdir(&format!("{SYSROOT}/{d}"))?;
    }

    // Mount the verity-sealed /Core from the composefs deployment.
    let repo = runix_deployment::Repo::open(format!("{DATA}/repo"))
        .context("opening composefs repository on data partition")?;
    let dep = runix_deployment::Deployment {
        version: cmd.version()?,
        verity_id: cmd.verity.clone().unwrap_or_default(),
    };
    repo.mount(&dep, Path::new(&format!("{SYSROOT}/Core")))
        .context("mounting composefs /Core")?;
    log("mounted /Core (composefs)");

    // Writable scratch; persistent dirs are bind-mounted from the data fs.
    vfs("tmpfs", &format!("{SYSROOT}/Transit"), "tmpfs")?;
    bind_if_present(&format!("{DATA}/Vault"), &format!("{SYSROOT}/Vault"));
    bind_if_present(&format!("{DATA}/Space"), &format!("{SYSROOT}/Space"));
    bind_if_present(&format!("{DATA}/Construct"), &format!("{SYSROOT}/Construct"));
    Ok(())
}

fn switch_root_exec(cmd: &Cmdline) -> Result<()> {
    // Carry the early mounts across into the new root.
    for d in ["proc", "sys", "dev", "run"] {
        mount_move(format!("/{d}"), format!("{SYSROOT}/{d}"))
            .with_context(|| format!("moving /{d} into {SYSROOT}"))?;
    }

    // The classic switch_root dance: make /sysroot the new "/".
    rustix::process::chdir(SYSROOT).context("chdir /sysroot")?;
    mount_move(".", "/").context("mount --move /sysroot /")?;
    rustix::process::chroot(".").context("chroot .")?;
    rustix::process::chdir("/").context("chdir /")?;

    log(&format!("exec {} as PID 1", cmd.init));
    // exec replaces this process; only returns on failure.
    Err(Command::new(&cmd.init).exec()).with_context(|| format!("exec {}", cmd.init))?
}

// ---- helpers ----

fn vfs(source: &str, target: &str, fstype: &str) -> Result<()> {
    mount(source, target, fstype, MountFlags::empty(), NODATA)
        .with_context(|| format!("mount {fstype} at {target}"))
}

fn bind_if_present(src: &str, target: &str) {
    if Path::new(src).exists() {
        if let Err(e) = mount_bind(src, target) {
            log(&format!("warn: bind {src} -> {target} failed: {e}"));
        }
    } else {
        log(&format!("note: {src} absent, skipping bind"));
    }
}

fn mkdir(path: &str) -> Result<()> {
    match std::fs::create_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("mkdir {path}")),
    }
}

fn log(msg: &str) {
    // Kernel console; eprintln goes to fd 2 which the kernel wires to the console.
    eprintln!("[runix-init] {msg}");
}

/// Park forever instead of exiting (PID 1 exiting triggers a kernel panic).
fn park() -> ! {
    log("parking (recovery handoff not yet implemented)");
    loop {
        // Best-effort: unmount nothing, just sleep in a syscall.
        let _ = unmount("/nonexistent", UnmountFlags::empty());
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_cmdline() {
        let c = parse_cmdline(
            "ro quiet runix.deploy=7.0.12 runix.data=/dev/sda2 runix.datafs=f2fs init=/Core/Bin/rev runix.verity=abcd",
        )
        .unwrap();
        assert_eq!(c.deploy, "7.0.12");
        assert_eq!(c.data, "/dev/sda2");
        assert_eq!(c.datafs, "f2fs");
        assert_eq!(c.init, "/Core/Bin/rev");
        assert_eq!(c.verity.as_deref(), Some("abcd"));
        let v = c.version().unwrap();
        assert_eq!((v.major, v.minor, v.patch), (7, 0, 12));
    }

    #[test]
    fn applies_defaults() {
        let c = parse_cmdline("runix.deploy=1.2.3 runix.data=/dev/vda1").unwrap();
        assert_eq!(c.datafs, DEFAULT_DATAFS);
        assert_eq!(c.init, DEFAULT_INIT);
        assert!(c.verity.is_none());
    }

    #[test]
    fn requires_deploy_and_data() {
        assert!(parse_cmdline("runix.data=/dev/sda2").is_err());
        assert!(parse_cmdline("runix.deploy=1.0.0").is_err());
    }

    #[test]
    fn rejects_bad_version() {
        let c = parse_cmdline("runix.deploy=7.x runix.data=/dev/sda2").unwrap();
        assert!(c.version().is_err());
    }
}
