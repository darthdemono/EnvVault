//! `unv node install`: turn this machine into a managed node in one command.
//!
//! Doing it by hand takes about ten steps (a system user, the binary, a config,
//! file permissions, a unit, a way to reload a service without root, a route to
//! the hub) and each one has been got wrong at least once. This builds the whole
//! list as data first (`plan`), prints it with `--dry-run`, and only then runs it.
//!
//! What it sets up, and what it deliberately does not:
//!
//! * The agent runs as an unprivileged `unv-node` user under a hardened unit.
//! * For each target it grants that user access to **that one file** and, because
//!   a write is "temp file then rename", write access to the file's directory.
//!   Nothing else on the machine is opened.
//! * Reloading a service needs root, and `sudo` is closed to the agent by
//!   `NoNewPrivileges`. So a root-owned systemd `.path` unit watches the target
//!   and runs `systemctl reload <unit>` when it changes. The agent never gains
//!   the ability to reload anything else.
//! * Targets are observe-only (`mode = "pull"`) unless you pass `apply=true`
//!   in the target spec.
//!
//! Linux with systemd only. Needs root.

use crate::error::{CliError, CliResult};
use std::path::PathBuf;

pub const USER: &str = "unv-node";
const STATE_DIR: &str = "/var/lib/unv-node";
const CONFIG_DIR: &str = "/etc/unv-node";
const SYSTEMD_DIR: &str = "/etc/systemd/system";
const BIN: &str = "/usr/local/bin/unv";
const RELAY_PORT: u16 = 18743;

/// One file the node manages.
#[derive(Clone, Debug, PartialEq)]
pub struct TargetSpec {
    pub id: String,
    pub path: PathBuf,
    pub project: String,
    pub exporter: String,
    /// `push` (vault to file) or `pull` (file to vault).
    pub mode: String,
    pub apply: bool,
    pub validate: Option<String>,
    /// A systemd unit to reload when the file changes, e.g. `wg-quick@wg0`.
    pub reload_unit: Option<String>,
    pub require_approval: bool,
}

#[derive(Clone, Debug)]
pub struct Options {
    pub hub: String,
    /// Reach a plain-HTTP hub on another machine through a loopback relay
    /// (`HOST:PORT`). The agent only talks plain HTTP to 127.0.0.1.
    pub relay: Option<String>,
    pub listen: Option<(String, String)>,
    pub targets: Vec<TargetSpec>,
    pub approver: Option<String>,
    pub interval_secs: u64,
}

/// One thing to do, in order.
#[derive(Clone, Debug, PartialEq)]
pub enum Step {
    /// Run a program.
    Run(Vec<String>),
    /// Create or overwrite a file with these bytes and this octal mode.
    Write {
        path: String,
        mode: u32,
        content: String,
    },
    /// Copy the running `unv` binary to this path.
    InstallBinary(String),
    /// Enrol with the hub (needs the token; done in-process).
    Enrol,
}

impl Step {
    pub fn describe(&self) -> String {
        match self {
            Step::Run(a) => a.join(" "),
            Step::Write { path, mode, .. } => format!("write {path} (mode {mode:o})"),
            Step::InstallBinary(p) => format!("install this binary as {p}"),
            Step::Enrol => "enrol with the hub".into(),
        }
    }
}

fn sh(args: &[&str]) -> Step {
    Step::Run(args.iter().map(|s| s.to_string()).collect())
}

/// `id=wg0,path=/etc/wireguard/wg0.conf,project=wg/vps,exporter=wireguard,...`
pub fn parse_target(spec: &str) -> CliResult<TargetSpec> {
    let mut t = TargetSpec {
        id: String::new(),
        path: PathBuf::new(),
        project: String::new(),
        exporter: String::new(),
        mode: "pull".into(),
        apply: false,
        validate: None,
        reload_unit: None,
        require_approval: false,
    };
    for part in spec.split(',').filter(|p| !p.trim().is_empty()) {
        let (k, v) = part.split_once('=').ok_or_else(|| {
            CliError::invalid(format!("target '{part}': expected key=value pairs"))
        })?;
        let v = v.trim();
        match k.trim() {
            "id" => t.id = v.into(),
            "path" => t.path = PathBuf::from(v),
            "project" => t.project = v.into(),
            "exporter" => t.exporter = v.into(),
            "mode" => t.mode = v.into(),
            "apply" => t.apply = v == "true",
            "validate" => t.validate = Some(v.into()),
            "reload" => t.reload_unit = Some(v.into()),
            "require_approval" => t.require_approval = v == "true",
            other => {
                return Err(CliError::invalid(format!(
                    "target: unknown key '{other}' (id, path, project, exporter, mode, apply, validate, reload, require_approval)"
                )))
            }
        }
    }
    for (name, empty) in [
        ("id", t.id.is_empty()),
        ("path", t.path.as_os_str().is_empty()),
        ("project", t.project.is_empty()),
        ("exporter", t.exporter.is_empty()),
    ] {
        if empty {
            return Err(CliError::invalid(format!("target needs {name}=…")));
        }
    }
    if t.mode != "push" && t.mode != "pull" {
        return Err(CliError::invalid("target mode is push or pull"));
    }
    if t.apply {
        t.mode = "push".into();
    }
    if t.apply && t.validate.is_none() && t.exporter == "wireguard" {
        // `wg-quick strip` re-runs itself under sudo, which the agent cannot use,
        // so the unprivileged check is structural only. The real syntax check is
        // `wg syncconf` inside the root-owned reload unit, which leaves the
        // running tunnel untouched when it fails.
        //
        // The command must name the file: `validate` runs with the new bytes
        // already in place and gives the command no stdin, so a bare `grep` read
        // an empty stream, failed every time, and the agent wrote and restored the
        // file on every beat (each write also triggered a reload).
        t.validate = Some(format!("grep -q \"^.Interface\" '{}'", t.path.display()));
    }
    Ok(t)
}

fn unit_name(t: &TargetSpec) -> String {
    let safe: String =
        t.id.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
    format!("unv-reload-{safe}")
}

/// The node's own config. Parsed back through `NodeConfig::parse` in the tests,
/// so what is written here is exactly what the agent will accept.
pub fn node_toml(o: &Options) -> String {
    let mut s = String::from(
        "# Written by `unv node install`. This file, and only this file, decides what\n\
         # the node may do; the hub cannot change it.\n",
    );
    s += &format!("interval_secs = {}\n", o.interval_secs);
    if let Some(a) = &o.approver {
        s += &format!("approver = \"{a}\"\n");
    }
    for t in &o.targets {
        s += "\n[[target]]\n";
        s += &format!("id = \"{}\"\n", t.id);
        s += &format!("path = '{}'\n", t.path.display());
        s += &format!("project = \"{}\"\n", t.project);
        s += &format!("exporter = \"{}\"\n", t.exporter);
        s += &format!("mode = \"{}\"\n", t.mode);
        if t.apply {
            s += "apply = true\n";
        }
        if let Some(v) = &t.validate {
            s += &format!(
                "validate = \"{}\"\n",
                v.replace('\\', "\\\\").replace('"', "\\\"")
            );
        }
        if t.require_approval {
            s += "require_approval = true\n";
        }
    }
    s
}

pub fn service_unit(o: &Options) -> String {
    let mut rw = vec![STATE_DIR.to_string()];
    for t in o.targets.iter().filter(|t| t.apply) {
        if let Some(dir) = t.path.parent() {
            let d = dir.display().to_string();
            if !rw.contains(&d) {
                rw.push(d);
            }
        }
    }
    let after = if o.relay.is_some() {
        "network-online.target unv-hub-relay.service"
    } else {
        "network-online.target"
    };
    format!(
        "[Unit]\nDescription=unv node agent\nAfter={after}\nWants=network-online.target\n\n\
         [Service]\nUser={USER}\nGroup={USER}\nEnvironment=UNV_NODE_DIR={STATE_DIR}\n\
         ExecStart={BIN} node run --config {CONFIG_DIR}/node.toml\nRestart=on-failure\nRestartSec=5\n\
         NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\n\
         ProtectKernelTunables=yes\nProtectControlGroups=yes\n\
         RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\nReadWritePaths={}\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        rw.join(" ")
    )
}

/// A root-owned pair: when the file changes, reload exactly one unit.
pub fn reload_units(t: &TargetSpec, unit: &str) -> (String, String) {
    let name = unit_name(t);
    let path_unit = format!(
        "[Unit]\nDescription=Reload {unit} when {} changes (written by unv node install)\n\n\
         [Path]\nPathChanged={}\nUnit={name}.service\n\n[Install]\nWantedBy=multi-user.target\n",
        t.path.display(),
        t.path.display()
    );
    let service = format!(
        "[Unit]\nDescription=Reload {unit}\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/systemctl reload {unit}\n"
    );
    (path_unit, service)
}

pub fn relay_unit(remote: &str) -> String {
    format!(
        "[Unit]\nDescription=Loopback relay to the unv hub (the agent only speaks plain HTTP to 127.0.0.1)\n\
         After=network-online.target\nWants=network-online.target\n\n\
         [Service]\nExecStart=/usr/bin/socat TCP-LISTEN:{RELAY_PORT},bind=127.0.0.1,fork,reuseaddr TCP:{remote}\n\
         Restart=always\nRestartSec=3\nDynamicUser=yes\nNoNewPrivileges=yes\nProtectSystem=strict\n\
         ProtectHome=yes\nPrivateTmp=yes\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}

/// The hub address the agent will actually use.
pub fn effective_hub(o: &Options) -> String {
    if o.relay.is_some() {
        format!("http://127.0.0.1:{RELAY_PORT}")
    } else {
        o.hub.clone()
    }
}

/// Everything to do, in order, up to (not including) starting the service.
pub fn plan(o: &Options) -> CliResult<Vec<Step>> {
    if o.targets.is_empty() {
        return Err(CliError::invalid("Give at least one --target"));
    }
    for t in &o.targets {
        if !t.path.is_absolute() {
            return Err(CliError::invalid(format!(
                "target '{}': path must be absolute",
                t.id
            )));
        }
        if t.reload_unit.is_some() && !t.apply {
            return Err(CliError::invalid(format!(
                "target '{}': reload only makes sense with apply=true",
                t.id
            )));
        }
    }
    let mut p = vec![
        sh(&[
            "sh",
            "-c",
            &format!(
                "id {USER} >/dev/null 2>&1 || useradd --system --home-dir {STATE_DIR} --create-home --shell /usr/sbin/nologin {USER}"
            ),
        ]),
        Step::InstallBinary(BIN.into()),
        sh(&["install", "-d", "-o", USER, "-g", USER, "-m", "700", CONFIG_DIR]),
        Step::Write {
            path: format!("{CONFIG_DIR}/node.toml"),
            mode: 0o600,
            content: node_toml(o),
        },
        sh(&["chown", &format!("{USER}:{USER}"), &format!("{CONFIG_DIR}/node.toml")]),
    ];
    for t in &o.targets {
        let file = t.path.display().to_string();
        let perm = if t.apply {
            "u:unv-node:rw"
        } else {
            "u:unv-node:r"
        };
        p.push(sh(&["setfacl", "-m", perm, &file]));
        if let Some(dir) = t.path.parent() {
            let d = dir.display().to_string();
            p.push(sh(&[
                "setfacl",
                "-m",
                if t.apply {
                    "u:unv-node:rwx"
                } else {
                    "u:unv-node:x"
                },
                &d,
            ]));
        }
        if let Some(unit) = &t.reload_unit {
            let (path_unit, service) = reload_units(t, unit);
            let n = unit_name(t);
            p.push(Step::Write {
                path: format!("{SYSTEMD_DIR}/{n}.path"),
                mode: 0o644,
                content: path_unit,
            });
            p.push(Step::Write {
                path: format!("{SYSTEMD_DIR}/{n}.service"),
                mode: 0o644,
                content: service,
            });
        }
    }
    if let Some(remote) = &o.relay {
        p.push(Step::Write {
            path: format!("{SYSTEMD_DIR}/unv-hub-relay.service"),
            mode: 0o644,
            content: relay_unit(remote),
        });
    }
    p.push(Step::Write {
        path: format!("{SYSTEMD_DIR}/unv-node.service"),
        mode: 0o644,
        content: service_unit(o),
    });
    p.push(sh(&["systemctl", "daemon-reload"]));
    if o.relay.is_some() {
        p.push(sh(&["systemctl", "enable", "--now", "unv-hub-relay"]));
    }
    p.push(Step::Enrol);
    p.push(sh(&["chown", "-R", &format!("{USER}:{USER}"), STATE_DIR]));
    for t in o.targets.iter().filter(|t| t.reload_unit.is_some()) {
        p.push(sh(&[
            "systemctl",
            "enable",
            "--now",
            &format!("{}.path", unit_name(t)),
        ]));
    }
    // `restart`, not `enable --now`: on a re-install the agent is already running
    // and must pick up the new binary and identity.
    p.push(sh(&["systemctl", "enable", "unv-node"]));
    p.push(sh(&["systemctl", "restart", "unv-node"]));
    Ok(p)
}

#[cfg(unix)]
pub fn execute(steps: &[Step], enrol: &mut dyn FnMut() -> CliResult, dry_run: bool) -> CliResult {
    use crate::error::Code;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    for (i, s) in steps.iter().enumerate() {
        eprintln!("[{}/{}] {}", i + 1, steps.len(), s.describe());
        if dry_run {
            continue;
        }
        match s {
            Step::Run(a) => {
                let st = std::process::Command::new(&a[0])
                    .args(&a[1..])
                    .status()
                    .map_err(|e| CliError::new(Code::Error, format!("{}: {e}", a[0])))?;
                if !st.success() {
                    return Err(CliError::new(
                        Code::Error,
                        format!("`{}` failed ({st})", a.join(" ")),
                    ));
                }
            }
            Step::Write {
                path,
                mode,
                content,
            } => {
                let mut f = std::fs::File::create(path)
                    .map_err(|e| CliError::new(Code::Error, format!("{path}: {e}")))?;
                f.write_all(content.as_bytes())
                    .map_err(|e| CliError::new(Code::Error, format!("{path}: {e}")))?;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode))
                    .map_err(|e| CliError::new(Code::Error, format!("{path}: {e}")))?;
            }
            Step::InstallBinary(dest) => {
                let me = std::env::current_exe().map_err(|e| {
                    CliError::new(Code::Error, format!("cannot find this binary: {e}"))
                })?;
                if me.as_path() != std::path::Path::new(dest) {
                    // Copy to a temp name and rename, so a running agent is not
                    // overwritten in place ("text file busy").
                    let tmp = format!("{dest}.new");
                    std::fs::copy(&me, &tmp)
                        .map_err(|e| CliError::new(Code::Error, format!("{tmp}: {e}")))?;
                    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
                        .map_err(|e| CliError::new(Code::Error, format!("{tmp}: {e}")))?;
                    std::fs::rename(&tmp, dest)
                        .map_err(|e| CliError::new(Code::Error, format!("{dest}: {e}")))?;
                }
            }
            Step::Enrol => enrol()?,
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn execute(_: &[Step], _: &mut dyn FnMut() -> CliResult, _: bool) -> CliResult {
    Err(CliError::invalid(
        "`unv node install` sets up a systemd service and works on Linux only",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::nodes::NodeConfig;

    fn opts(targets: Vec<TargetSpec>) -> Options {
        Options {
            hub: "https://hub.example:8743".into(),
            relay: None,
            listen: None,
            targets,
            approver: None,
            interval_secs: 30,
        }
    }

    fn wg(apply: bool) -> TargetSpec {
        parse_target(&format!(
            "id=wg0,path=/etc/wireguard/wg0.conf,project=wg/vps,exporter=wireguard,apply={apply}{}",
            if apply { ",reload=wg-quick@wg0" } else { "" }
        ))
        .unwrap()
    }

    #[test]
    fn the_generated_config_is_one_the_agent_accepts() {
        for apply in [false, true] {
            let t = wg(apply);
            let toml = node_toml(&opts(vec![t]));
            let c = NodeConfig::parse(&toml).unwrap_or_else(|e| panic!("{e}\n{toml}"));
            assert_eq!(c.targets[0].apply, apply);
            assert_eq!(c.targets[0].mode, if apply { "push" } else { "pull" });
        }
    }

    #[test]
    fn a_target_is_observe_only_unless_it_says_otherwise() {
        let t = parse_target("id=a,path=/etc/a,project=p,exporter=env").unwrap();
        assert!(!t.apply);
        assert_eq!(t.mode, "pull");
        assert!(t.validate.is_none());
    }

    #[test]
    fn a_wireguard_push_gets_an_unprivileged_structural_check() {
        let t = wg(true);
        let v = t.validate.unwrap();
        assert!(v.contains("Interface"));
        assert!(
            v.contains("/etc/wireguard/wg0.conf"),
            "the check must name the file: {v}"
        );
        assert!(!v.contains("wg-quick"));
    }

    #[test]
    fn the_default_wireguard_check_passes_a_real_config_and_refuses_junk() {
        use vault_core::nodes_apply::apply;
        let dir = std::env::temp_dir().join(format!("unv-install-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("wg0.conf");
        std::fs::write(&file, "[Interface]\nAddress = 10.0.0.1/24\n").unwrap();
        let t = parse_target(&format!(
            "id=wg0,path={},project=p,exporter=wireguard,apply=true",
            file.display()
        ))
        .unwrap();
        let cfg = NodeConfig::parse(&node_toml(&opts(vec![t]))).unwrap();
        let target = &cfg.targets[0];
        let good = b"[Interface]\nAddress = 10.0.0.1/24\nListenPort = 51820\n";
        let sha = |b: &[u8]| vault_core::nodes_apply::sha256_hex(b);
        apply(target, good, &sha(good), &dir).expect("a real config must pass the check");
        let bad = b"nothing useful\n";
        let e = apply(target, bad, &sha(bad), &dir).unwrap_err();
        assert!(e.contains("validate failed"), "{e}");
        assert_eq!(
            std::fs::read(&file).unwrap(),
            good,
            "the refused file was not restored"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mistakes_in_a_target_are_named() {
        assert!(parse_target("id=a,path=/x,project=p").is_err());
        assert!(parse_target("id=a,path=/x,project=p,exporter=e,colour=red").is_err());
        assert!(parse_target("id=a,path=/x,project=p,exporter=e,mode=sideways").is_err());
        let err = plan(&opts(vec![parse_target(
            "id=a,path=/etc/a,project=p,exporter=env,reload=nginx",
        )
        .unwrap()]))
        .unwrap_err();
        assert!(err.to_string().contains("apply=true"), "{err}");
    }

    #[test]
    fn only_a_pushing_target_can_write_its_directory() {
        let read = plan(&opts(vec![wg(false)])).unwrap();
        let flat: Vec<String> = read.iter().map(Step::describe).collect();
        assert!(flat
            .iter()
            .any(|s| s == "setfacl -m u:unv-node:r /etc/wireguard/wg0.conf"));
        assert!(flat
            .iter()
            .any(|s| s == "setfacl -m u:unv-node:x /etc/wireguard"));
        assert!(!flat.iter().any(|s| s.contains("rwx")));

        let push = plan(&opts(vec![wg(true)])).unwrap();
        let flat: Vec<String> = push.iter().map(Step::describe).collect();
        assert!(flat
            .iter()
            .any(|s| s == "setfacl -m u:unv-node:rw /etc/wireguard/wg0.conf"));
        assert!(flat
            .iter()
            .any(|s| s == "setfacl -m u:unv-node:rwx /etc/wireguard"));
    }

    #[test]
    fn the_service_may_write_only_what_it_manages() {
        let u = service_unit(&opts(vec![wg(true)]));
        assert!(u.contains("ReadWritePaths=/var/lib/unv-node /etc/wireguard"));
        assert!(u.contains("NoNewPrivileges=yes"));
        let u = service_unit(&opts(vec![wg(false)]));
        assert!(u.contains("ReadWritePaths=/var/lib/unv-node\n"));
    }

    #[test]
    fn reloading_is_a_root_unit_watching_one_file_for_one_service() {
        let t = wg(true);
        let (path, service) = reload_units(&t, "wg-quick@wg0");
        assert!(path.contains("PathChanged=/etc/wireguard/wg0.conf"));
        assert!(path.contains("Unit=unv-reload-wg0.service"));
        assert!(service.contains("ExecStart=/usr/bin/systemctl reload wg-quick@wg0"));
        assert!(
            !service.contains("User="),
            "the reload runs as root by design"
        );
    }

    #[test]
    fn a_relay_replaces_the_hub_url_with_the_loopback() {
        let mut o = opts(vec![wg(false)]);
        o.hub = "http://10.10.0.2:8743".into();
        o.relay = Some("10.10.0.2:8743".into());
        assert_eq!(effective_hub(&o), "http://127.0.0.1:18743");
        let steps: Vec<String> = plan(&o).unwrap().iter().map(Step::describe).collect();
        assert!(steps.iter().any(|s| s.contains("unv-hub-relay.service")));
        assert!(service_unit(&o).contains("unv-hub-relay.service"));
    }

    #[test]
    fn the_plan_enrols_before_it_starts_the_agent() {
        let steps = plan(&opts(vec![wg(true)])).unwrap();
        let enrol = steps.iter().position(|s| *s == Step::Enrol).unwrap();
        let start = steps
            .iter()
            .position(|s| s.describe() == "systemctl restart unv-node")
            .unwrap();
        assert!(enrol < start);
        assert_eq!(
            steps.last().unwrap().describe(),
            "systemctl restart unv-node"
        );
    }
}
