mod auth;
mod channel;
mod config;
mod dns;
mod embed;
mod hls_in;
mod http;
mod ts;

use crate::auth::{hash_password_sync, valid_login, valid_password};
use crate::config::{
    atomic_write_file_sync, default_cfg_obj, load_disk_config, load_json_obj_or_cfg,
    resolve_default_config_path,
};
use crate::http::{
    serve_http_port, spawn_background_tasks, AppState, ASTRIKA_CLI_VERSION, ASTRIKA_VERSION,
};
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Arc;

const DEFAULT_SVC: &str = "astrika";
const DEFAULT_PORT: u16 = 8000;
const BIN_PATH: &str = "/usr/bin/astrika";
const CONF_DIR: &str = "/etc/astrika";
const STATE_DIR: &str = "/var/lib/astrika";
const SYS_DIR: &str = "/etc/systemd/system";
const ASTRIKA_USER: &str = "astrika";

fn print_help() {
    println!(
        "Astrika {ver} - High-Performance Async IPTV Streaming Server (Rust)\n\
         \n\
         Usage:\n\
           astrika [-c <config>] [-p <port>] [--host <ip>] [--pid <file>]\n\
           astrika init [port] [name] [--start|--no-start]\n\
           astrika remove [port|name] [--purge]\n\
           astrika purge\n\
           astrika reset-password [user] [pass] [-c <config>]\n\
           astrika --version | -v\n\
           astrika --help | -h\n\
         \n\
         Environment:\n\
           ASTRIKA_CONFIG_FILE       Override default config path\n\
           ASTRIKA_WORKERS           Worker thread count (default: clamp(cpus, 2, 4))\n\
           ASTRIKA_VERIFY_TLS=1      Enforce strict TLS certificate verification\n\
           ASTRIKA_DISABLE_EXTRA_PORTS=1  Disable extra HTTP output ports",
        ver = ASTRIKA_CLI_VERSION
    );
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn valid_svc_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn parse_port(s: &str) -> Option<u16> {
    let p: u16 = s.parse().ok()?;
    if p == 0 {
        None
    } else {
        Some(p)
    }
}

fn run_cmd(prog: &str, args: &[&str]) -> bool {
    Command::new(prog)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_cmd_quiet(prog: &str, args: &[&str]) -> bool {
    Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn ensure_system_user() {
    if run_cmd_quiet("id", &["-u", ASTRIKA_USER]) {
        return;
    }
    let _ = run_cmd_quiet(
        "useradd",
        &[
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            ASTRIKA_USER,
        ],
    );
}

fn chown_astrika(path: &Path, recursive: bool) {
    let target = format!("{}:{}", ASTRIKA_USER, ASTRIKA_USER);
    if recursive {
        let _ = run_cmd_quiet("chown", &["-R", &target, &path.to_string_lossy()]);
    } else {
        let _ = run_cmd_quiet("chown", &[&target, &path.to_string_lossy()]);
    }
}

fn write_unit_file(svc: &str, port: u16, conf: &Path) -> Result<(), String> {
    let unit_path = Path::new(SYS_DIR).join(format!("{}.service", svc));
    let content = format!(
        "[Unit]\n\
         Description=Astrika IPTV Streaming Server ({svc})\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User={user}\n\
         Group={user}\n\
         Environment=\"ASTRIKA_CONFIG_FILE={conf}\"\n\
         ExecStart={bin} -c {conf} -p {port}\n\
         ExecReload=/bin/kill -HUP $MAINPID\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         LimitNOFILE=65536\n\
         NoNewPrivileges=true\n\
         PrivateTmp=true\n\
         ProtectSystem=full\n\
         ReadWritePaths={conf_dir} {state_dir}\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        svc = svc,
        user = ASTRIKA_USER,
        conf = conf.display(),
        bin = BIN_PATH,
        port = port,
        conf_dir = CONF_DIR,
        state_dir = STATE_DIR
    );
    atomic_write_file_sync(&unit_path, content.as_bytes(), 0o644)
        .map_err(|e| format!("failed to write {}: {}", unit_path.display(), e))
}

fn cmd_init(args: &[String]) -> ExitCode {
    if !is_root() {
        eprintln!("Error: 'astrika init' must be run as root (use sudo).");
        return ExitCode::from(1);
    }

    let mut port: u16 = DEFAULT_PORT;
    let mut svc = DEFAULT_SVC.to_string();
    let mut explicit_name = false;
    let mut do_start = true;

    for a in args {
        match a.as_str() {
            "--start" => do_start = true,
            "--no-start" => do_start = false,
            _ if a.starts_with('-') => {
                eprintln!("Unknown option for init: {}", a);
                return ExitCode::from(2);
            }
            _ => {
                if let Some(p) = parse_port(a) {
                    port = p;
                } else if valid_svc_name(a) {
                    svc = a.clone();
                    explicit_name = true;
                } else {
                    eprintln!("Invalid argument: {}", a);
                    return ExitCode::from(2);
                }
            }
        }
    }

    if !explicit_name && port != DEFAULT_PORT {
        svc = format!("{}-{}", DEFAULT_SVC, port);
    }

    ensure_system_user();

    // Install current executable to /usr/bin/astrika if not already running from there
    if let Ok(exe) = std::env::current_exe() {
        let dest = Path::new(BIN_PATH);
        if exe != dest {
            if let Err(e) = fs::copy(&exe, dest) {
                eprintln!("Warning: could not copy binary to {}: {}", BIN_PATH, e);
            } else {
                let _ = fs::set_permissions(dest, fs::Permissions::from_mode(0o755));
            }
        }
    }

    let _ = fs::create_dir_all(CONF_DIR);
    let _ = fs::create_dir_all(STATE_DIR);

    let conf_path = Path::new(CONF_DIR).join(format!("{}.conf", svc));
    if !conf_path.exists() {
        // Seamless migration from legacy /etc/astrag/astrag.conf if present
        let legacy = Path::new("/etc/astrag/astrag.conf");
        if svc == DEFAULT_SVC && legacy.exists() {
            if let Ok(data) = fs::read(legacy) {
                if let Err(e) = atomic_write_file_sync(&conf_path, &data, 0o640) {
                    eprintln!("Error migrating {}: {}", legacy.display(), e);
                    return ExitCode::from(1);
                }
                println!(
                    "Migrated existing configuration from {} -> {}",
                    legacy.display(),
                    conf_path.display()
                );
            }
        }
    }

    if !conf_path.exists() {
        let cfg = default_cfg_obj(port, "0.0.0.0");
        let mut bytes = serde_json::to_vec_pretty(&cfg).unwrap_or_default();
        bytes.push(b'\n');
        if let Err(e) = atomic_write_file_sync(&conf_path, &bytes, 0o640) {
            eprintln!("Error writing config {}: {}", conf_path.display(), e);
            return ExitCode::from(1);
        }
    }

    chown_astrika(Path::new(CONF_DIR), true);
    chown_astrika(Path::new(STATE_DIR), true);

    if let Err(e) = write_unit_file(&svc, port, &conf_path) {
        eprintln!("Error: {}", e);
        return ExitCode::from(1);
    }

    let _ = run_cmd("systemctl", &["daemon-reload"]);
    let _ = run_cmd("systemctl", &["enable", &svc]);
    if do_start {
        let _ = run_cmd("systemctl", &["restart", &svc]);
    }

    // Open UFW firewall port if UFW is active
    if let Ok(out) = Command::new("ufw").arg("status").output() {
        let s = String::from_utf8_lossy(&out.stdout);
        if s.contains("Status: active") {
            let _ = run_cmd_quiet("ufw", &["allow", &format!("{}/tcp", port)]);
        }
    }

    println!(
        "Astrika initialized: service={} port={} config={}",
        svc,
        port,
        conf_path.display()
    );
    ExitCode::SUCCESS
}

fn cmd_remove(args: &[String]) -> ExitCode {
    if !is_root() {
        eprintln!("Error: 'astrika remove' must be run as root.");
        return ExitCode::from(1);
    }

    let mut svc = DEFAULT_SVC.to_string();
    let mut purge = false;

    for a in args {
        if a == "--purge" {
            purge = true;
        } else if let Some(p) = parse_port(a) {
            svc = if p == DEFAULT_PORT {
                DEFAULT_SVC.to_string()
            } else {
                format!("{}-{}", DEFAULT_SVC, p)
            };
        } else if valid_svc_name(a) {
            svc = a.clone();
        }
    }

    let _ = run_cmd_quiet("systemctl", &["stop", &svc]);
    let _ = run_cmd_quiet("systemctl", &["disable", &svc]);
    let unit_path = Path::new(SYS_DIR).join(format!("{}.service", svc));
    let _ = fs::remove_file(&unit_path);
    let _ = run_cmd_quiet("systemctl", &["daemon-reload"]);

    if purge {
        let conf_path = Path::new(CONF_DIR).join(format!("{}.conf", svc));
        let _ = fs::remove_file(&conf_path);
    }
    println!("Removed service {}{}", svc, if purge { " (and config)" } else { "" });
    ExitCode::SUCCESS
}

fn cmd_purge() -> ExitCode {
    if !is_root() {
        eprintln!("Error: 'astrika purge' must be run as root.");
        return ExitCode::from(1);
    }
    if let Ok(entries) = fs::read_dir(SYS_DIR) {
        for e in entries.flatten() {
            let fname = e.file_name().to_string_lossy().to_string();
            if fname.starts_with(DEFAULT_SVC) && fname.ends_with(".service") {
                let svc = fname.trim_end_matches(".service");
                let _ = run_cmd_quiet("systemctl", &["stop", svc]);
                let _ = run_cmd_quiet("systemctl", &["disable", svc]);
                let _ = fs::remove_file(e.path());
            }
        }
    }
    let _ = run_cmd_quiet("systemctl", &["daemon-reload"]);
    let _ = fs::remove_dir_all(CONF_DIR);
    let _ = fs::remove_dir_all(STATE_DIR);
    let _ = fs::remove_file(BIN_PATH);
    println!("Astrika completely removed.");
    ExitCode::SUCCESS
}

fn cmd_reset_password(args: &[String]) -> ExitCode {
    let mut cfg_arg: Option<String> = None;
    let mut pos: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" if i + 1 < args.len() => {
                cfg_arg = Some(args[i + 1].clone());
                i += 2;
            }
            _ => {
                pos.push(args[i].clone());
                i += 1;
            }
        }
    }

    let user = pos.first().map(|s| s.as_str()).unwrap_or("admin");
    let pass = match pos.get(1) {
        Some(p) => p.clone(),
        None => {
            eprintln!("Usage: astrika reset-password <user> <new_password> [-c <config>]");
            return ExitCode::from(2);
        }
    };

    if !valid_login(user) {
        eprintln!("Invalid login '{}'", user);
        return ExitCode::from(2);
    }
    if !valid_password(&pass) {
        eprintln!("Password must be 12..128 chars and include letters and digits.");
        return ExitCode::from(2);
    }

    let conf_path = resolve_default_config_path(cfg_arg.as_deref());
    let mut cfg = load_json_obj_or_cfg(&conf_path).unwrap_or_else(|| default_cfg_obj(8000, "0.0.0.0"));
    let hashed = hash_password_sync(&pass);

    if cfg.get("users").and_then(|u| u.as_object()).is_none() {
        cfg["users"] = json!({});
    }
    if let Some(users) = cfg.get_mut("users").and_then(|u| u.as_object_mut()) {
        let entry = users
            .entry(user.to_string())
            .or_insert_with(|| json!({ "enable": true, "type": 1, "role": "admin" }));
        if let Some(uo) = entry.as_object_mut() {
            uo.insert("password".to_string(), json!(hashed));
            uo.insert("enable".to_string(), json!(true));
        }
    }

    let mut bytes = serde_json::to_vec_pretty(&cfg).unwrap_or_default();
    bytes.push(b'\n');
    if let Err(e) = atomic_write_file_sync(&conf_path, &bytes, 0o640) {
        eprintln!("Failed to save {}: {}", conf_path.display(), e);
        return ExitCode::from(1);
    }
    println!("Password updated for '{}' in {}", user, conf_path.display());
    ExitCode::SUCCESS
}

fn raise_nofile_limit() {
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
            let target = 65536u64.min(rl.rlim_max);
            if rl.rlim_cur < target {
                rl.rlim_cur = target;
                let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
            }
        }
    }
}

fn worker_count() -> usize {
    if let Ok(v) = std::env::var("ASTRIKA_WORKERS") {
        if let Ok(n) = v.parse::<usize>() {
            if n >= 1 && n <= 64 {
                return n;
            }
        }
    }
    // Clamp to 2..4 by default to keep RSS tiny even on 32/64-core servers while
    // fully utilizing multi-core async I/O.
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(2, 4))
        .unwrap_or(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if let Some(first) = args.first().map(|s| s.as_str()) {
        match first {
            "-v" | "--version" | "version" => {
                println!("{} ({})", ASTRIKA_VERSION, ASTRIKA_CLI_VERSION);
                return ExitCode::SUCCESS;
            }
            "-h" | "--help" | "help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            "init" => return cmd_init(&args[1..]),
            "remove" => return cmd_remove(&args[1..]),
            "purge" => return cmd_purge(),
            "reset-password" => return cmd_reset_password(&args[1..]),
            _ => {}
        }
    }

    let mut cfg_arg: Option<String> = None;
    let mut cli_host: Option<String> = None;
    let mut cli_port: u16 = 0;
    let mut pid_file: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" if i + 1 < args.len() => {
                cfg_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "-p" | "--port" if i + 1 < args.len() => {
                cli_port = parse_port(&args[i + 1]).unwrap_or(0);
                i += 2;
            }
            "--host" if i + 1 < args.len() => {
                cli_host = Some(args[i + 1].clone());
                i += 2;
            }
            "--pid" if i + 1 < args.len() => {
                pid_file = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            other => {
                if !other.starts_with('-') && cfg_arg.is_none() {
                    cfg_arg = Some(other.to_string());
                    i += 1;
                } else {
                    eprintln!("Unknown option: {}", other);
                    return ExitCode::from(2);
                }
            }
        }
    }

    raise_nofile_limit();

    let conf_path = resolve_default_config_path(cfg_arg.as_deref());
    let initial_cfg = match load_disk_config(&conf_path, cli_host.as_deref(), cli_port) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error ({}): {}", conf_path.display(), e);
            return ExitCode::from(1);
        }
    };

    if let Some(ref pf) = pid_file {
        let _ = fs::write(pf, format!("{}\n", std::process::id()));
    }

    let workers = worker_count();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(workers)
        .max_blocking_threads(4)
        .thread_stack_size(1024 * 1024)
        .thread_name("astrika")
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to initialize async runtime: {}", e);
            return ExitCode::from(1);
        }
    };

    let exit_code = rt.block_on(async move {
        let state = AppState::new(conf_path.clone(), initial_cfg);
        state.sync_local_engines(true);
        state.sync_extra_ports();
        spawn_background_tasks(Arc::clone(&state));

        let snap = state.config();
        let bind_host = snap.host.clone();
        let bind_port = snap.port;

        // SIGHUP live reload handler
        let st_hup = Arc::clone(&state);
        let hup_host = cli_host.clone();
        tokio::spawn(async move {
            let Ok(mut sig) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            else {
                return;
            };
            while sig.recv().await.is_some() {
                if let Ok(reloaded) = load_disk_config(&st_hup.config_path, hup_host.as_deref(), cli_port) {
                    if let Err(e) = st_hup.apply_config(reloaded, false, false).await {
                        eprintln!("SIGHUP reload rejected: {}", e);
                    }
                }
            }
        });

        // Graceful shutdown on SIGTERM / SIGINT
        let st_sig = Arc::clone(&state);
        tokio::spawn(async move {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
            let ctrl_c = tokio::signal::ctrl_c();
            tokio::select! {
                _ = ctrl_c => {}
                _ = async {
                    if let Some(ref mut t) = term {
                        t.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {}
            }
            st_sig.shutdown_all();
        });

        eprintln!(
            "{} listening on {}:{} (workers={}, config={})",
            ASTRIKA_VERSION,
            bind_host,
            bind_port,
            workers,
            conf_path.display()
        );

        match serve_http_port(Arc::clone(&state), &bind_host, bind_port).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Server error: {}", e);
                ExitCode::from(1)
            }
        }
    });

    if let Some(ref pf) = pid_file {
        let _ = fs::remove_file(pf);
    }
    exit_code
}
