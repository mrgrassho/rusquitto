use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, ErrorKind, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rusquitto_core::{
    BrokerState, PersistedSession, Qos2Outbound, Qos2OutboundState, Subscription,
};
use rusquitto_protocol::{
    decode_frame, encode_connack, encode_connack_with_retain_available, encode_disconnect,
    encode_pingresp, encode_puback, encode_pubcomp, encode_publish, encode_pubrec, encode_pubrel,
    encode_suback, encode_unsuback, read_frame, topic, MqttPacket, ProtocolVersion, Publication,
};

const MQTT_RC_MALFORMED_PACKET: u8 = 0x81;
const MQTT_RC_PROTOCOL_ERROR: u8 = 0x82;
const MQTT_RC_NOT_AUTHORIZED: u8 = 0x87;
const MQTT_RC_RETAIN_NOT_SUPPORTED: u8 = 0x9A;
const UNKNOWN_SCHEMA_VERSION_PREFIX: &str = "Unknown database_schema version ";

type OutboundMap = Arc<Mutex<HashMap<String, ClientOutbound>>>;
type ClientUsers = Arc<Mutex<HashMap<String, Option<String>>>>;
type SharedBroker = Arc<Mutex<BrokerState>>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ListenerSettings {
    port: u16,
    allow_anonymous: bool,
}

#[derive(Debug, Clone)]
struct ListenerDraft {
    port: u16,
    allow_anonymous: Option<bool>,
}

struct BoundListener {
    settings: ListenerSettings,
    listener: TcpListener,
}

#[derive(Debug, Clone)]
struct ClientOutbound {
    protocol: ProtocolVersion,
    sender: Sender<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct Settings {
    listeners: Vec<ListenerSettings>,
    verbose: bool,
    retain_available: bool,
    upgrade_outgoing_qos: bool,
    persistence_db_file: Option<String>,
    password_file: Option<HashMap<String, PasswordEntry>>,
    acl_file: Option<AclFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PasswordEntry {
    Plain(String),
    Sha512 { salt: Vec<u8>, hash: Vec<u8> },
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AclFile {
    rules: Vec<AclRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AclRule {
    scope: AclScope,
    access: AclAccess,
    filter: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AclScope {
    Anonymous,
    User(String),
    Pattern,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclAccess {
    Read,
    Write,
    ReadWrite,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclOperation {
    Read,
    Write,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            listeners: vec![ListenerSettings {
                port: 1883,
                allow_anonymous: true,
            }],
            verbose: false,
            retain_available: true,
            upgrade_outgoing_qos: false,
            persistence_db_file: None,
            password_file: None,
            acl_file: None,
        }
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        std::process::exit(exit_code_for_error(&err));
    }
}

fn exit_code_for_error(err: &str) -> i32 {
    if err.starts_with(UNKNOWN_SCHEMA_VERSION_PREFIX) {
        3
    } else {
        1
    }
}

fn run() -> Result<(), String> {
    let settings = parse_settings(env::args().skip(1).collect())?;
    let listeners = bind_listeners(&settings.listeners)?;
    if settings.verbose {
        eprintln!("rusquitto version 2.1.2 starting");
        for listener in &listeners {
            eprintln!(
                "Opening ipv4 listen socket on port {}.",
                listener.settings.port
            );
        }
    }

    shutdown::install();
    for listener in &listeners {
        listener
            .listener
            .set_nonblocking(true)
            .map_err(|e| e.to_string())?;
    }

    let mut broker_state = BrokerState::new();
    broker_state.set_upgrade_outgoing_qos(settings.upgrade_outgoing_qos);
    if let Some(path) = settings.persistence_db_file.as_deref() {
        sqlite_persistence::validate_schema_version(path)?;
        let retained = sqlite_persistence::load_retained(path)?;
        broker_state.restore_retained(retained);
        let sessions = sqlite_persistence::load_sessions(path)?;
        broker_state.restore_sessions(sessions);
    }
    let broker = Arc::new(Mutex::new(broker_state));
    let outbound = Arc::new(Mutex::new(HashMap::new()));
    let client_users = Arc::new(Mutex::new(HashMap::new()));
    while !shutdown::requested() {
        let mut accepted = false;
        for listener in &listeners {
            match listener.listener.accept() {
                Ok((stream, _)) => {
                    accepted = true;
                    if let Err(err) = stream.set_nonblocking(false) {
                        eprintln!("Client setup error: {err}");
                        continue;
                    }
                    let broker = Arc::clone(&broker);
                    let outbound = Arc::clone(&outbound);
                    let client_users = Arc::clone(&client_users);
                    let settings = settings.clone();
                    let allow_anonymous = listener.settings.allow_anonymous;
                    thread::spawn(move || {
                        if let Err(err) = handle_client(
                            stream,
                            broker,
                            outbound,
                            client_users,
                            settings,
                            allow_anonymous,
                        ) {
                            eprintln!("Client error: {err}");
                        }
                    });
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Err(err) => {
                    eprintln!("Accept error: {err}");
                }
            }
        }
        if !accepted {
            thread::sleep(Duration::from_millis(25));
        }
    }
    if let Some(path) = settings.persistence_db_file.as_deref() {
        let (retained, sessions) = {
            let broker = broker.lock().expect("broker lock poisoned");
            (broker.retained_snapshot(), broker.session_snapshot())
        };
        sqlite_persistence::save(path, &retained, &sessions)?;
    }
    Ok(())
}

#[cfg(unix)]
mod shutdown {
    use std::sync::atomic::{AtomicBool, Ordering};

    static REQUESTED: AtomicBool = AtomicBool::new(false);

    type SignalHandler = extern "C" fn(i32);

    extern "C" {
        fn signal(signum: i32, handler: SignalHandler) -> SignalHandler;
    }

    extern "C" fn handle_signal(_signum: i32) {
        REQUESTED.store(true, Ordering::SeqCst);
    }

    pub fn install() {
        unsafe {
            let _ = signal(2, handle_signal);
            let _ = signal(15, handle_signal);
        }
    }

    pub fn requested() -> bool {
        REQUESTED.load(Ordering::SeqCst)
    }
}

#[cfg(not(unix))]
mod shutdown {
    pub fn install() {}

    pub fn requested() -> bool {
        false
    }
}

fn bind_listeners(settings: &[ListenerSettings]) -> Result<Vec<BoundListener>, String> {
    settings
        .iter()
        .cloned()
        .map(|settings| {
            TcpListener::bind(("::", settings.port))
                .or_else(|_| TcpListener::bind(("0.0.0.0", settings.port)))
                .map(|listener| BoundListener { settings, listener })
                .map_err(|e| e.to_string())
        })
        .collect()
}

fn parse_settings(args: Vec<String>) -> Result<Settings, String> {
    let mut settings = Settings::default();
    let mut config_path = None;
    let mut cli_port = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!("mosquitto [-c config file] [-p port] [-v]");
                std::process::exit(0);
            }
            "-c" => {
                i += 1;
                config_path = args.get(i).cloned();
            }
            "-p" => {
                i += 1;
                let port = args
                    .get(i)
                    .ok_or_else(|| "-p requires a port".to_owned())?
                    .parse::<u16>()
                    .map_err(|_| "-p requires a numeric port".to_owned())?;
                cli_port = Some(port);
            }
            "-v" => settings.verbose = true,
            other => return Err(format!("unsupported option {other}")),
        }
        i += 1;
    }

    let mut config_declared_listener = false;
    let mut explicit_allow = None;
    let mut listener_drafts = Vec::new();
    let mut default_listener_allow = None;
    let mut password_file_path = None;
    let mut acl_file_path = None;
    if let Some(path) = config_path {
        let contents =
            fs::read_to_string(&path).map_err(|e| format!("unable to read config {path}: {e}"))?;
        for raw_line in contents.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let key = parts.next().unwrap_or("");
            let value = parts.next();
            match key {
                "port" => {
                    config_declared_listener = true;
                    if let Some(value) = value {
                        if let Ok(port) = value.parse::<u16>() {
                            listener_drafts.clear();
                            listener_drafts.push(ListenerDraft {
                                port,
                                allow_anonymous: None,
                            });
                        }
                    }
                }
                "listener" => {
                    config_declared_listener = true;
                    if let Some(value) = value {
                        if let Ok(port) = value.parse::<u16>() {
                            listener_drafts.push(ListenerDraft {
                                port,
                                allow_anonymous: None,
                            });
                        }
                    }
                }
                "allow_anonymous" => {
                    explicit_allow = parse_bool(value);
                }
                "listener_allow_anonymous" => {
                    if let Some(value) = parse_bool(value) {
                        if let Some(listener) = listener_drafts.last_mut() {
                            listener.allow_anonymous = Some(value);
                        } else {
                            default_listener_allow = Some(value);
                        }
                    }
                }
                "retain_available" => {
                    if let Some(value) = parse_bool(value) {
                        settings.retain_available = value;
                    }
                }
                "upgrade_outgoing_qos" => {
                    if let Some(value) = parse_bool(value) {
                        settings.upgrade_outgoing_qos = value;
                    }
                }
                "plugin_opt_db_file" => {
                    if let Some(value) = value {
                        settings.persistence_db_file = Some(value.to_owned());
                    }
                }
                "password_file" => {
                    if let Some(value) = value {
                        password_file_path = Some(resolve_config_path(&path, value));
                    }
                }
                "acl_file" => {
                    if let Some(value) = value {
                        acl_file_path = Some(resolve_config_path(&path, value));
                    }
                }
                _ => {}
            }
        }
    }

    if listener_drafts.is_empty() {
        listener_drafts.push(ListenerDraft {
            port: cli_port.unwrap_or(1883),
            allow_anonymous: default_listener_allow,
        });
    }
    let default_allow_anonymous = explicit_allow.unwrap_or(!config_declared_listener);
    settings.listeners = listener_drafts
        .into_iter()
        .map(|listener| ListenerSettings {
            port: listener.port,
            allow_anonymous: listener.allow_anonymous.unwrap_or(default_allow_anonymous),
        })
        .collect();
    if let Some(path) = password_file_path {
        settings.password_file = Some(load_password_file(&path)?);
    }
    if let Some(path) = acl_file_path {
        settings.acl_file = Some(load_acl_file(&path)?);
    }

    Ok(settings)
}

fn parse_bool(value: Option<&str>) -> Option<bool> {
    match value {
        Some("true") | Some("1") => Some(true),
        Some("false") | Some("0") => Some(false),
        _ => None,
    }
}

fn resolve_config_path(config_path: &str, value: &str) -> String {
    let value_path = Path::new(value);
    if value_path.is_absolute() {
        return value.to_owned();
    }
    Path::new(config_path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| parent.join(value).to_string_lossy().to_string())
        .unwrap_or_else(|| value.to_owned())
}

fn load_password_file(path: &str) -> Result<HashMap<String, PasswordEntry>, String> {
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("unable to read password_file {path}: {e}"))?;
    let mut entries = HashMap::new();
    for raw_line in contents.lines() {
        let line = raw_line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((username, password)) = line.split_once(':') else {
            return Err(format!("invalid password_file line for {path}"));
        };
        entries.insert(
            username.to_owned(),
            parse_password_entry(password)
                .map_err(|e| format!("invalid password_file line for {path}: {e}"))?,
        );
    }
    Ok(entries)
}

fn parse_password_entry(value: &str) -> Result<PasswordEntry, String> {
    if let Some(rest) = value.strip_prefix("$6$") {
        let mut parts = rest.split('$');
        let salt_b64 = parts
            .next()
            .ok_or_else(|| "missing sha512 salt".to_owned())?;
        let hash_b64 = parts
            .next()
            .ok_or_else(|| "missing sha512 password hash".to_owned())?;
        if parts.next().is_some() {
            return Err("invalid sha512 password hash".to_owned());
        }
        let salt = decode_base64(salt_b64)?;
        let hash = decode_base64(hash_b64)?;
        if !(salt.len() == 12 || salt.len() == 64) {
            return Err("invalid sha512 salt length".to_owned());
        }
        if hash.len() != 64 {
            return Err("invalid sha512 hash length".to_owned());
        }
        Ok(PasswordEntry::Sha512 { salt, hash })
    } else if value.starts_with('$') {
        Ok(PasswordEntry::Unsupported)
    } else {
        Ok(PasswordEntry::Plain(value.to_owned()))
    }
}

fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    let mut padding = false;
    for byte in value.bytes() {
        let sextet = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding = true;
                continue;
            }
            b'\r' | b'\n' => continue,
            _ => return Err("invalid base64 character".to_owned()),
        };
        if padding {
            return Err("invalid base64 padding".to_owned());
        }
        buffer = (buffer << 6) | u32::from(sextet);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1_u32 << bits) - 1;
        }
    }
    Ok(output)
}

fn connection_authorized(
    allow_anonymous: bool,
    password_file: Option<&HashMap<String, PasswordEntry>>,
    username: Option<&str>,
    password: Option<&[u8]>,
) -> bool {
    let Some(username) = username else {
        return allow_anonymous;
    };
    let Some(password_file) = password_file else {
        return allow_anonymous;
    };
    let Some(stored_password) = password_file.get(username) else {
        return false;
    };
    let Some(password) = password else {
        return false;
    };
    password_entry_matches(stored_password, password)
}

fn password_entry_matches(entry: &PasswordEntry, password: &[u8]) -> bool {
    match entry {
        PasswordEntry::Plain(stored_password) => stored_password.as_bytes() == password,
        PasswordEntry::Sha512 { salt, hash } => sha512_password_matches(salt, hash, password),
        PasswordEntry::Unsupported => false,
    }
}

fn sha512_password_matches(salt: &[u8], expected_hash: &[u8], password: &[u8]) -> bool {
    let mut child = match Command::new("openssl")
        .arg("dgst")
        .arg("-sha512")
        .arg("-binary")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return false,
    };
    let Some(mut stdin) = child.stdin.take() else {
        return false;
    };
    if stdin.write_all(password).is_err() || stdin.write_all(salt).is_err() {
        return false;
    }
    drop(stdin);
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(_) => return false,
    };
    output.status.success() && constant_time_eq(&output.stdout, expected_hash)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

fn load_acl_file(path: &str) -> Result<AclFile, String> {
    let contents =
        fs::read_to_string(path).map_err(|e| format!("unable to read acl_file {path}: {e}"))?;
    let mut rules = Vec::new();
    let mut current_user = None;
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("user") => {
                current_user = parts.next().map(str::to_owned);
            }
            Some("topic") => {
                let Some((access, filter)) = parse_acl_access_and_filter(parts.collect()) else {
                    return Err(format!("invalid acl_file line for {path}: {line}"));
                };
                rules.push(AclRule {
                    scope: current_user
                        .as_ref()
                        .map_or(AclScope::Anonymous, |user| AclScope::User(user.clone())),
                    access,
                    filter,
                });
            }
            Some("pattern") => {
                let Some((access, filter)) = parse_acl_access_and_filter(parts.collect()) else {
                    return Err(format!("invalid acl_file line for {path}: {line}"));
                };
                rules.push(AclRule {
                    scope: AclScope::Pattern,
                    access,
                    filter,
                });
            }
            _ => {}
        }
    }
    Ok(AclFile { rules })
}

fn parse_acl_access_and_filter(parts: Vec<&str>) -> Option<(AclAccess, String)> {
    match parts.as_slice() {
        [filter] => Some((AclAccess::ReadWrite, (*filter).to_owned())),
        [access, filter] => parse_acl_access(access).map(|access| (access, (*filter).to_owned())),
        _ => None,
    }
}

fn parse_acl_access(value: &str) -> Option<AclAccess> {
    match value {
        "read" => Some(AclAccess::Read),
        "write" => Some(AclAccess::Write),
        "readwrite" => Some(AclAccess::ReadWrite),
        "deny" => Some(AclAccess::Deny),
        _ => None,
    }
}

fn acl_allows(
    settings: &Settings,
    username: Option<&str>,
    client_id: &str,
    operation: AclOperation,
    topic_name: &str,
) -> bool {
    let Some(acl_file) = settings.acl_file.as_ref() else {
        return true;
    };
    let mut allowed = false;
    for rule in &acl_file.rules {
        if !acl_rule_applies(rule, username, client_id, topic_name) {
            continue;
        }
        if rule.access == AclAccess::Deny {
            return false;
        }
        if acl_access_allows(rule.access, operation) {
            allowed = true;
        }
    }
    allowed
}

fn acl_rule_applies(
    rule: &AclRule,
    username: Option<&str>,
    client_id: &str,
    topic_name: &str,
) -> bool {
    match &rule.scope {
        AclScope::Anonymous => username.is_none() && topic::matches(&rule.filter, topic_name),
        AclScope::User(rule_user) => {
            username == Some(rule_user.as_str()) && topic::matches(&rule.filter, topic_name)
        }
        AclScope::Pattern => {
            let Some(username) = username else {
                return false;
            };
            let filter = rule.filter.replace("%u", username).replace("%c", client_id);
            topic::matches(&filter, topic_name)
        }
    }
}

fn acl_access_allows(access: AclAccess, operation: AclOperation) -> bool {
    matches!(
        (access, operation),
        (AclAccess::ReadWrite, _)
            | (AclAccess::Read, AclOperation::Read)
            | (AclAccess::Write, AclOperation::Write)
    )
}

mod sqlite_persistence {
    use super::*;

    pub fn validate_schema_version(path: &str) -> Result<(), String> {
        if !Path::new(path).exists() {
            return Ok(());
        }

        let has_version_info = sqlite_scalar(
            path,
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='version_info';",
            "inspect persistence schema",
        )?;
        if has_version_info.trim() == "0" {
            return Ok(());
        }

        let version = sqlite_scalar(
            path,
            "SELECT major || '.' || minor || '.' || patch FROM version_info WHERE component='database_schema' LIMIT 1;",
            "inspect persistence schema",
        )?;
        let version = version.trim();
        if version.is_empty() || version.starts_with("1.0.") || version.starts_with("1.1.") {
            Ok(())
        } else {
            Err(format!("{UNKNOWN_SCHEMA_VERSION_PREFIX}{version}"))
        }
    }

    fn sqlite_scalar(path: &str, sql: &str, context: &str) -> Result<String, String> {
        let output = Command::new("sqlite3")
            .arg("-batch")
            .arg(path)
            .arg(sql)
            .output()
            .map_err(|e| format!("unable to run sqlite3: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "unable to {context}: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    pub fn load_retained(path: &str) -> Result<Vec<Publication>, String> {
        if !Path::new(path).exists() {
            return Ok(Vec::new());
        }
        let output = Command::new("sqlite3")
            .arg("-batch")
            .arg("-separator")
            .arg("\t")
            .arg(path)
            .arg(
                "SELECT b.topic, hex(COALESCE(b.payload, X'')), b.qos \
                 FROM base_msgs b JOIN retains r ON b.store_id = r.store_id \
                 ORDER BY r.topic;",
            )
            .output()
            .map_err(|e| format!("unable to run sqlite3: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "unable to load retained persistence: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let mut retained = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let mut parts = line.split('\t');
            let Some(topic) = parts.next() else { continue };
            let payload_hex = parts.next().unwrap_or_default();
            let qos = parts
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            retained.push(Publication {
                topic: topic.to_owned(),
                payload: decode_hex(payload_hex)?,
                qos,
                retain: true,
                packet_id: None,
                dup: false,
                topic_alias: None,
                subscription_identifiers: Vec::new(),
            });
        }
        Ok(retained)
    }

    pub fn load_sessions(path: &str) -> Result<Vec<PersistedSession>, String> {
        if !Path::new(path).exists() {
            return Ok(Vec::new());
        }
        let output = Command::new("sqlite3")
            .arg("-batch")
            .arg("-separator")
            .arg("\t")
            .arg(path)
            .arg(
                "SELECT c.client_id, COALESCE(c.session_expiry_interval, 0), \
                        COALESCE(s.topic, ''), COALESCE(s.subscription_options, 0), \
                        COALESCE(s.subscription_identifier, 0) \
                 FROM clients c LEFT JOIN subscriptions s ON c.client_id = s.client_id \
                 ORDER BY c.client_id, s.topic;",
            )
            .output()
            .map_err(|e| format!("unable to run sqlite3: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "unable to load session persistence: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let mut sessions = Vec::new();
        let mut current: Option<PersistedSession> = None;
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let mut parts = line.split('\t');
            let Some(client_id) = parts.next() else {
                continue;
            };
            if client_id.is_empty() {
                continue;
            }
            let session_expiry_interval =
                session_expiry_interval_from_db(parts.next().unwrap_or_default());
            if session_expiry_interval == 0 {
                continue;
            }

            let new_client = current
                .as_ref()
                .map_or(true, |session| session.client_id != client_id);
            if new_client {
                if let Some(session) = current.take() {
                    sessions.push(session);
                }
                current = Some(PersistedSession {
                    client_id: client_id.to_owned(),
                    session_expiry_interval,
                    subscriptions: Vec::new(),
                    queued: Vec::new(),
                    inflight_qos1: Vec::new(),
                    inflight_qos2: Vec::new(),
                    inbound_qos2: Vec::new(),
                });
            }

            let topic = parts.next().unwrap_or_default();
            if topic.is_empty() {
                continue;
            }
            let options = parts
                .next()
                .and_then(|value| value.parse::<u8>().ok())
                .unwrap_or(0);
            let identifier = parts
                .next()
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|identifier| *identifier > 0);
            if let Some(session) = current.as_mut() {
                session.subscriptions.push(subscription_from_options(
                    topic.to_owned(),
                    options,
                    identifier,
                ));
            }
        }
        if let Some(session) = current {
            sessions.push(session);
        }
        load_client_messages(path, &mut sessions)?;
        Ok(sessions)
    }

    fn load_client_messages(path: &str, sessions: &mut [PersistedSession]) -> Result<(), String> {
        let output = Command::new("sqlite3")
            .arg("-batch")
            .arg("-separator")
            .arg("\t")
            .arg(path)
            .arg(
                "SELECT cm.client_id, cm.mid, cm.qos, cm.retain, cm.dup, cm.direction, \
                        cm.state, COALESCE(cm.subscription_identifier, 0), b.topic, \
                        hex(COALESCE(b.payload, X'')) \
                 FROM client_msgs cm JOIN base_msgs b ON cm.store_id = b.store_id \
                 WHERE (cm.direction = 1 AND cm.state IN (3, 5, 9, 11)) \
                    OR (cm.direction = 0 AND cm.state = 7) \
                 ORDER BY cm.client_id, cm.cmsg_id;",
            )
            .output()
            .map_err(|e| format!("unable to run sqlite3: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "unable to load client message persistence: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let indexes: HashMap<_, _> = sessions
            .iter()
            .enumerate()
            .map(|(idx, session)| (session.client_id.clone(), idx))
            .collect();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let mut parts = line.split('\t');
            let Some(client_id) = parts.next() else {
                continue;
            };
            let Some(session_idx) = indexes.get(client_id).copied() else {
                continue;
            };
            let packet_id = parts
                .next()
                .and_then(|value| value.parse::<u16>().ok())
                .filter(|packet_id| *packet_id > 0);
            let qos = parts
                .next()
                .and_then(|value| value.parse::<u8>().ok())
                .unwrap_or(0);
            let retain = parts.next().is_some_and(|value| value == "1");
            let dup = parts.next().is_some_and(|value| value == "1");
            let direction = parts
                .next()
                .and_then(|value| value.parse::<u8>().ok())
                .unwrap_or(0);
            let state = parts
                .next()
                .and_then(|value| value.parse::<u8>().ok())
                .unwrap_or(0);
            let subscription_identifier = parts
                .next()
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|identifier| *identifier > 0);
            let topic = parts.next().unwrap_or_default();
            let payload_hex = parts.next().unwrap_or_default();
            let publication = Publication {
                topic: topic.to_owned(),
                payload: decode_hex(payload_hex)?,
                qos,
                retain,
                packet_id,
                dup,
                topic_alias: None,
                subscription_identifiers: subscription_identifier.into_iter().collect(),
            };
            match (direction, state) {
                (1, 11) => sessions[session_idx].queued.push(publication),
                (1, 3) => sessions[session_idx].inflight_qos1.push(publication),
                (1, 5) => sessions[session_idx].inflight_qos2.push(Qos2Outbound {
                    publication,
                    state: Qos2OutboundState::WaitingPubRec,
                }),
                (1, 9) => sessions[session_idx].inflight_qos2.push(Qos2Outbound {
                    publication,
                    state: Qos2OutboundState::WaitingPubComp,
                }),
                (0, 7) => sessions[session_idx].inbound_qos2.push(publication),
                _ => {}
            }
        }
        Ok(())
    }

    pub fn save(
        path: &str,
        retained: &[Publication],
        sessions: &[PersistedSession],
    ) -> Result<(), String> {
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("unable to create persistence directory: {e}"))?;
            }
        }
        validate_schema_version(path)?;

        let mut sql = String::new();
        sql.push_str("PRAGMA page_size=4096;\n");
        sql.push_str("PRAGMA journal_mode=WAL;\n");
        sql.push_str("PRAGMA foreign_keys = ON;\n");
        sql.push_str("PRAGMA synchronous=1;\n");
        append_schema(&mut sql);
        sql.push_str("CREATE TEMP TABLE IF NOT EXISTS rusquitto_schema_patch(patch INTEGER);\n");
        sql.push_str("DELETE FROM rusquitto_schema_patch;\n");
        sql.push_str("INSERT INTO rusquitto_schema_patch(patch) SELECT COALESCE((SELECT patch FROM version_info WHERE component='database_schema' AND major=1 AND minor=1 LIMIT 1), 0);\n");
        sql.push_str("BEGIN IMMEDIATE;\n");
        sql.push_str("DELETE FROM client_msgs;\n");
        sql.push_str("DELETE FROM subscriptions;\n");
        sql.push_str("DELETE FROM clients;\n");
        sql.push_str("DELETE FROM wills;\n");
        sql.push_str("DELETE FROM retains;\n");
        sql.push_str("DELETE FROM base_msgs;\n");
        let mut store_id = 1_i64;
        for session in sessions {
            if session.client_id.is_empty() || session.session_expiry_interval == 0 {
                continue;
            }
            sql.push_str(&format!(
                "INSERT INTO clients(client_id,username,connection_time,will_delay_time,session_expiry_time,listener_port,max_packet_size,max_qos,retain_available,session_expiry_interval,will_delay_interval) VALUES ('{}',NULL,0,0,{},NULL,0,2,1,{},0);\n",
                escape_sql(&session.client_id),
                session_expiry_time(session.session_expiry_interval),
                db_session_expiry_interval(session.session_expiry_interval),
            ));
            for subscription in &session.subscriptions {
                sql.push_str(&format!(
                    "INSERT INTO subscriptions(client_id,topic,subscription_options,subscription_identifier) VALUES ('{}','{}',{},{});\n",
                    escape_sql(&session.client_id),
                    escape_sql(&subscription.filter),
                    subscription_options(subscription),
                    subscription.identifier.unwrap_or(0),
                ));
            }
            let mut client_msg_id = 1_i64;
            for publication in &session.queued {
                append_persisted_client_msg(
                    &mut sql,
                    &session.client_id,
                    &mut store_id,
                    &mut client_msg_id,
                    publication,
                    1,
                    11,
                );
            }
            for publication in &session.inflight_qos1 {
                append_persisted_client_msg(
                    &mut sql,
                    &session.client_id,
                    &mut store_id,
                    &mut client_msg_id,
                    publication,
                    1,
                    3,
                );
            }
            for outbound in &session.inflight_qos2 {
                let state = match outbound.state {
                    Qos2OutboundState::WaitingPubRec => 5,
                    Qos2OutboundState::WaitingPubComp => 9,
                };
                append_persisted_client_msg(
                    &mut sql,
                    &session.client_id,
                    &mut store_id,
                    &mut client_msg_id,
                    &outbound.publication,
                    1,
                    state,
                );
            }
            for publication in &session.inbound_qos2 {
                append_persisted_client_msg(
                    &mut sql,
                    &session.client_id,
                    &mut store_id,
                    &mut client_msg_id,
                    publication,
                    0,
                    7,
                );
            }
        }
        for publication in retained {
            append_base_msg(&mut sql, store_id, publication, true);
            sql.push_str(&format!(
                "INSERT INTO retains(topic,store_id) VALUES ('{}',{store_id});\n",
                escape_sql(&publication.topic)
            ));
            store_id += 1;
        }
        sql.push_str("DELETE FROM version_info WHERE component='database_schema';\n");
        sql.push_str("INSERT INTO version_info(component,major,minor,patch) SELECT 'database_schema',1,1,patch FROM rusquitto_schema_patch LIMIT 1;\n");
        sql.push_str("COMMIT;\n");
        sql.push_str("PRAGMA wal_checkpoint(TRUNCATE);\n");

        let mut child = Command::new("sqlite3")
            .arg("-batch")
            .arg(path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("unable to run sqlite3: {e}"))?;
        child
            .stdin
            .as_mut()
            .ok_or_else(|| "unable to open sqlite3 stdin".to_owned())?
            .write_all(sql.as_bytes())
            .map_err(|e| format!("unable to write persistence SQL: {e}"))?;
        let output = child
            .wait_with_output()
            .map_err(|e| format!("unable to wait for sqlite3: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "unable to save persistence: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }

    fn append_base_msg(sql: &mut String, store_id: i64, publication: &Publication, retain: bool) {
        sql.push_str(&format!(
            "INSERT INTO base_msgs(store_id,expiry_time,topic,payload,source_id,source_username,payloadlen,source_mid,source_port,qos,retain,properties) VALUES ({store_id},0,'{}',X'{}','',NULL,{},0,0,{},{},NULL);\n",
            escape_sql(&publication.topic),
            encode_hex(&publication.payload),
            publication.payload.len(),
            publication.qos,
            u8::from(retain),
        ));
    }

    fn append_persisted_client_msg(
        sql: &mut String,
        client_id: &str,
        store_id: &mut i64,
        client_msg_id: &mut i64,
        publication: &Publication,
        direction: u8,
        state: u8,
    ) {
        let Some(packet_id) = publication.packet_id else {
            return;
        };
        if publication.qos == 0 {
            return;
        }
        append_base_msg(sql, *store_id, publication, publication.retain);
        sql.push_str(&format!(
            "INSERT INTO client_msgs(client_id,cmsg_id,store_id,dup,direction,mid,qos,retain,state,subscription_identifier) VALUES ('{}',{},{},{},{},{},{},{},{},{});\n",
            escape_sql(client_id),
            *client_msg_id,
            *store_id,
            u8::from(publication.dup),
            direction,
            packet_id,
            publication.qos,
            u8::from(publication.retain),
            state,
            publication.subscription_identifiers.first().copied().unwrap_or(0),
        ));
        *store_id += 1;
        *client_msg_id += 1;
    }

    fn append_schema(sql: &mut String) {
        sql.push_str("CREATE TABLE IF NOT EXISTS base_msgs (store_id INT64 PRIMARY KEY,expiry_time INT64,topic STRING NOT NULL,payload BLOB,source_id STRING,source_username STRING,payloadlen INTEGER,source_mid INTEGER,source_port INTEGER,qos INTEGER,retain INTEGER,properties STRING);\n");
        sql.push_str(
            "CREATE TABLE IF NOT EXISTS retains (topic STRING PRIMARY KEY,store_id INT64);\n",
        );
        sql.push_str("CREATE TABLE IF NOT EXISTS clients (client_id TEXT PRIMARY KEY,username TEXT,connection_time INT64,will_delay_time INT64,session_expiry_time INT64,listener_port INT,max_packet_size INT,max_qos INT,retain_available INT,session_expiry_interval INT,will_delay_interval INT);\n");
        sql.push_str("CREATE TABLE IF NOT EXISTS subscriptions (client_id TEXT NOT NULL,topic TEXT NOT NULL,subscription_options INTEGER,subscription_identifier INTEGER,PRIMARY KEY (client_id, topic) );\n");
        sql.push_str("CREATE TABLE IF NOT EXISTS client_msgs (client_id TEXT NOT NULL,cmsg_id INT64,store_id INT64,dup INTEGER,direction INTEGER,mid INTEGER,qos INTEGER,retain INTEGER,state INTEGER,subscription_identifier INTEGER);\n");
        sql.push_str("CREATE TABLE IF NOT EXISTS wills(client_id TEXT PRIMARY KEY,payload BLOB,topic STRING NOT NULL,payloadlen INTEGER,qos INTEGER,retain INTEGER,properties STRING);\n");
        sql.push_str("CREATE TABLE IF NOT EXISTS version_info (component TEXT NOT NULL,major INTEGER NOT NULL,minor INTEGER NOT NULL,patch INTEGER NOT NULL);\n");
    }

    fn subscription_from_options(
        filter: String,
        options: u8,
        identifier: Option<u32>,
    ) -> Subscription {
        Subscription {
            filter,
            qos: options & 0x03,
            no_local: (options & 0x04) != 0,
            retain_as_published: (options & 0x08) != 0,
            retain_handling: (options & 0x30) >> 4,
            identifier,
            order: 0,
        }
    }

    fn subscription_options(subscription: &Subscription) -> u8 {
        let mut options = subscription.qos & 0x03;
        if subscription.no_local {
            options |= 0x04;
        }
        if subscription.retain_as_published {
            options |= 0x08;
        }
        options | ((subscription.retain_handling & 0x03) << 4)
    }

    fn session_expiry_interval_from_db(value: &str) -> u32 {
        match value.parse::<i64>() {
            Ok(-1) => u32::MAX,
            Ok(value) if value > 0 => u32::try_from(value).unwrap_or(u32::MAX),
            _ => 0,
        }
    }

    fn db_session_expiry_interval(value: u32) -> i64 {
        if value == u32::MAX {
            -1
        } else {
            i64::from(value)
        }
    }

    fn session_expiry_time(value: u32) -> i64 {
        if value == 0 || value == u32::MAX {
            0
        } else {
            1
        }
    }

    fn escape_sql(value: &str) -> String {
        value.replace('\'', "''")
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0F) as usize] as char);
        }
        out
    }

    fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
        if value.len() % 2 != 0 {
            return Err("invalid hex payload length".to_owned());
        }
        let mut bytes = Vec::with_capacity(value.len() / 2);
        for chunk in value.as_bytes().chunks(2) {
            let hex = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
            bytes.push(u8::from_str_radix(hex, 16).map_err(|e| e.to_string())?);
        }
        Ok(bytes)
    }
}

fn broker_session_expiry_interval(
    protocol: ProtocolVersion,
    clean_start: bool,
    session_expiry_interval: Option<u32>,
) -> u32 {
    if protocol == ProtocolVersion::V5 {
        session_expiry_interval.unwrap_or(0)
    } else if clean_start {
        0
    } else {
        u32::MAX
    }
}

fn handle_client(
    mut stream: TcpStream,
    broker: SharedBroker,
    outbound: OutboundMap,
    client_users: ClientUsers,
    settings: Settings,
    allow_anonymous: bool,
) -> io::Result<()> {
    let first = match read_frame(&mut stream) {
        Ok(frame) => frame,
        Err(_) => return Ok(()),
    };
    let connect = match decode_frame(&first, None) {
        Ok(MqttPacket::Connect {
            protocol,
            clean_start,
            client_id,
            username,
            password,
            will,
            session_expiry_interval,
            ..
        }) => (
            protocol,
            clean_start,
            client_id,
            username,
            password,
            will,
            session_expiry_interval,
        ),
        _ => return Ok(()),
    };

    let (protocol, clean_start, mut client_id, username, password, will, session_expiry_interval) =
        connect;
    if client_id.is_empty() {
        client_id = format!("auto-{}", unique_id());
    }
    if !connection_authorized(
        allow_anonymous,
        settings.password_file.as_ref(),
        username.as_deref(),
        password.as_deref(),
    ) {
        let rc = if protocol == ProtocolVersion::V5 {
            MQTT_RC_NOT_AUTHORIZED
        } else {
            5
        };
        stream.write_all(&encode_connack(protocol, false, rc))?;
        return Ok(());
    }
    client_users
        .lock()
        .expect("client user lock poisoned")
        .insert(client_id.clone(), username.clone());

    let broker_session_expiry_interval =
        broker_session_expiry_interval(protocol, clean_start, session_expiry_interval);
    let connect_result = broker.lock().expect("broker lock poisoned").connect(
        client_id.clone(),
        clean_start,
        will,
        broker_session_expiry_interval,
    );
    stream.write_all(&encode_connack_with_retain_available(
        protocol,
        connect_result.session_present,
        0,
        settings.retain_available,
    ))?;

    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    outbound.lock().expect("outbound lock poisoned").insert(
        client_id.clone(),
        ClientOutbound {
            protocol,
            sender: tx.clone(),
        },
    );

    let mut writer = stream.try_clone()?;
    thread::spawn(move || {
        while let Ok(packet) = rx.recv() {
            if writer.write_all(&packet).is_err() {
                break;
            }
        }
    });

    for publication in connect_result.queued {
        let _ = tx.send(encode_publish(protocol, &publication));
    }
    for packet_id in connect_result.pubrels {
        let _ = tx.send(encode_pubrel(protocol, packet_id));
    }

    let mut topic_aliases: HashMap<u16, String> = HashMap::new();
    while let Ok(frame) = read_frame(&mut stream) {
        let packet = match decode_frame(&frame, Some(protocol)) {
            Ok(packet) => packet,
            Err(_) => {
                if protocol == ProtocolVersion::V5 {
                    let _ = tx.send(encode_disconnect(protocol, MQTT_RC_MALFORMED_PACKET));
                }
                break;
            }
        };

        match packet {
            MqttPacket::Publish(mut publication) => {
                if publication.retain && !settings.retain_available {
                    if protocol == ProtocolVersion::V5 {
                        let _ = tx.send(encode_disconnect(protocol, MQTT_RC_RETAIN_NOT_SUPPORTED));
                    }
                    break;
                }
                if !resolve_topic_alias(&mut publication, &mut topic_aliases) {
                    if protocol == ProtocolVersion::V5 {
                        let _ = tx.send(encode_disconnect(protocol, MQTT_RC_MALFORMED_PACKET));
                    }
                    break;
                }
                if !acl_allows(
                    &settings,
                    username.as_deref(),
                    &client_id,
                    AclOperation::Write,
                    &publication.topic,
                ) {
                    match publication.qos {
                        1 => {
                            if let Some(packet_id) = publication.packet_id {
                                let _ = tx.send(encode_puback(protocol, packet_id));
                            }
                        }
                        2 => {
                            if let Some(packet_id) = publication.packet_id {
                                let _ = tx.send(encode_pubrec(protocol, packet_id));
                            }
                        }
                        _ => {}
                    }
                    continue;
                }

                match publication.qos {
                    1 => {
                        let packet_id = publication.packet_id;
                        let result = broker
                            .lock()
                            .expect("broker lock poisoned")
                            .publish(&client_id, publication);
                        if !result.accepted {
                            if protocol == ProtocolVersion::V5 {
                                let _ =
                                    tx.send(encode_disconnect(protocol, MQTT_RC_MALFORMED_PACKET));
                            }
                            break;
                        }
                        send_deliveries(&settings, &client_users, &outbound, result.deliveries);
                        if let Some(packet_id) = packet_id {
                            let _ = tx.send(encode_puback(protocol, packet_id));
                        }
                    }
                    2 => {
                        let Some(packet_id) = publication.packet_id else {
                            if protocol == ProtocolVersion::V5 {
                                let _ =
                                    tx.send(encode_disconnect(protocol, MQTT_RC_MALFORMED_PACKET));
                            }
                            break;
                        };
                        let result = broker
                            .lock()
                            .expect("broker lock poisoned")
                            .receive_qos2_publish(&client_id, publication);
                        if !result.accepted {
                            if protocol == ProtocolVersion::V5 {
                                let _ =
                                    tx.send(encode_disconnect(protocol, MQTT_RC_MALFORMED_PACKET));
                            }
                            break;
                        }
                        let _ = tx.send(encode_pubrec(protocol, packet_id));
                    }
                    _ => {
                        let result = broker
                            .lock()
                            .expect("broker lock poisoned")
                            .publish(&client_id, publication);
                        if !result.accepted {
                            if protocol == ProtocolVersion::V5 {
                                let _ =
                                    tx.send(encode_disconnect(protocol, MQTT_RC_MALFORMED_PACKET));
                            }
                            break;
                        }
                        send_deliveries(&settings, &client_users, &outbound, result.deliveries);
                    }
                }
            }
            MqttPacket::PubRel { packet_id } => {
                let result = broker
                    .lock()
                    .expect("broker lock poisoned")
                    .pubrel(&client_id, packet_id);
                if let Some(result) = result {
                    if !result.accepted {
                        if protocol == ProtocolVersion::V5 {
                            let _ = tx.send(encode_disconnect(protocol, MQTT_RC_MALFORMED_PACKET));
                        }
                        break;
                    }
                    send_deliveries(&settings, &client_users, &outbound, result.deliveries);
                }
                let _ = tx.send(encode_pubcomp(protocol, packet_id));
            }
            MqttPacket::PubAck { packet_id } => {
                let invalid_qos2_ack = broker
                    .lock()
                    .expect("broker lock poisoned")
                    .has_inflight_qos2(&client_id, packet_id);
                if invalid_qos2_ack {
                    if protocol == ProtocolVersion::V5 {
                        let _ = tx.send(encode_disconnect(protocol, MQTT_RC_PROTOCOL_ERROR));
                    }
                    break;
                }
                broker
                    .lock()
                    .expect("broker lock poisoned")
                    .puback(&client_id, packet_id);
            }
            MqttPacket::PubRec { packet_id } => {
                let invalid_qos1_ack = broker
                    .lock()
                    .expect("broker lock poisoned")
                    .has_inflight_qos1(&client_id, packet_id);
                if invalid_qos1_ack {
                    if protocol == ProtocolVersion::V5 {
                        let _ = tx.send(encode_disconnect(protocol, MQTT_RC_PROTOCOL_ERROR));
                    }
                    break;
                }
                let send_pubrel = broker
                    .lock()
                    .expect("broker lock poisoned")
                    .pubrec(&client_id, packet_id);
                if send_pubrel {
                    let _ = tx.send(encode_pubrel(protocol, packet_id));
                }
            }
            MqttPacket::PubComp { packet_id } => {
                let invalid_qos1_ack = broker
                    .lock()
                    .expect("broker lock poisoned")
                    .has_inflight_qos1(&client_id, packet_id);
                if invalid_qos1_ack {
                    if protocol == ProtocolVersion::V5 {
                        let _ = tx.send(encode_disconnect(protocol, MQTT_RC_PROTOCOL_ERROR));
                    }
                    break;
                }
                broker
                    .lock()
                    .expect("broker lock poisoned")
                    .pubcomp(&client_id, packet_id);
            }
            MqttPacket::Subscribe { packet_id, filters } => {
                let result = broker
                    .lock()
                    .expect("broker lock poisoned")
                    .subscribe(&client_id, filters);
                if result.reason_codes.iter().any(|code| *code == 0x80) {
                    if protocol == ProtocolVersion::V5 {
                        let _ = tx.send(encode_disconnect(protocol, MQTT_RC_MALFORMED_PACKET));
                    }
                    break;
                }
                let _ = tx.send(encode_suback(protocol, packet_id, &result.reason_codes));
                send_deliveries(&settings, &client_users, &outbound, result.retained);
            }
            MqttPacket::Unsubscribe { packet_id, filters } => {
                broker
                    .lock()
                    .expect("broker lock poisoned")
                    .unsubscribe(&client_id, &filters);
                let _ = tx.send(encode_unsuback(protocol, packet_id, filters.len()));
            }
            MqttPacket::PingReq => {
                let _ = tx.send(encode_pingresp());
            }
            MqttPacket::Disconnect {
                session_expiry_interval,
                ..
            } => {
                let deliveries = broker.lock().expect("broker lock poisoned").disconnect(
                    &client_id,
                    true,
                    session_expiry_interval,
                );
                send_deliveries(&settings, &client_users, &outbound, deliveries);
                outbound
                    .lock()
                    .expect("outbound lock poisoned")
                    .remove(&client_id);
                client_users
                    .lock()
                    .expect("client user lock poisoned")
                    .remove(&client_id);
                return Ok(());
            }
            MqttPacket::Connect { .. } => break,
        }
    }

    outbound
        .lock()
        .expect("outbound lock poisoned")
        .remove(&client_id);
    client_users
        .lock()
        .expect("client user lock poisoned")
        .remove(&client_id);
    let deliveries = broker
        .lock()
        .expect("broker lock poisoned")
        .disconnect(&client_id, false, None);
    send_deliveries(&settings, &client_users, &outbound, deliveries);
    Ok(())
}

fn resolve_topic_alias(
    publication: &mut Publication,
    topic_aliases: &mut HashMap<u16, String>,
) -> bool {
    if let Some(alias) = publication.topic_alias {
        if !publication.topic.is_empty() {
            topic_aliases.insert(alias, publication.topic.clone());
            true
        } else if let Some(topic) = topic_aliases.get(&alias) {
            publication.topic.clone_from(topic);
            true
        } else {
            false
        }
    } else {
        !publication.topic.is_empty()
    }
}

fn send_deliveries(
    settings: &Settings,
    client_users: &ClientUsers,
    outbound: &OutboundMap,
    deliveries: Vec<rusquitto_core::Delivery>,
) {
    let map = outbound.lock().expect("outbound lock poisoned");
    let users = client_users.lock().expect("client user lock poisoned");
    for delivery in deliveries {
        let username = users
            .get(&delivery.client_id)
            .and_then(|username| username.as_deref());
        if !acl_allows(
            settings,
            username,
            &delivery.client_id,
            AclOperation::Read,
            &delivery.publication.topic,
        ) {
            continue;
        }
        if let Some(client) = map.get(&delivery.client_id) {
            let _ = client
                .sender
                .send(encode_publish(client.protocol, &delivery.publication));
        }
    }
}

fn unique_id() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retained_publication(topic: &str, payload: &[u8], qos: u8) -> Publication {
        Publication {
            topic: topic.to_owned(),
            payload: payload.to_vec(),
            qos,
            retain: true,
            packet_id: None,
            dup: false,
            topic_alias: None,
            subscription_identifiers: Vec::new(),
        }
    }

    fn queued_publication(
        topic: &str,
        payload: &[u8],
        qos: u8,
        packet_id: u16,
        subscription_identifier: Option<u32>,
    ) -> Publication {
        Publication {
            topic: topic.to_owned(),
            payload: payload.to_vec(),
            qos,
            retain: false,
            packet_id: Some(packet_id),
            dup: false,
            topic_alias: None,
            subscription_identifiers: subscription_identifier.into_iter().collect(),
        }
    }

    fn sqlite_scalar(path: &str, sql: &str) -> String {
        let output = Command::new("sqlite3")
            .arg("-batch")
            .arg(path)
            .arg(sql)
            .output()
            .expect("sqlite3 should run");
        assert!(
            output.status.success(),
            "sqlite3 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("sqlite output should be utf8")
            .trim()
            .to_owned()
    }

    fn sqlite_exec(path: &str, sql: &str) {
        let output = Command::new("sqlite3")
            .arg("-batch")
            .arg(path)
            .arg(sql)
            .output()
            .expect("sqlite3 should run");
        assert!(
            output.status.success(),
            "sqlite3 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn write_temp_config(contents: &str) -> String {
        let path = env::temp_dir().join(format!("rusquitto-config-test-{}.conf", unique_id()));
        fs::write(&path, contents).expect("temp config should be written");
        path.to_string_lossy().to_string()
    }

    #[test]
    fn parse_settings_keeps_configured_listeners_when_cli_port_is_present() {
        let config = write_temp_config(
            "listener 18881\nlistener_allow_anonymous true\nlistener 18882\nlistener_allow_anonymous false\nallow_anonymous true\n",
        );

        let settings = parse_settings(vec![
            "-c".to_owned(),
            config.clone(),
            "-p".to_owned(),
            "18881".to_owned(),
        ])
        .expect("settings should parse");

        assert_eq!(
            settings.listeners,
            vec![
                ListenerSettings {
                    port: 18881,
                    allow_anonymous: true,
                },
                ListenerSettings {
                    port: 18882,
                    allow_anonymous: false,
                },
            ]
        );

        let _ = fs::remove_file(config);
    }

    #[test]
    fn parse_settings_uses_cli_port_when_config_has_no_listener() {
        let config = write_temp_config("max_connections 10\nallow_anonymous false\n");

        let settings = parse_settings(vec![
            "-c".to_owned(),
            config.clone(),
            "-p".to_owned(),
            "18883".to_owned(),
        ])
        .expect("settings should parse");

        assert_eq!(
            settings.listeners,
            vec![ListenerSettings {
                port: 18883,
                allow_anonymous: false,
            }]
        );

        let _ = fs::remove_file(config);
    }

    #[test]
    fn parse_settings_disables_anonymous_by_default_for_config_listeners() {
        let config = write_temp_config("listener 18884\n");

        let settings =
            parse_settings(vec!["-c".to_owned(), config.clone()]).expect("settings should parse");

        assert_eq!(
            settings.listeners,
            vec![ListenerSettings {
                port: 18884,
                allow_anonymous: false,
            }]
        );

        let _ = fs::remove_file(config);
    }

    #[test]
    fn parse_settings_loads_password_file_relative_to_config() {
        let dir = env::temp_dir().join(format!("rusquitto-password-test-{}", unique_id()));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        let password_file = dir.join("passwords");
        let config = dir.join("mosquitto.conf");
        fs::write(&password_file, "user:password\n").expect("password file should be written");
        fs::write(&config, "listener 18885\npassword_file passwords\n")
            .expect("config should be written");

        let settings = parse_settings(vec!["-c".to_owned(), config.to_string_lossy().to_string()])
            .expect("settings should parse");

        assert_eq!(
            settings
                .password_file
                .as_ref()
                .and_then(|entries| entries.get("user")),
            Some(&PasswordEntry::Plain("password".to_owned()))
        );

        let _ = fs::remove_file(&password_file);
        let _ = fs::remove_file(&config);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn connection_authorization_uses_plaintext_password_file_entries() {
        let mut passwords = HashMap::new();
        passwords.insert(
            "user".to_owned(),
            PasswordEntry::Plain("password".to_owned()),
        );

        assert!(connection_authorized(
            false,
            Some(&passwords),
            Some("user"),
            Some(b"password")
        ));
        assert!(!connection_authorized(
            false,
            Some(&passwords),
            Some("user"),
            Some(b"wrong")
        ));
        assert!(!connection_authorized(
            false,
            Some(&passwords),
            Some("user"),
            None
        ));
        assert!(!connection_authorized(
            false,
            Some(&passwords),
            Some("missing"),
            Some(b"password")
        ));
        assert!(connection_authorized(true, Some(&passwords), None, None));
        assert!(!connection_authorized(false, Some(&passwords), None, None));
        assert!(connection_authorized(
            true,
            None,
            Some("user"),
            Some(b"password")
        ));
        assert!(!connection_authorized(
            false,
            None,
            Some("user"),
            Some(b"password")
        ));
    }

    #[test]
    fn connection_authorization_matches_mosquitto_sha512_password_entries() {
        let mut passwords = HashMap::new();
        passwords.insert(
            "user".to_owned(),
            parse_password_entry("$6$vZY4TS+/HBxHw38S$vvjVFECzb8dyuu/mruD2QKTfdFn0WmKxbc+1TsdB0L8EdHk3v9JRmfjHd56+VaTnUcSZOZ/hzkdvWCtxlX7AUQ==")
                .expect("sha512 password entry should parse"),
        );

        assert!(connection_authorized(
            false,
            Some(&passwords),
            Some("user"),
            Some(b"password")
        ));
        assert!(!connection_authorized(
            false,
            Some(&passwords),
            Some("user"),
            Some(b"password9")
        ));
    }

    #[test]
    fn acl_file_matches_anonymous_user_and_pattern_rules() {
        let settings = Settings {
            acl_file: Some(AclFile {
                rules: vec![
                    AclRule {
                        scope: AclScope::Anonymous,
                        access: AclAccess::ReadWrite,
                        filter: "topic/global/#".to_owned(),
                    },
                    AclRule {
                        scope: AclScope::Anonymous,
                        access: AclAccess::Deny,
                        filter: "topic/global/except".to_owned(),
                    },
                    AclRule {
                        scope: AclScope::User("username".to_owned()),
                        access: AclAccess::ReadWrite,
                        filter: "topic/username/#".to_owned(),
                    },
                    AclRule {
                        scope: AclScope::User("username".to_owned()),
                        access: AclAccess::Deny,
                        filter: "topic/username/except".to_owned(),
                    },
                    AclRule {
                        scope: AclScope::Pattern,
                        access: AclAccess::ReadWrite,
                        filter: "pattern/%u/#".to_owned(),
                    },
                    AclRule {
                        scope: AclScope::Pattern,
                        access: AclAccess::Deny,
                        filter: "pattern/%u/except".to_owned(),
                    },
                ],
            }),
            ..Settings::default()
        };

        assert!(acl_allows(
            &settings,
            None,
            "client",
            AclOperation::Write,
            "topic/global"
        ));
        assert!(!acl_allows(
            &settings,
            Some("username"),
            "client",
            AclOperation::Write,
            "topic/global"
        ));
        assert!(!acl_allows(
            &settings,
            None,
            "client",
            AclOperation::Read,
            "topic/global/except"
        ));
        assert!(acl_allows(
            &settings,
            Some("username"),
            "client",
            AclOperation::Read,
            "topic/username/value"
        ));
        assert!(!acl_allows(
            &settings,
            Some("username"),
            "client",
            AclOperation::Read,
            "topic/username/except"
        ));
        assert!(acl_allows(
            &settings,
            Some("username"),
            "client",
            AclOperation::Write,
            "pattern/username/value"
        ));
        assert!(!acl_allows(
            &settings,
            Some("username"),
            "client",
            AclOperation::Write,
            "pattern/username/except"
        ));
        assert!(!acl_allows(
            &settings,
            None,
            "client",
            AclOperation::Write,
            "pattern/username/value"
        ));
    }

    #[test]
    fn acl_file_loader_preserves_topic_wildcards() {
        let path = env::temp_dir().join(format!("rusquitto-acl-test-{}.acl", unique_id()));
        fs::write(
            &path,
            "# comment\ntopic readwrite topic/global/#\npattern readwrite pattern/%u/#\n",
        )
        .expect("acl file should be written");

        let acl = load_acl_file(&path.to_string_lossy()).expect("acl should load");

        assert_eq!(acl.rules.len(), 2);
        assert_eq!(acl.rules[0].filter, "topic/global/#");
        assert_eq!(acl.rules[1].filter, "pattern/%u/#");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn maps_unknown_schema_version_to_migration_failure_exit_code() {
        assert_eq!(
            exit_code_for_error("Unknown database_schema version 1.2.0"),
            3
        );
        assert_eq!(exit_code_for_error("other startup failure"), 1);
    }

    #[test]
    fn sqlite_persistence_rejects_unknown_schema_versions() {
        let dir = env::temp_dir().join(format!("rusquitto-version-reject-test-{}", unique_id()));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        let db = dir.join("mosquitto.sqlite3");
        let db_path = db.to_string_lossy().to_string();

        sqlite_exec(
            &db_path,
            "CREATE TABLE version_info(component TEXT NOT NULL,major INTEGER NOT NULL,minor INTEGER NOT NULL,patch INTEGER NOT NULL); INSERT INTO version_info(component,major,minor,patch) VALUES ('database_schema',1,2,0);",
        );

        let err = sqlite_persistence::validate_schema_version(&db_path)
            .expect_err("unknown schema version should be rejected");
        assert_eq!(err, "Unknown database_schema version 1.2.0");
        let err = sqlite_persistence::save(&db_path, &[], &[])
            .expect_err("save should not rewrite unknown schema versions");
        assert_eq!(err, "Unknown database_schema version 1.2.0");

        let _ = fs::remove_file(&db);
        let _ = fs::remove_file(format!("{}-wal", db_path));
        let _ = fs::remove_file(format!("{}-shm", db_path));
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn sqlite_persistence_round_trips_retained_messages() {
        let dir = env::temp_dir().join(format!("rusquitto-retained-test-{}", unique_id()));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        let db = dir.join("mosquitto.sqlite3");
        let db_path = db.to_string_lossy().to_string();

        let retained = vec![
            retained_publication("b/topic", b"payload-b", 1),
            retained_publication("a/topic", b"payload-a", 0),
        ];
        sqlite_persistence::save(&db_path, &retained, &[]).expect("retained save should work");

        assert_eq!(
            sqlite_scalar(&db_path, "SELECT COUNT(*) FROM base_msgs;"),
            "2"
        );
        assert_eq!(
            sqlite_scalar(&db_path, "SELECT COUNT(*) FROM retains;"),
            "2"
        );
        assert_eq!(
            sqlite_scalar(&db_path, "SELECT COUNT(*) FROM clients;"),
            "0"
        );
        assert_eq!(
            sqlite_scalar(&db_path, "SELECT COUNT(*) FROM subscriptions;"),
            "0"
        );
        assert_eq!(
            sqlite_scalar(&db_path, "SELECT COUNT(*) FROM client_msgs;"),
            "0"
        );
        assert_eq!(sqlite_scalar(&db_path, "SELECT COUNT(*) FROM wills;"), "0");
        assert_eq!(
            sqlite_scalar(
                &db_path,
                "SELECT major || '.' || minor || '.' || patch FROM version_info WHERE component = 'database_schema';",
            ),
            "1.1.0"
        );

        let loaded =
            sqlite_persistence::load_retained(&db_path).expect("retained load should work");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].topic, "a/topic");
        assert_eq!(loaded[0].payload, b"payload-a");
        assert_eq!(loaded[0].qos, 0);
        assert!(loaded[0].retain);
        assert_eq!(loaded[1].topic, "b/topic");
        assert_eq!(loaded[1].payload, b"payload-b");
        assert_eq!(loaded[1].qos, 1);
        assert!(loaded[1].retain);

        let _ = fs::remove_file(&db);
        let _ = fs::remove_file(format!("{}-wal", db_path));
        let _ = fs::remove_file(format!("{}-shm", db_path));
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn sqlite_persistence_preserves_compatible_schema_patch_version() {
        let dir = env::temp_dir().join(format!("rusquitto-version-test-{}", unique_id()));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        let db = dir.join("mosquitto.sqlite3");
        let db_path = db.to_string_lossy().to_string();

        sqlite_persistence::save(&db_path, &[], &[]).expect("initial save should work");
        sqlite_exec(
            &db_path,
            "UPDATE version_info SET patch = 2 WHERE component = 'database_schema';",
        );
        sqlite_persistence::save(&db_path, &[], &[]).expect("resave should work");

        assert_eq!(
            sqlite_scalar(
                &db_path,
                "SELECT major || '.' || minor || '.' || patch FROM version_info WHERE component = 'database_schema';",
            ),
            "1.1.2"
        );

        let _ = fs::remove_file(&db);
        let _ = fs::remove_file(format!("{}-wal", db_path));
        let _ = fs::remove_file(format!("{}-shm", db_path));
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn sqlite_persistence_round_trips_queued_messages() {
        let dir = env::temp_dir().join(format!("rusquitto-queue-test-{}", unique_id()));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        let db = dir.join("mosquitto.sqlite3");
        let db_path = db.to_string_lossy().to_string();

        let sessions = vec![PersistedSession {
            client_id: "queued-client".into(),
            session_expiry_interval: 60,
            subscriptions: Vec::new(),
            queued: vec![
                queued_publication("queue/one", b"message-one", 1, 4, Some(12)),
                queued_publication("queue/two", b"message-two", 2, 5, None),
            ],
            inflight_qos1: Vec::new(),
            inflight_qos2: Vec::new(),
            inbound_qos2: Vec::new(),
        }];
        sqlite_persistence::save(&db_path, &[], &sessions).expect("queue save should work");

        assert_eq!(
            sqlite_scalar(&db_path, "SELECT COUNT(*) FROM base_msgs;"),
            "2"
        );
        assert_eq!(
            sqlite_scalar(
                &db_path,
                "SELECT COUNT(*) FROM client_msgs WHERE direction = 1;",
            ),
            "2"
        );
        assert_eq!(
            sqlite_scalar(
                &db_path,
                "SELECT cmsg_id || ':' || store_id || ':' || mid || ':' || qos || ':' || state || ':' || subscription_identifier FROM client_msgs ORDER BY cmsg_id;",
            ),
            "1:1:4:1:11:12\n2:2:5:2:11:0"
        );

        let loaded = sqlite_persistence::load_sessions(&db_path).expect("queue load should work");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].client_id, "queued-client");
        assert_eq!(loaded[0].queued.len(), 2);
        assert_eq!(loaded[0].queued[0].topic, "queue/one");
        assert_eq!(loaded[0].queued[0].payload, b"message-one");
        assert_eq!(loaded[0].queued[0].qos, 1);
        assert_eq!(loaded[0].queued[0].packet_id, Some(4));
        assert_eq!(loaded[0].queued[0].subscription_identifiers, vec![12]);
        assert_eq!(loaded[0].queued[1].topic, "queue/two");
        assert_eq!(loaded[0].queued[1].payload, b"message-two");
        assert_eq!(loaded[0].queued[1].qos, 2);
        assert_eq!(loaded[0].queued[1].packet_id, Some(5));
        assert!(loaded[0].queued[1].subscription_identifiers.is_empty());

        let _ = fs::remove_file(&db);
        let _ = fs::remove_file(format!("{}-wal", db_path));
        let _ = fs::remove_file(format!("{}-shm", db_path));
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn sqlite_persistence_round_trips_outbound_inflight_messages() {
        let dir = env::temp_dir().join(format!("rusquitto-inflight-test-{}", unique_id()));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        let db = dir.join("mosquitto.sqlite3");
        let db_path = db.to_string_lossy().to_string();

        let mut qos2_wait_pubrec =
            queued_publication("inflight/qos2/pubrec", b"qos2-a", 2, 8, Some(31));
        qos2_wait_pubrec.dup = true;
        let qos2_wait_pubcomp = queued_publication("inflight/qos2/pubcomp", b"qos2-b", 2, 9, None);
        let sessions = vec![PersistedSession {
            client_id: "inflight-client".into(),
            session_expiry_interval: 60,
            subscriptions: Vec::new(),
            queued: Vec::new(),
            inflight_qos1: vec![queued_publication("inflight/qos1", b"qos1", 1, 7, Some(30))],
            inflight_qos2: vec![
                Qos2Outbound {
                    publication: qos2_wait_pubrec,
                    state: Qos2OutboundState::WaitingPubRec,
                },
                Qos2Outbound {
                    publication: qos2_wait_pubcomp,
                    state: Qos2OutboundState::WaitingPubComp,
                },
            ],
            inbound_qos2: Vec::new(),
        }];
        sqlite_persistence::save(&db_path, &[], &sessions).expect("inflight save should work");

        assert_eq!(
            sqlite_scalar(&db_path, "SELECT COUNT(*) FROM base_msgs;"),
            "3"
        );
        assert_eq!(
            sqlite_scalar(
                &db_path,
                "SELECT cmsg_id || ':' || store_id || ':' || mid || ':' || qos || ':' || dup || ':' || state || ':' || subscription_identifier FROM client_msgs ORDER BY cmsg_id;",
            ),
            "1:1:7:1:0:3:30\n2:2:8:2:1:5:31\n3:3:9:2:0:9:0"
        );

        let loaded =
            sqlite_persistence::load_sessions(&db_path).expect("inflight load should work");
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].queued.is_empty());
        assert_eq!(loaded[0].inflight_qos1.len(), 1);
        assert_eq!(loaded[0].inflight_qos1[0].topic, "inflight/qos1");
        assert_eq!(loaded[0].inflight_qos1[0].packet_id, Some(7));
        assert_eq!(
            loaded[0].inflight_qos1[0].subscription_identifiers,
            vec![30]
        );
        assert_eq!(loaded[0].inflight_qos2.len(), 2);
        assert_eq!(
            loaded[0].inflight_qos2[0].state,
            Qos2OutboundState::WaitingPubRec
        );
        assert!(loaded[0].inflight_qos2[0].publication.dup);
        assert_eq!(
            loaded[0].inflight_qos2[1].state,
            Qos2OutboundState::WaitingPubComp
        );

        let _ = fs::remove_file(&db);
        let _ = fs::remove_file(format!("{}-wal", db_path));
        let _ = fs::remove_file(format!("{}-shm", db_path));
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn sqlite_persistence_round_trips_inbound_qos2_messages() {
        let dir = env::temp_dir().join(format!("rusquitto-inbound-test-{}", unique_id()));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        let db = dir.join("mosquitto.sqlite3");
        let db_path = db.to_string_lossy().to_string();

        let sessions = vec![PersistedSession {
            client_id: "inbound-client".into(),
            session_expiry_interval: 60,
            subscriptions: Vec::new(),
            queued: Vec::new(),
            inflight_qos1: Vec::new(),
            inflight_qos2: Vec::new(),
            inbound_qos2: vec![
                queued_publication("inbound/qos2/one", b"inbound-one", 2, 10, None),
                queued_publication("inbound/qos2/two", b"inbound-two", 2, 11, None),
            ],
        }];
        sqlite_persistence::save(&db_path, &[], &sessions).expect("inbound save should work");

        assert_eq!(
            sqlite_scalar(&db_path, "SELECT COUNT(*) FROM base_msgs;"),
            "2"
        );
        assert_eq!(
            sqlite_scalar(
                &db_path,
                "SELECT cmsg_id || ':' || store_id || ':' || direction || ':' || mid || ':' || qos || ':' || state FROM client_msgs ORDER BY cmsg_id;",
            ),
            "1:1:0:10:2:7\n2:2:0:11:2:7"
        );

        let loaded = sqlite_persistence::load_sessions(&db_path).expect("inbound load should work");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].client_id, "inbound-client");
        assert!(loaded[0].queued.is_empty());
        assert!(loaded[0].inflight_qos1.is_empty());
        assert!(loaded[0].inflight_qos2.is_empty());
        assert_eq!(loaded[0].inbound_qos2.len(), 2);
        assert_eq!(loaded[0].inbound_qos2[0].topic, "inbound/qos2/one");
        assert_eq!(loaded[0].inbound_qos2[0].payload, b"inbound-one");
        assert_eq!(loaded[0].inbound_qos2[0].packet_id, Some(10));
        assert_eq!(loaded[0].inbound_qos2[1].topic, "inbound/qos2/two");
        assert_eq!(loaded[0].inbound_qos2[1].payload, b"inbound-two");
        assert_eq!(loaded[0].inbound_qos2[1].packet_id, Some(11));

        let _ = fs::remove_file(&db);
        let _ = fs::remove_file(format!("{}-wal", db_path));
        let _ = fs::remove_file(format!("{}-shm", db_path));
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn sqlite_persistence_round_trips_durable_sessions_and_subscriptions() {
        let dir = env::temp_dir().join(format!("rusquitto-session-test-{}", unique_id()));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        let db = dir.join("mosquitto.sqlite3");
        let db_path = db.to_string_lossy().to_string();

        let sessions = vec![PersistedSession {
            client_id: "persist-client".into(),
            session_expiry_interval: u32::MAX,
            subscriptions: vec![Subscription {
                filter: "persist/#".into(),
                qos: 1,
                no_local: true,
                retain_as_published: true,
                retain_handling: 2,
                identifier: Some(7),
                order: 9,
            }],
            queued: Vec::new(),
            inflight_qos1: Vec::new(),
            inflight_qos2: Vec::new(),
            inbound_qos2: Vec::new(),
        }];
        sqlite_persistence::save(&db_path, &[], &sessions).expect("session save should work");

        assert_eq!(
            sqlite_scalar(&db_path, "SELECT COUNT(*) FROM clients;"),
            "1"
        );
        assert_eq!(
            sqlite_scalar(&db_path, "SELECT COUNT(*) FROM subscriptions;"),
            "1"
        );
        assert_eq!(
            sqlite_scalar(
                &db_path,
                "SELECT client_id || ':' || session_expiry_interval || ':' || session_expiry_time FROM clients;",
            ),
            "persist-client:-1:0"
        );
        assert_eq!(
            sqlite_scalar(
                &db_path,
                "SELECT topic || ':' || subscription_options || ':' || subscription_identifier FROM subscriptions;",
            ),
            "persist/#:45:7"
        );

        let loaded = sqlite_persistence::load_sessions(&db_path).expect("session load should work");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].client_id, "persist-client");
        assert_eq!(loaded[0].session_expiry_interval, u32::MAX);
        assert_eq!(loaded[0].subscriptions.len(), 1);
        assert!(loaded[0].queued.is_empty());
        assert!(loaded[0].inflight_qos1.is_empty());
        assert!(loaded[0].inflight_qos2.is_empty());
        assert!(loaded[0].inbound_qos2.is_empty());
        let subscription = &loaded[0].subscriptions[0];
        assert_eq!(subscription.filter, "persist/#");
        assert_eq!(subscription.qos, 1);
        assert!(subscription.no_local);
        assert!(subscription.retain_as_published);
        assert_eq!(subscription.retain_handling, 2);
        assert_eq!(subscription.identifier, Some(7));

        let _ = fs::remove_file(&db);
        let _ = fs::remove_file(format!("{}-wal", db_path));
        let _ = fs::remove_file(format!("{}-shm", db_path));
        let _ = fs::remove_dir(&dir);
    }
}
