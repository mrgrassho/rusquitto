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

use rusquitto_core::{BrokerState, PersistedSession, Subscription};
use rusquitto_protocol::{
    decode_frame, encode_connack, encode_connack_with_retain_available, encode_disconnect,
    encode_pingresp, encode_puback, encode_pubcomp, encode_publish, encode_pubrec, encode_pubrel,
    encode_suback, encode_unsuback, read_frame, MqttPacket, ProtocolVersion, Publication,
};

const MQTT_RC_MALFORMED_PACKET: u8 = 0x81;
const MQTT_RC_PROTOCOL_ERROR: u8 = 0x82;
const MQTT_RC_NOT_AUTHORIZED: u8 = 0x87;
const MQTT_RC_RETAIN_NOT_SUPPORTED: u8 = 0x9A;

type OutboundMap = Arc<Mutex<HashMap<String, ClientOutbound>>>;
type SharedBroker = Arc<Mutex<BrokerState>>;

#[derive(Debug, Clone)]
struct ClientOutbound {
    protocol: ProtocolVersion,
    sender: Sender<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct Settings {
    port: u16,
    verbose: bool,
    allow_anonymous: bool,
    retain_available: bool,
    upgrade_outgoing_qos: bool,
    persistence_db_file: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            port: 1883,
            verbose: false,
            allow_anonymous: true,
            retain_available: true,
            upgrade_outgoing_qos: false,
            persistence_db_file: None,
        }
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let settings = parse_settings(env::args().skip(1).collect())?;
    let listener = bind_listener(settings.port)?;
    if settings.verbose {
        eprintln!("rusquitto version 2.1.2 starting");
        eprintln!("Opening ipv4 listen socket on port {}.", settings.port);
    }

    shutdown::install();
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;

    let mut broker_state = BrokerState::new();
    broker_state.set_upgrade_outgoing_qos(settings.upgrade_outgoing_qos);
    if let Some(path) = settings.persistence_db_file.as_deref() {
        let retained = sqlite_persistence::load_retained(path)?;
        broker_state.restore_retained(retained);
        let sessions = sqlite_persistence::load_sessions(path)?;
        broker_state.restore_sessions(sessions);
    }
    let broker = Arc::new(Mutex::new(broker_state));
    let outbound = Arc::new(Mutex::new(HashMap::new()));
    while !shutdown::requested() {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(err) = stream.set_nonblocking(false) {
                    eprintln!("Client setup error: {err}");
                    continue;
                }
                let broker = Arc::clone(&broker);
                let outbound = Arc::clone(&outbound);
                let settings = settings.clone();
                thread::spawn(move || {
                    if let Err(err) = handle_client(stream, broker, outbound, settings) {
                        eprintln!("Client error: {err}");
                    }
                });
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => {
                eprintln!("Accept error: {err}");
            }
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

fn bind_listener(port: u16) -> Result<TcpListener, String> {
    TcpListener::bind(("::", port))
        .or_else(|_| TcpListener::bind(("0.0.0.0", port)))
        .map_err(|e| e.to_string())
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
    let mut listener_allow = None;
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
                "port" | "listener" => {
                    config_declared_listener = true;
                    if let Some(value) = value {
                        if let Ok(port) = value.parse::<u16>() {
                            settings.port = port;
                        }
                    }
                }
                "allow_anonymous" => {
                    explicit_allow = parse_bool(value);
                }
                "listener_allow_anonymous" => {
                    listener_allow = parse_bool(value);
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
                _ => {}
            }
        }
    }

    if let Some(port) = cli_port {
        settings.port = port;
    }
    settings.allow_anonymous = if let Some(value) = listener_allow {
        value
    } else if let Some(value) = explicit_allow {
        value
    } else {
        !config_declared_listener
    };

    Ok(settings)
}

fn parse_bool(value: Option<&str>) -> Option<bool> {
    match value {
        Some("true") | Some("1") => Some(true),
        Some("false") | Some("0") => Some(false),
        _ => None,
    }
}

mod sqlite_persistence {
    use super::*;

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
        Ok(sessions)
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

        let mut sql = String::new();
        sql.push_str("PRAGMA page_size=4096;\n");
        sql.push_str("PRAGMA journal_mode=WAL;\n");
        sql.push_str("PRAGMA foreign_keys = ON;\n");
        sql.push_str("PRAGMA synchronous=1;\n");
        append_schema(&mut sql);
        sql.push_str("BEGIN IMMEDIATE;\n");
        sql.push_str("DELETE FROM client_msgs;\n");
        sql.push_str("DELETE FROM subscriptions;\n");
        sql.push_str("DELETE FROM clients;\n");
        sql.push_str("DELETE FROM retains;\n");
        sql.push_str("DELETE FROM base_msgs;\n");
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
        }
        for (idx, publication) in retained.iter().enumerate() {
            let store_id = idx + 1;
            sql.push_str(&format!(
                "INSERT INTO base_msgs(store_id,expiry_time,topic,payload,source_id,source_username,payloadlen,source_mid,source_port,qos,retain,properties) VALUES ({store_id},0,'{}',X'{}','',NULL,{},0,0,{},1,NULL);\n",
                escape_sql(&publication.topic),
                encode_hex(&publication.payload),
                publication.payload.len(),
                publication.qos,
            ));
            sql.push_str(&format!(
                "INSERT INTO retains(topic,store_id) VALUES ('{}',{store_id});\n",
                escape_sql(&publication.topic)
            ));
        }
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

    fn append_schema(sql: &mut String) {
        sql.push_str("CREATE TABLE IF NOT EXISTS base_msgs (store_id INT64 PRIMARY KEY,expiry_time INT64,topic STRING NOT NULL,payload BLOB,source_id STRING,source_username STRING,payloadlen INTEGER,source_mid INTEGER,source_port INTEGER,qos INTEGER,retain INTEGER,properties STRING);\n");
        sql.push_str(
            "CREATE TABLE IF NOT EXISTS retains (topic STRING PRIMARY KEY,store_id INT64);\n",
        );
        sql.push_str("CREATE TABLE IF NOT EXISTS clients (client_id TEXT PRIMARY KEY,username TEXT,connection_time INT64,will_delay_time INT64,session_expiry_time INT64,listener_port INT,max_packet_size INT,max_qos INT,retain_available INT,session_expiry_interval INT,will_delay_interval INT);\n");
        sql.push_str("CREATE TABLE IF NOT EXISTS subscriptions (client_id TEXT NOT NULL,topic TEXT NOT NULL,subscription_options INTEGER,subscription_identifier INTEGER,PRIMARY KEY (client_id, topic) );\n");
        sql.push_str("CREATE TABLE IF NOT EXISTS client_msgs (client_id TEXT NOT NULL,cmsg_id INT64,store_id INT64,dup INTEGER,direction INTEGER,mid INTEGER,qos INTEGER,retain INTEGER,state INTEGER,subscription_identifier INTEGER);\n");
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
    settings: Settings,
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
            will,
            session_expiry_interval,
            ..
        }) => (
            protocol,
            clean_start,
            client_id,
            username,
            will,
            session_expiry_interval,
        ),
        _ => return Ok(()),
    };

    let (protocol, clean_start, mut client_id, username, will, session_expiry_interval) = connect;
    if client_id.is_empty() {
        client_id = format!("auto-{}", unique_id());
    }
    if !settings.allow_anonymous && username.is_none() {
        let rc = if protocol == ProtocolVersion::V5 {
            MQTT_RC_NOT_AUTHORIZED
        } else {
            5
        };
        stream.write_all(&encode_connack(protocol, false, rc))?;
        return Ok(());
    }

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
                        send_deliveries(protocol, &outbound, result.deliveries);
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
                        send_deliveries(protocol, &outbound, result.deliveries);
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
                    send_deliveries(protocol, &outbound, result.deliveries);
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
                send_deliveries(protocol, &outbound, result.retained);
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
                send_deliveries(protocol, &outbound, deliveries);
                outbound
                    .lock()
                    .expect("outbound lock poisoned")
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
    let deliveries = broker
        .lock()
        .expect("broker lock poisoned")
        .disconnect(&client_id, false, None);
    send_deliveries(protocol, &outbound, deliveries);
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
    _source_protocol: ProtocolVersion,
    outbound: &OutboundMap,
    deliveries: Vec<rusquitto_core::Delivery>,
) {
    let map = outbound.lock().expect("outbound lock poisoned");
    for delivery in deliveries {
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
