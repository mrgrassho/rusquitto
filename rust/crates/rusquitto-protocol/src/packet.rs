use std::fmt;
use std::io::{self, Read};

const CMD_CONNECT: u8 = 0x10;
const CMD_CONNACK: u8 = 0x20;
const CMD_PUBLISH: u8 = 0x30;
const CMD_PUBACK: u8 = 0x40;
const CMD_PUBREC: u8 = 0x50;
const CMD_PUBREL: u8 = 0x60;
const CMD_PUBCOMP: u8 = 0x70;
const CMD_SUBSCRIBE: u8 = 0x80;
const CMD_SUBACK: u8 = 0x90;
const CMD_UNSUBSCRIBE: u8 = 0xA0;
const CMD_UNSUBACK: u8 = 0xB0;
const CMD_PINGREQ: u8 = 0xC0;
const CMD_PINGRESP: u8 = 0xD0;
const CMD_DISCONNECT: u8 = 0xE0;

const PROP_PAYLOAD_FORMAT_INDICATOR: u32 = 0x01;
const PROP_MESSAGE_EXPIRY_INTERVAL: u32 = 0x02;
const PROP_CONTENT_TYPE: u32 = 0x03;
const PROP_RESPONSE_TOPIC: u32 = 0x08;
const PROP_CORRELATION_DATA: u32 = 0x09;
const PROP_SUBSCRIPTION_IDENTIFIER: u32 = 0x0B;
const PROP_SESSION_EXPIRY_INTERVAL: u32 = 0x11;
const PROP_ASSIGNED_CLIENT_IDENTIFIER: u32 = 0x12;
const PROP_SERVER_KEEP_ALIVE: u32 = 0x13;
const PROP_AUTHENTICATION_METHOD: u32 = 0x15;
const PROP_AUTHENTICATION_DATA: u32 = 0x16;
const PROP_REQUEST_PROBLEM_INFORMATION: u32 = 0x17;
const PROP_WILL_DELAY_INTERVAL: u32 = 0x18;
const PROP_REQUEST_RESPONSE_INFORMATION: u32 = 0x19;
const PROP_RESPONSE_INFORMATION: u32 = 0x1A;
const PROP_SERVER_REFERENCE: u32 = 0x1C;
const PROP_REASON_STRING: u32 = 0x1F;
const PROP_RECEIVE_MAXIMUM: u32 = 0x21;
const PROP_TOPIC_ALIAS_MAXIMUM: u32 = 0x22;
const PROP_TOPIC_ALIAS: u32 = 0x23;
const PROP_MAXIMUM_QOS: u32 = 0x24;
const PROP_RETAIN_AVAILABLE: u32 = 0x25;
const PROP_USER_PROPERTY: u32 = 0x26;
const PROP_MAXIMUM_PACKET_SIZE: u32 = 0x27;
const PROP_WILDCARD_SUB_AVAILABLE: u32 = 0x28;
const PROP_SUBSCRIPTION_ID_AVAILABLE: u32 = 0x29;
const PROP_SHARED_SUB_AVAILABLE: u32 = 0x2A;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    V31,
    V311,
    V5,
}

impl ProtocolVersion {
    pub fn level(self) -> u8 {
        match self {
            Self::V31 => 3,
            Self::V311 => 4,
            Self::V5 => 5,
        }
    }

    fn from_level(level: u8) -> Result<Self, ProtocolError> {
        match level {
            3 => Ok(Self::V31),
            4 => Ok(Self::V311),
            5 => Ok(Self::V5),
            _ => Err(ProtocolError::UnsupportedProtocolVersion(level)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub command: u8,
    pub flags: u8,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Will {
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: u8,
    pub retain: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publication {
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: u8,
    pub retain: bool,
    pub packet_id: Option<u16>,
    pub dup: bool,
    pub topic_alias: Option<u16>,
    pub payload_format_indicator: Option<u8>,
    pub response_topic: Option<String>,
    pub correlation_data: Option<Vec<u8>>,
    pub subscription_identifiers: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionRequest {
    pub filter: String,
    pub qos: u8,
    pub no_local: bool,
    pub retain_as_published: bool,
    pub retain_handling: u8,
    pub identifier: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MqttPacket {
    Connect {
        protocol: ProtocolVersion,
        clean_start: bool,
        keep_alive: u16,
        client_id: String,
        username: Option<String>,
        password: Option<Vec<u8>>,
        will: Option<Will>,
        session_expiry_interval: Option<u32>,
        maximum_packet_size: Option<u32>,
    },
    Publish(Publication),
    PubAck {
        packet_id: u16,
    },
    PubRec {
        packet_id: u16,
    },
    PubRel {
        packet_id: u16,
    },
    PubComp {
        packet_id: u16,
    },
    Subscribe {
        packet_id: u16,
        filters: Vec<SubscriptionRequest>,
    },
    Unsubscribe {
        packet_id: u16,
        filters: Vec<String>,
    },
    PingReq,
    Disconnect {
        reason_code: Option<u8>,
        session_expiry_interval: Option<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Io(String),
    MalformedPacket(&'static str),
    UnsupportedProtocolVersion(u8),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::MalformedPacket(msg) => write!(f, "malformed MQTT packet: {msg}"),
            Self::UnsupportedProtocolVersion(level) => {
                write!(f, "unsupported MQTT protocol level {level}")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<io::Error> for ProtocolError {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

pub fn read_frame<R: Read>(reader: &mut R) -> Result<Frame, ProtocolError> {
    let mut first = [0_u8; 1];
    reader.read_exact(&mut first)?;
    let remaining_len = read_remaining_length(reader)?;
    let mut body = vec![0_u8; remaining_len as usize];
    reader.read_exact(&mut body)?;
    Ok(Frame {
        command: first[0] & 0xF0,
        flags: first[0] & 0x0F,
        body,
    })
}

fn read_remaining_length<R: Read>(reader: &mut R) -> Result<u32, ProtocolError> {
    let mut multiplier = 1_u32;
    let mut value = 0_u32;
    for _ in 0..4 {
        let mut byte = [0_u8; 1];
        reader.read_exact(&mut byte)?;
        value += ((byte[0] & 127) as u32) * multiplier;
        if (byte[0] & 128) == 0 {
            return Ok(value);
        }
        multiplier = multiplier
            .checked_mul(128)
            .ok_or(ProtocolError::MalformedPacket("remaining length overflow"))?;
    }
    Err(ProtocolError::MalformedPacket(
        "remaining length is too long",
    ))
}

pub fn decode_frame(
    frame: &Frame,
    current_protocol: Option<ProtocolVersion>,
) -> Result<MqttPacket, ProtocolError> {
    let mut cursor = Cursor::new(&frame.body);
    match frame.command {
        CMD_CONNECT => decode_connect(&mut cursor),
        CMD_PUBLISH => decode_publish(frame.flags, &mut cursor, current_protocol),
        CMD_PUBACK => Ok(MqttPacket::PubAck {
            packet_id: read_packet_id(&mut cursor)?,
        }),
        CMD_PUBREC => Ok(MqttPacket::PubRec {
            packet_id: read_packet_id(&mut cursor)?,
        }),
        CMD_PUBREL => Ok(MqttPacket::PubRel {
            packet_id: read_packet_id(&mut cursor)?,
        }),
        CMD_PUBCOMP => Ok(MqttPacket::PubComp {
            packet_id: read_packet_id(&mut cursor)?,
        }),
        CMD_SUBSCRIBE => decode_subscribe(&mut cursor, current_protocol),
        CMD_UNSUBSCRIBE => decode_unsubscribe(&mut cursor, current_protocol),
        CMD_PINGREQ => Ok(MqttPacket::PingReq),
        CMD_DISCONNECT => decode_disconnect(&mut cursor, current_protocol),
        _ => Err(ProtocolError::MalformedPacket("unsupported command")),
    }
}

fn decode_connect(cursor: &mut Cursor<'_>) -> Result<MqttPacket, ProtocolError> {
    let protocol_name = cursor.read_utf8()?;
    let level = cursor.read_u8()?;
    let protocol = ProtocolVersion::from_level(level)?;
    if (protocol == ProtocolVersion::V31 && protocol_name != "MQIsdp")
        || (protocol != ProtocolVersion::V31 && protocol_name != "MQTT")
    {
        return Err(ProtocolError::MalformedPacket("invalid protocol name"));
    }

    let flags = cursor.read_u8()?;
    let clean_start = (flags & 0x02) != 0;
    let will_flag = (flags & 0x04) != 0;
    let will_qos = (flags & 0x18) >> 3;
    let will_retain = (flags & 0x20) != 0;
    let password_flag = (flags & 0x40) != 0;
    let username_flag = (flags & 0x80) != 0;
    let keep_alive = cursor.read_u16()?;

    let connect_properties = if protocol == ProtocolVersion::V5 {
        cursor.read_connect_properties()?
    } else {
        ConnectProperties::default()
    };

    let client_id = cursor.read_utf8()?;
    let will = if will_flag {
        if protocol == ProtocolVersion::V5 {
            cursor.skip_properties()?;
        }
        Some(Will {
            topic: cursor.read_utf8()?,
            payload: cursor.read_binary()?,
            qos: will_qos,
            retain: will_retain,
        })
    } else {
        None
    };
    let username = if username_flag {
        Some(cursor.read_utf8()?)
    } else {
        None
    };
    let password = if password_flag {
        Some(cursor.read_binary()?)
    } else {
        None
    };

    Ok(MqttPacket::Connect {
        protocol,
        clean_start,
        keep_alive,
        client_id,
        username,
        password,
        will,
        session_expiry_interval: connect_properties.session_expiry_interval,
        maximum_packet_size: connect_properties.maximum_packet_size,
    })
}

fn decode_publish(
    flags: u8,
    cursor: &mut Cursor<'_>,
    current_protocol: Option<ProtocolVersion>,
) -> Result<MqttPacket, ProtocolError> {
    let dup = (flags & 0x08) != 0;
    let qos = (flags & 0x06) >> 1;
    let retain = (flags & 0x01) != 0;
    if qos == 3 {
        return Err(ProtocolError::MalformedPacket("invalid publish qos"));
    }
    let topic = cursor.read_utf8()?;
    let packet_id = if qos > 0 {
        Some(read_packet_id(cursor)?)
    } else {
        None
    };
    let publish_properties = if current_protocol == Some(ProtocolVersion::V5) {
        cursor.read_publish_properties()?
    } else {
        PublishProperties::default()
    };
    let payload = cursor.read_remaining().to_vec();
    Ok(MqttPacket::Publish(Publication {
        topic,
        payload,
        qos,
        retain,
        packet_id,
        dup,
        topic_alias: publish_properties.topic_alias,
        payload_format_indicator: publish_properties.payload_format_indicator,
        response_topic: publish_properties.response_topic,
        correlation_data: publish_properties.correlation_data,
        subscription_identifiers: publish_properties.subscription_identifiers,
    }))
}

fn decode_subscribe(
    cursor: &mut Cursor<'_>,
    current_protocol: Option<ProtocolVersion>,
) -> Result<MqttPacket, ProtocolError> {
    let packet_id = read_packet_id(cursor)?;
    let identifier = if current_protocol == Some(ProtocolVersion::V5) {
        cursor.read_subscribe_properties()?
    } else {
        None
    };
    let mut filters = Vec::new();
    while cursor.remaining() > 0 {
        let filter = cursor.read_utf8()?;
        let options = cursor.read_u8()?;
        let qos = options & 0x03;
        let retain_handling = (options & 0x30) >> 4;
        if qos == 3 || retain_handling == 3 || (options & 0xC0) != 0 {
            return Err(ProtocolError::MalformedPacket("invalid subscribe options"));
        }
        filters.push(SubscriptionRequest {
            filter,
            qos,
            no_local: (options & 0x04) != 0,
            retain_as_published: (options & 0x08) != 0,
            retain_handling,
            identifier,
        });
    }
    if filters.is_empty() {
        return Err(ProtocolError::MalformedPacket("empty subscribe"));
    }
    Ok(MqttPacket::Subscribe { packet_id, filters })
}

fn decode_unsubscribe(
    cursor: &mut Cursor<'_>,
    current_protocol: Option<ProtocolVersion>,
) -> Result<MqttPacket, ProtocolError> {
    let packet_id = read_packet_id(cursor)?;
    if current_protocol == Some(ProtocolVersion::V5) {
        cursor.skip_properties()?;
    }
    let mut filters = Vec::new();
    while cursor.remaining() > 0 {
        filters.push(cursor.read_utf8()?);
    }
    if filters.is_empty() {
        return Err(ProtocolError::MalformedPacket("empty unsubscribe"));
    }
    Ok(MqttPacket::Unsubscribe { packet_id, filters })
}

fn decode_disconnect(
    cursor: &mut Cursor<'_>,
    current_protocol: Option<ProtocolVersion>,
) -> Result<MqttPacket, ProtocolError> {
    if cursor.remaining() == 0 || current_protocol != Some(ProtocolVersion::V5) {
        return Ok(MqttPacket::Disconnect {
            reason_code: None,
            session_expiry_interval: None,
        });
    }
    let reason_code = cursor.read_u8()?;
    let session_expiry_interval = if cursor.remaining() > 0 {
        cursor.read_session_expiry_property()?
    } else {
        None
    };
    Ok(MqttPacket::Disconnect {
        reason_code: Some(reason_code),
        session_expiry_interval,
    })
}

fn read_packet_id(cursor: &mut Cursor<'_>) -> Result<u16, ProtocolError> {
    let packet_id = cursor.read_u16()?;
    if packet_id == 0 {
        return Err(ProtocolError::MalformedPacket(
            "packet identifier must be non-zero",
        ));
    }
    Ok(packet_id)
}

pub fn encode_frame(command: u8, flags: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(1 + 4 + body.len());
    packet.push(command | flags);
    write_varint(body.len() as u32, &mut packet);
    packet.extend_from_slice(body);
    packet
}

pub fn encode_connack(
    protocol: ProtocolVersion,
    session_present: bool,
    reason_code: u8,
) -> Vec<u8> {
    encode_connack_with_options(
        protocol,
        session_present,
        reason_code,
        ConnackOptions::default(),
    )
}

#[derive(Debug, Clone, Copy)]
pub struct ConnackOptions<'a> {
    pub retain_available: bool,
    pub assigned_client_id: Option<&'a str>,
    pub server_keep_alive: Option<u16>,
    pub maximum_packet_size: u32,
}

impl Default for ConnackOptions<'_> {
    fn default() -> Self {
        Self {
            retain_available: true,
            assigned_client_id: None,
            server_keep_alive: None,
            maximum_packet_size: 2_000_000,
        }
    }
}

pub fn encode_connack_with_retain_available(
    protocol: ProtocolVersion,
    session_present: bool,
    reason_code: u8,
    retain_available: bool,
) -> Vec<u8> {
    encode_connack_with_options(
        protocol,
        session_present,
        reason_code,
        ConnackOptions {
            retain_available,
            ..ConnackOptions::default()
        },
    )
}

pub fn encode_connack_with_assigned_client_id(
    protocol: ProtocolVersion,
    session_present: bool,
    reason_code: u8,
    retain_available: bool,
    assigned_client_id: Option<&str>,
) -> Vec<u8> {
    encode_connack_with_options(
        protocol,
        session_present,
        reason_code,
        ConnackOptions {
            retain_available,
            assigned_client_id,
            ..ConnackOptions::default()
        },
    )
}

pub fn encode_connack_with_options(
    protocol: ProtocolVersion,
    session_present: bool,
    reason_code: u8,
    options: ConnackOptions<'_>,
) -> Vec<u8> {
    let mut body = vec![u8::from(session_present), reason_code];
    if protocol == ProtocolVersion::V5 {
        if reason_code == 0 {
            let mut properties = Vec::new();
            if let Some(keep_alive) = options.server_keep_alive {
                properties.push(PROP_SERVER_KEEP_ALIVE as u8);
                write_u16(keep_alive, &mut properties);
            }
            properties.push(PROP_TOPIC_ALIAS_MAXIMUM as u8);
            write_u16(10, &mut properties);
            if let Some(client_id) = options.assigned_client_id {
                properties.push(PROP_ASSIGNED_CLIENT_IDENTIFIER as u8);
                write_utf8(client_id, &mut properties);
            }
            if !options.retain_available {
                properties.push(PROP_RETAIN_AVAILABLE as u8);
                properties.push(0);
            }
            properties.push(PROP_MAXIMUM_PACKET_SIZE as u8);
            write_u32(options.maximum_packet_size, &mut properties);
            properties.push(PROP_RECEIVE_MAXIMUM as u8);
            write_u16(20, &mut properties);
            write_varint(properties.len() as u32, &mut body);
            body.extend_from_slice(&properties);
        } else {
            body.push(0);
        }
    }
    encode_frame(CMD_CONNACK, 0, &body)
}

pub fn encode_suback(protocol: ProtocolVersion, packet_id: u16, reason_codes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + reason_codes.len());
    write_u16(packet_id, &mut body);
    if protocol == ProtocolVersion::V5 {
        body.push(0);
    }
    body.extend_from_slice(reason_codes);
    encode_frame(CMD_SUBACK, 0, &body)
}

pub fn encode_unsuback(protocol: ProtocolVersion, packet_id: u16, count: usize) -> Vec<u8> {
    let mut body = Vec::new();
    write_u16(packet_id, &mut body);
    if protocol == ProtocolVersion::V5 {
        body.push(0);
        body.extend(std::iter::repeat(0).take(count));
    }
    encode_frame(CMD_UNSUBACK, 0, &body)
}

pub fn encode_publish(protocol: ProtocolVersion, publication: &Publication) -> Vec<u8> {
    let mut body = Vec::new();
    write_utf8(&publication.topic, &mut body);
    if publication.qos > 0 {
        write_u16(
            publication
                .packet_id
                .expect("QoS publish requires a packet identifier"),
            &mut body,
        );
    }
    if protocol == ProtocolVersion::V5 {
        let mut properties = Vec::new();
        if let Some(payload_format_indicator) = publication.payload_format_indicator {
            properties.push(PROP_PAYLOAD_FORMAT_INDICATOR as u8);
            properties.push(payload_format_indicator);
        }
        if let Some(response_topic) = &publication.response_topic {
            properties.push(PROP_RESPONSE_TOPIC as u8);
            write_utf8(response_topic, &mut properties);
        }
        if let Some(correlation_data) = &publication.correlation_data {
            properties.push(PROP_CORRELATION_DATA as u8);
            write_binary(correlation_data, &mut properties);
        }
        for identifier in &publication.subscription_identifiers {
            properties.push(PROP_SUBSCRIPTION_IDENTIFIER as u8);
            write_varint(*identifier, &mut properties);
        }
        write_varint(properties.len() as u32, &mut body);
        body.extend_from_slice(&properties);
    }
    body.extend_from_slice(&publication.payload);
    let flags = (if publication.dup { 0x08 } else { 0 })
        | ((publication.qos & 0x03) << 1)
        | u8::from(publication.retain);
    encode_frame(CMD_PUBLISH, flags, &body)
}

pub fn encode_puback(protocol: ProtocolVersion, packet_id: u16) -> Vec<u8> {
    encode_ack(CMD_PUBACK, 0, protocol, packet_id)
}

pub fn encode_puback_reason(protocol: ProtocolVersion, packet_id: u16, reason_code: u8) -> Vec<u8> {
    encode_ack_reason(CMD_PUBACK, 0, protocol, packet_id, reason_code)
}

pub fn encode_pubrec(protocol: ProtocolVersion, packet_id: u16) -> Vec<u8> {
    encode_ack(CMD_PUBREC, 0, protocol, packet_id)
}

pub fn encode_pubrel(_protocol: ProtocolVersion, packet_id: u16) -> Vec<u8> {
    let mut body = Vec::new();
    write_u16(packet_id, &mut body);
    encode_frame(CMD_PUBREL, 0x02, &body)
}

pub fn encode_pubcomp(protocol: ProtocolVersion, packet_id: u16) -> Vec<u8> {
    encode_ack(CMD_PUBCOMP, 0, protocol, packet_id)
}

fn encode_ack(command: u8, flags: u8, _protocol: ProtocolVersion, packet_id: u16) -> Vec<u8> {
    let mut body = Vec::new();
    write_u16(packet_id, &mut body);
    encode_frame(command, flags, &body)
}

fn encode_ack_reason(
    command: u8,
    flags: u8,
    protocol: ProtocolVersion,
    packet_id: u16,
    reason_code: u8,
) -> Vec<u8> {
    let mut body = Vec::new();
    write_u16(packet_id, &mut body);
    if protocol == ProtocolVersion::V5 {
        body.push(reason_code);
    }
    encode_frame(command, flags, &body)
}

pub fn encode_pingresp() -> Vec<u8> {
    encode_frame(CMD_PINGRESP, 0, &[])
}

pub fn encode_disconnect(protocol: ProtocolVersion, reason_code: u8) -> Vec<u8> {
    let body = if protocol == ProtocolVersion::V5 {
        vec![reason_code]
    } else {
        Vec::new()
    };
    encode_frame(CMD_DISCONNECT, 0, &body)
}

fn write_varint(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let mut encoded = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            encoded |= 128;
        }
        out.push(encoded);
        if value == 0 {
            break;
        }
    }
}

fn write_u16(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(value: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_utf8(value: &str, out: &mut Vec<u8>) {
    write_u16(value.len() as u16, out);
    out.extend_from_slice(value.as_bytes());
}

fn write_binary(value: &[u8], out: &mut Vec<u8>) {
    write_u16(value.len() as u16, out);
    out.extend_from_slice(value);
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

#[derive(Debug, Default)]
struct ConnectProperties {
    session_expiry_interval: Option<u32>,
    maximum_packet_size: Option<u32>,
}

#[derive(Debug, Default)]
struct PublishProperties {
    topic_alias: Option<u16>,
    payload_format_indicator: Option<u8>,
    response_topic: Option<String>,
    correlation_data: Option<Vec<u8>>,
    subscription_identifiers: Vec<u32>,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn read_remaining(&mut self) -> &'a [u8] {
        let result = &self.bytes[self.pos..];
        self.pos = self.bytes.len();
        result
    }

    fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        if self.remaining() < 1 {
            return Err(ProtocolError::MalformedPacket("unexpected end of packet"));
        }
        let value = self.bytes[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, ProtocolError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, ProtocolError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_utf8(&mut self) -> Result<String, ProtocolError> {
        let len = self.read_u16()? as usize;
        let bytes = self.read_bytes(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| ProtocolError::MalformedPacket("invalid utf-8 string"))
    }

    fn read_binary(&mut self) -> Result<Vec<u8>, ProtocolError> {
        let len = self.read_u16()? as usize;
        Ok(self.read_bytes(len)?.to_vec())
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], ProtocolError> {
        if self.remaining() < len {
            return Err(ProtocolError::MalformedPacket("unexpected end of packet"));
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.bytes[start..self.pos])
    }

    fn read_varint(&mut self) -> Result<u32, ProtocolError> {
        let mut multiplier = 1_u32;
        let mut value = 0_u32;
        for _ in 0..4 {
            let byte = self.read_u8()?;
            value += ((byte & 127) as u32) * multiplier;
            if (byte & 128) == 0 {
                return Ok(value);
            }
            multiplier = multiplier
                .checked_mul(128)
                .ok_or(ProtocolError::MalformedPacket("varint overflow"))?;
        }
        Err(ProtocolError::MalformedPacket("varint is too long"))
    }

    fn skip_properties(&mut self) -> Result<(), ProtocolError> {
        let len = self.read_varint()? as usize;
        self.read_bytes(len)?;
        Ok(())
    }

    fn read_connect_properties(&mut self) -> Result<ConnectProperties, ProtocolError> {
        let len = self.read_varint()? as usize;
        if self.remaining() < len {
            return Err(ProtocolError::MalformedPacket("truncated properties"));
        }
        let end = self.pos + len;
        let mut properties = ConnectProperties::default();
        while self.pos < end {
            let identifier = self.read_varint()?;
            match identifier {
                PROP_SESSION_EXPIRY_INTERVAL => {
                    properties.session_expiry_interval = Some(self.read_u32()?);
                }
                PROP_MAXIMUM_PACKET_SIZE => {
                    let value = self.read_u32()?;
                    if value == 0 {
                        return Err(ProtocolError::MalformedPacket("zero maximum packet size"));
                    }
                    properties.maximum_packet_size = Some(value);
                }
                _ => self.skip_property_value(identifier)?,
            }
        }
        if self.pos != end {
            return Err(ProtocolError::MalformedPacket("property length mismatch"));
        }
        Ok(properties)
    }

    fn read_session_expiry_property(&mut self) -> Result<Option<u32>, ProtocolError> {
        let len = self.read_varint()? as usize;
        if self.remaining() < len {
            return Err(ProtocolError::MalformedPacket("truncated properties"));
        }
        let end = self.pos + len;
        let mut session_expiry_interval = None;
        while self.pos < end {
            let identifier = self.read_varint()?;
            if identifier == PROP_SESSION_EXPIRY_INTERVAL {
                session_expiry_interval = Some(self.read_u32()?);
            } else {
                self.skip_property_value(identifier)?;
            }
        }
        if self.pos != end {
            return Err(ProtocolError::MalformedPacket("property length mismatch"));
        }
        Ok(session_expiry_interval)
    }

    fn read_subscribe_properties(&mut self) -> Result<Option<u32>, ProtocolError> {
        let len = self.read_varint()? as usize;
        if self.remaining() < len {
            return Err(ProtocolError::MalformedPacket("truncated properties"));
        }
        let end = self.pos + len;
        let mut subscription_identifier = None;
        while self.pos < end {
            let identifier = self.read_varint()?;
            match identifier {
                PROP_SUBSCRIPTION_IDENTIFIER => {
                    let value = self.read_varint()?;
                    if value == 0 {
                        return Err(ProtocolError::MalformedPacket(
                            "zero subscription identifier",
                        ));
                    }
                    if subscription_identifier.replace(value).is_some() {
                        return Err(ProtocolError::MalformedPacket(
                            "duplicate subscription identifier",
                        ));
                    }
                }
                _ => self.skip_property_value(identifier)?,
            }
        }
        if self.pos != end {
            return Err(ProtocolError::MalformedPacket("property length mismatch"));
        }
        Ok(subscription_identifier)
    }

    fn read_publish_properties(&mut self) -> Result<PublishProperties, ProtocolError> {
        let len = self.read_varint()? as usize;
        if self.remaining() < len {
            return Err(ProtocolError::MalformedPacket("truncated properties"));
        }
        let end = self.pos + len;
        let mut properties = PublishProperties::default();
        while self.pos < end {
            let identifier = self.read_varint()?;
            match identifier {
                PROP_PAYLOAD_FORMAT_INDICATOR => {
                    properties.payload_format_indicator = Some(self.read_u8()?);
                }
                PROP_TOPIC_ALIAS => {
                    properties.topic_alias = Some(self.read_u16()?);
                }
                PROP_RESPONSE_TOPIC => {
                    properties.response_topic = Some(self.read_utf8()?);
                }
                PROP_CORRELATION_DATA => {
                    properties.correlation_data = Some(self.read_binary()?);
                }
                PROP_SUBSCRIPTION_IDENTIFIER => {
                    let value = self.read_varint()?;
                    if value == 0 {
                        return Err(ProtocolError::MalformedPacket(
                            "zero subscription identifier",
                        ));
                    }
                    properties.subscription_identifiers.push(value);
                }
                _ => self.skip_property_value(identifier)?,
            }
        }
        if self.pos != end {
            return Err(ProtocolError::MalformedPacket("property length mismatch"));
        }
        Ok(properties)
    }

    fn skip_property_value(&mut self, identifier: u32) -> Result<(), ProtocolError> {
        match identifier {
            PROP_PAYLOAD_FORMAT_INDICATOR
            | PROP_REQUEST_PROBLEM_INFORMATION
            | PROP_REQUEST_RESPONSE_INFORMATION
            | PROP_MAXIMUM_QOS
            | PROP_RETAIN_AVAILABLE
            | PROP_WILDCARD_SUB_AVAILABLE
            | PROP_SUBSCRIPTION_ID_AVAILABLE
            | PROP_SHARED_SUB_AVAILABLE => {
                self.read_u8()?;
            }
            PROP_SERVER_KEEP_ALIVE | PROP_RECEIVE_MAXIMUM | PROP_TOPIC_ALIAS_MAXIMUM => {
                self.read_u16()?;
            }
            PROP_TOPIC_ALIAS => {
                self.read_u16()?;
            }
            PROP_MESSAGE_EXPIRY_INTERVAL
            | PROP_SESSION_EXPIRY_INTERVAL
            | PROP_WILL_DELAY_INTERVAL
            | PROP_MAXIMUM_PACKET_SIZE => {
                self.read_u32()?;
            }
            PROP_SUBSCRIPTION_IDENTIFIER => {
                self.read_varint()?;
            }
            PROP_CONTENT_TYPE
            | PROP_RESPONSE_TOPIC
            | PROP_ASSIGNED_CLIENT_IDENTIFIER
            | PROP_AUTHENTICATION_METHOD
            | PROP_RESPONSE_INFORMATION
            | PROP_SERVER_REFERENCE
            | PROP_REASON_STRING => {
                let skip = self.read_u16()? as usize;
                self.read_bytes(skip)?;
            }
            PROP_CORRELATION_DATA | PROP_AUTHENTICATION_DATA => {
                let skip = self.read_u16()? as usize;
                self.read_bytes(skip)?;
            }
            PROP_USER_PROPERTY => {
                let name_len = self.read_u16()? as usize;
                self.read_bytes(name_len)?;
                let value_len = self.read_u16()? as usize;
                self.read_bytes(value_len)?;
            }
            _ => return Err(ProtocolError::MalformedPacket("unknown property")),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_remaining_length_boundaries() {
        assert_eq!(&encode_frame(CMD_PINGREQ, 0, &[]), &[0xC0, 0x00]);
        assert_eq!(
            &encode_frame(CMD_PUBLISH, 0, &[0; 128])[0..3],
            &[0x30, 0x80, 0x01]
        );
    }

    #[test]
    fn encodes_mqtt_v5_connack_properties() {
        assert_eq!(
            encode_connack(ProtocolVersion::V5, false, 0),
            vec![0x20, 14, 0, 0, 11, 0x22, 0, 10, 0x27, 0, 0x1E, 0x84, 0x80, 0x21, 0, 20,]
        );
    }

    #[test]
    fn encodes_mqtt_v5_connack_retain_unavailable() {
        assert_eq!(
            encode_connack_with_retain_available(ProtocolVersion::V5, false, 0, false),
            vec![0x20, 16, 0, 0, 13, 0x22, 0, 10, 0x25, 0, 0x27, 0, 0x1E, 0x84, 0x80, 0x21, 0, 20,]
        );
    }

    #[test]
    fn encodes_mqtt_v5_assigned_client_identifier() {
        assert_eq!(
            encode_connack_with_assigned_client_id(
                ProtocolVersion::V5,
                false,
                0,
                true,
                Some("auto-test"),
            ),
            vec![
                0x20, 26, 0, 0, 23, 0x22, 0, 10, 0x12, 0, 9, b'a', b'u', b't', b'o', b'-', b't',
                b'e', b's', b't', 0x27, 0, 0x1E, 0x84, 0x80, 0x21, 0, 20,
            ]
        );
    }

    #[test]
    fn encodes_mqtt_v5_configured_maximum_packet_size() {
        assert_eq!(
            encode_connack_with_options(
                ProtocolVersion::V5,
                false,
                0,
                ConnackOptions {
                    maximum_packet_size: 50,
                    ..ConnackOptions::default()
                },
            ),
            vec![0x20, 14, 0, 0, 11, 0x22, 0, 10, 0x27, 0, 0, 0, 50, 0x21, 0, 20,]
        );
    }

    #[test]
    fn encodes_mqtt_v5_server_keep_alive() {
        assert_eq!(
            encode_connack_with_options(
                ProtocolVersion::V5,
                false,
                0,
                ConnackOptions {
                    server_keep_alive: Some(60),
                    ..ConnackOptions::default()
                },
            ),
            vec![
                0x20, 17, 0, 0, 14, 0x13, 0, 60, 0x22, 0, 10, 0x27, 0, 0x1E, 0x84, 0x80, 0x21, 0,
                20,
            ]
        );
    }

    #[test]
    fn encodes_mqtt_v5_error_connack_without_properties() {
        assert_eq!(
            encode_connack(ProtocolVersion::V5, false, 0x87),
            vec![0x20, 3, 0, 0x87, 0]
        );
    }

    #[test]
    fn decodes_mqtt_v5_connect() {
        let body = [
            0, 4, b'M', b'Q', b'T', b'T', 5, 2, 0, 60, 0, 0, 6, b'c', b'l', b'i', b'e', b'n', b't',
        ];
        let packet = decode_frame(
            &Frame {
                command: CMD_CONNECT,
                flags: 0,
                body: body.to_vec(),
            },
            None,
        )
        .unwrap();
        match packet {
            MqttPacket::Connect {
                protocol,
                client_id,
                clean_start,
                session_expiry_interval,
                ..
            } => {
                assert_eq!(protocol, ProtocolVersion::V5);
                assert_eq!(client_id, "client");
                assert!(clean_start);
                assert_eq!(session_expiry_interval, None);
            }
            other => panic!("unexpected packet: {other:?}"),
        }
    }

    #[test]
    fn decodes_session_expiry_properties() {
        let body = [
            0, 4, b'M', b'Q', b'T', b'T', 5, 0, 0, 60, 5, 0x11, 0, 0, 0, 60, 0, 6, b'c', b'l',
            b'i', b'e', b'n', b't',
        ];
        let packet = decode_frame(
            &Frame {
                command: CMD_CONNECT,
                flags: 0,
                body: body.to_vec(),
            },
            None,
        )
        .unwrap();
        match packet {
            MqttPacket::Connect {
                session_expiry_interval,
                ..
            } => {
                assert_eq!(session_expiry_interval, Some(60));
            }
            other => panic!("unexpected packet: {other:?}"),
        }

        let disconnect = decode_frame(
            &Frame {
                command: CMD_DISCONNECT,
                flags: 0,
                body: vec![0, 5, 0x11, 0, 0, 0, 3],
            },
            Some(ProtocolVersion::V5),
        )
        .unwrap();
        match disconnect {
            MqttPacket::Disconnect {
                reason_code,
                session_expiry_interval,
            } => {
                assert_eq!(reason_code, Some(0));
                assert_eq!(session_expiry_interval, Some(3));
            }
            other => panic!("unexpected packet: {other:?}"),
        }
    }

    #[test]
    fn decodes_qos1_publish_packet_identifier() {
        let packet = decode_frame(
            &Frame {
                command: CMD_PUBLISH,
                flags: 0x02,
                body: vec![0, 1, b'a', 0x12, 0x34, b'p'],
            },
            Some(ProtocolVersion::V311),
        )
        .unwrap();
        match packet {
            MqttPacket::Publish(publication) => {
                assert_eq!(publication.qos, 1);
                assert_eq!(publication.packet_id, Some(0x1234));
                assert_eq!(publication.payload, b"p");
            }
            other => panic!("unexpected packet: {other:?}"),
        }
    }

    #[test]
    fn rejects_zero_packet_identifier() {
        let publish = decode_frame(
            &Frame {
                command: CMD_PUBLISH,
                flags: 0x02,
                body: vec![0, 1, b'a', 0, 0],
            },
            Some(ProtocolVersion::V311),
        );
        assert!(matches!(publish, Err(ProtocolError::MalformedPacket(_))));

        let puback = decode_frame(
            &Frame {
                command: CMD_PUBACK,
                flags: 0,
                body: vec![0, 0],
            },
            Some(ProtocolVersion::V311),
        );
        assert!(matches!(puback, Err(ProtocolError::MalformedPacket(_))));
    }

    #[test]
    fn encodes_qos1_publish_packet_identifier() {
        let encoded = encode_publish(
            ProtocolVersion::V311,
            &Publication {
                topic: "a".into(),
                payload: b"p".to_vec(),
                qos: 1,
                retain: false,
                packet_id: Some(0x1234),
                dup: true,
                topic_alias: None,
                payload_format_indicator: None,
                response_topic: None,
                correlation_data: None,
                subscription_identifiers: Vec::new(),
            },
        );
        assert_eq!(encoded, vec![0x3A, 6, 0, 1, b'a', 0x12, 0x34, b'p']);
    }

    #[test]
    fn decodes_mqtt_v5_connect_maximum_packet_size() {
        let body = [
            0, 4, b'M', b'Q', b'T', b'T', 5, 2, 0, 60, 5, 0x27, 0, 0, 0, 40, 0, 6, b'c', b'l',
            b'i', b'e', b'n', b't',
        ];
        let packet = decode_frame(
            &Frame {
                command: CMD_CONNECT,
                flags: 0,
                body: body.to_vec(),
            },
            None,
        )
        .unwrap();

        match packet {
            MqttPacket::Connect {
                maximum_packet_size,
                ..
            } => assert_eq!(maximum_packet_size, Some(40)),
            other => panic!("unexpected packet: {other:?}"),
        }
    }

    #[test]
    fn decodes_mqtt_v5_subscription_identifier() {
        let packet = decode_frame(
            &Frame {
                command: CMD_SUBSCRIBE,
                flags: 2,
                body: vec![0, 7, 2, 0x0B, 42, 0, 3, b'a', b'/', b'#', 1],
            },
            Some(ProtocolVersion::V5),
        )
        .unwrap();

        match packet {
            MqttPacket::Subscribe { packet_id, filters } => {
                assert_eq!(packet_id, 7);
                assert_eq!(filters.len(), 1);
                assert_eq!(filters[0].filter, "a/#");
                assert_eq!(filters[0].qos, 1);
                assert_eq!(filters[0].identifier, Some(42));
            }
            other => panic!("unexpected packet: {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_subscribe_options() {
        for options in [0x03, 0x30, 0x80] {
            let packet = decode_frame(
                &Frame {
                    command: CMD_SUBSCRIBE,
                    flags: 2,
                    body: vec![0, 7, 0, 0, 1, b'a', options],
                },
                Some(ProtocolVersion::V5),
            );
            assert!(matches!(packet, Err(ProtocolError::MalformedPacket(_))));
        }
    }

    #[test]
    fn encodes_mqtt_v5_publish_subscription_identifier() {
        let encoded = encode_publish(
            ProtocolVersion::V5,
            &Publication {
                topic: "a".into(),
                payload: b"p".to_vec(),
                qos: 0,
                retain: false,
                packet_id: None,
                dup: false,
                topic_alias: None,
                payload_format_indicator: None,
                response_topic: None,
                correlation_data: None,
                subscription_identifiers: vec![321],
            },
        );
        assert_eq!(
            encoded,
            vec![0x30, 8, 0, 1, b'a', 3, 0x0B, 0xC1, 0x02, b'p']
        );
    }

    #[test]
    fn encodes_pubrel_with_required_flags() {
        assert_eq!(
            encode_pubrel(ProtocolVersion::V311, 0x1234),
            vec![0x62, 2, 0x12, 0x34]
        );
        assert_eq!(
            encode_pubrel(ProtocolVersion::V5, 0x1234),
            vec![0x62, 2, 0x12, 0x34]
        );
    }

    #[test]
    fn encodes_mqtt5_puback_reason_code() {
        assert_eq!(
            encode_puback_reason(ProtocolVersion::V5, 0x1234, 0x10),
            vec![0x40, 0x03, 0x12, 0x34, 0x10]
        );
        assert_eq!(
            encode_puback_reason(ProtocolVersion::V311, 0x1234, 0x10),
            vec![0x40, 0x02, 0x12, 0x34]
        );
    }

    #[test]
    fn encodes_mqtt_v5_publish_response_properties() {
        let encoded = encode_publish(
            ProtocolVersion::V5,
            &Publication {
                topic: "normal/topic".into(),
                payload: b"2".to_vec(),
                qos: 0,
                retain: false,
                packet_id: None,
                dup: false,
                topic_alias: None,
                payload_format_indicator: Some(1),
                response_topic: Some("response/topic".to_owned()),
                correlation_data: Some(b"corr".to_vec()),
                subscription_identifiers: Vec::new(),
            },
        );
        assert!(encoded
            .windows(2)
            .any(|window| { window == [PROP_PAYLOAD_FORMAT_INDICATOR as u8, 1] }));
        assert!(encoded.windows(17).any(|window| {
            window
                == [
                    PROP_RESPONSE_TOPIC as u8,
                    0,
                    14,
                    b'r',
                    b'e',
                    b's',
                    b'p',
                    b'o',
                    b'n',
                    b's',
                    b'e',
                    b'/',
                    b't',
                    b'o',
                    b'p',
                    b'i',
                    b'c',
                ]
        }));
        assert!(encoded.windows(7).any(|window| {
            window == [PROP_CORRELATION_DATA as u8, 0, 4, b'c', b'o', b'r', b'r']
        }));
    }

    #[test]
    fn decodes_topic_alias_property() {
        let body = [
            0, 1, b'a', 3, 0x23, 0, 7, b'p', b'a', b'y', b'l', b'o', b'a', b'd',
        ];
        let packet = decode_frame(
            &Frame {
                command: CMD_PUBLISH,
                flags: 0,
                body: body.to_vec(),
            },
            Some(ProtocolVersion::V5),
        )
        .unwrap();
        match packet {
            MqttPacket::Publish(publication) => {
                assert_eq!(publication.topic, "a");
                assert_eq!(publication.topic_alias, Some(7));
                assert!(publication.subscription_identifiers.is_empty());
                assert_eq!(publication.payload, b"payload");
            }
            other => panic!("unexpected packet: {other:?}"),
        }
    }
}
