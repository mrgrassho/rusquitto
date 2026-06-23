use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use rusquitto_protocol::topic;
use rusquitto_protocol::{Publication, SubscriptionRequest, Will};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub filter: String,
    pub qos: u8,
    pub no_local: bool,
    pub retain_as_published: bool,
    pub retain_handling: u8,
    pub identifier: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qos2OutboundState {
    WaitingPubRec,
    WaitingPubComp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qos2Outbound {
    pub publication: Publication,
    pub state: Qos2OutboundState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSession {
    pub client_id: String,
    pub subscriptions: HashMap<String, Subscription>,
    pub will: Option<Will>,
    pub queued: Vec<Publication>,
    pub inflight_qos1: BTreeMap<u16, Publication>,
    pub inflight_qos2: BTreeMap<u16, Qos2Outbound>,
    pub inbound_qos2: BTreeMap<u16, Publication>,
    pub session_expiry_interval: u32,
    pub disconnected_at: Option<Instant>,
    pub online: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub client_id: String,
    pub publication: Publication,
}

#[derive(Debug, Clone, Default)]
pub struct BrokerState {
    clients: HashMap<String, ClientSession>,
    retained: HashMap<String, Publication>,
    next_outgoing_mid: u16,
}

impl BrokerState {
    pub fn new() -> Self {
        Self {
            next_outgoing_mid: 1,
            ..Self::default()
        }
    }

    pub fn connect(
        &mut self,
        client_id: String,
        clean_start: bool,
        will: Option<Will>,
        session_expiry_interval: u32,
    ) -> ConnectResult {
        self.expire_sessions_at(Instant::now());
        let session_present = !clean_start && self.clients.contains_key(&client_id);
        if clean_start || !self.clients.contains_key(&client_id) {
            self.clients.insert(
                client_id.clone(),
                ClientSession {
                    client_id: client_id.clone(),
                    subscriptions: HashMap::new(),
                    will,
                    queued: Vec::new(),
                    inflight_qos1: BTreeMap::new(),
                    inflight_qos2: BTreeMap::new(),
                    inbound_qos2: BTreeMap::new(),
                    session_expiry_interval,
                    disconnected_at: None,
                    online: true,
                },
            );
        } else if let Some(session) = self.clients.get_mut(&client_id) {
            session.will = will;
            session.session_expiry_interval = session_expiry_interval;
            session.disconnected_at = None;
            session.online = true;
        }

        let (queued, pubrels) = self
            .clients
            .get_mut(&client_id)
            .map(|session| {
                let mut pending: Vec<_> = session
                    .inflight_qos1
                    .values()
                    .cloned()
                    .map(|mut publication| {
                        publication.dup = true;
                        publication
                    })
                    .collect();

                pending.extend(session.inflight_qos2.values().filter_map(|outbound| {
                    if outbound.state == Qos2OutboundState::WaitingPubRec {
                        let mut publication = outbound.publication.clone();
                        publication.dup = true;
                        Some(publication)
                    } else {
                        None
                    }
                }));

                let pubrels = session
                    .inflight_qos2
                    .iter()
                    .filter_map(|(packet_id, outbound)| {
                        (outbound.state == Qos2OutboundState::WaitingPubComp).then_some(*packet_id)
                    })
                    .collect();

                let queued = std::mem::take(&mut session.queued);
                for publication in &queued {
                    if let Some(packet_id) = publication.packet_id {
                        match publication.qos {
                            1 => {
                                session.inflight_qos1.insert(packet_id, publication.clone());
                            }
                            2 => {
                                session.inflight_qos2.insert(
                                    packet_id,
                                    Qos2Outbound {
                                        publication: publication.clone(),
                                        state: Qos2OutboundState::WaitingPubRec,
                                    },
                                );
                            }
                            _ => {}
                        }
                    }
                }
                pending.extend(queued);
                (pending, pubrels)
            })
            .unwrap_or_default();

        ConnectResult {
            session_present,
            queued,
            pubrels,
        }
    }

    pub fn disconnect(
        &mut self,
        client_id: &str,
        graceful: bool,
        session_expiry_interval: Option<u32>,
    ) -> Vec<Delivery> {
        let mut remove_session = false;
        let will = self.clients.get_mut(client_id).and_then(|session| {
            session.online = false;
            if let Some(session_expiry_interval) = session_expiry_interval {
                session.session_expiry_interval = session_expiry_interval;
            }
            session.disconnected_at = Some(Instant::now());
            remove_session = session.session_expiry_interval == 0;
            if graceful {
                session.will = None;
                None
            } else {
                session.will.take()
            }
        });

        if let Some(will) = will {
            let publication = Publication {
                topic: will.topic,
                payload: will.payload,
                qos: will.qos,
                retain: will.retain,
                packet_id: None,
                dup: false,
                topic_alias: None,
                subscription_identifiers: Vec::new(),
            };
            let deliveries = self.publish(client_id, publication).deliveries;
            if remove_session {
                self.clients.remove(client_id);
            }
            deliveries
        } else {
            if remove_session {
                self.clients.remove(client_id);
            }
            Vec::new()
        }
    }

    pub fn subscribe(
        &mut self,
        client_id: &str,
        filters: Vec<SubscriptionRequest>,
    ) -> SubscribeResult {
        let mut reason_codes = Vec::with_capacity(filters.len());
        let mut retained = Vec::new();
        let mut replay_filters = Vec::new();

        let Some(session) = self.clients.get_mut(client_id) else {
            return SubscribeResult {
                reason_codes,
                retained,
            };
        };

        for request in filters {
            let valid_identifier = request.identifier.map_or(true, |identifier| identifier > 0);
            let valid = topic::check_subscribe_topic(&request.filter).is_ok()
                && request.qos <= 2
                && request.retain_handling <= 2
                && valid_identifier;
            if !valid {
                reason_codes.push(0x80);
                continue;
            }

            let existed = session.subscriptions.contains_key(&request.filter);
            let subscription = Subscription {
                filter: request.filter.clone(),
                qos: request.qos,
                no_local: request.no_local,
                retain_as_published: request.retain_as_published,
                retain_handling: request.retain_handling,
                identifier: request.identifier,
            };
            session
                .subscriptions
                .insert(request.filter.clone(), subscription.clone());
            reason_codes.push(request.qos);

            let send_retained = match request.retain_handling {
                0 => true,
                1 => !existed,
                _ => false,
            };
            if send_retained {
                replay_filters.push(subscription);
            }
        }

        for subscription in replay_filters {
            let matching: Vec<Publication> = self
                .retained
                .values()
                .filter(|publication| topic::matches(&subscription.filter, &publication.topic))
                .cloned()
                .collect();

            for publication in matching {
                let mut retained_publication = publication.clone();
                retained_publication.qos = retained_publication.qos.min(subscription.qos);
                retained_publication.retain =
                    !subscription.retain_as_published || publication.retain;
                retained_publication.subscription_identifiers.clear();
                if let Some(identifier) = subscription.identifier {
                    retained_publication
                        .subscription_identifiers
                        .push(identifier);
                }
                if retained_publication.qos > 0 {
                    retained_publication.packet_id = Some(self.next_packet_id());
                }
                self.track_outgoing(client_id, &retained_publication);
                retained.push(Delivery {
                    client_id: client_id.to_owned(),
                    publication: retained_publication,
                });
            }
        }

        SubscribeResult {
            reason_codes,
            retained,
        }
    }

    pub fn unsubscribe(&mut self, client_id: &str, filters: &[String]) {
        if let Some(session) = self.clients.get_mut(client_id) {
            for filter in filters {
                session.subscriptions.remove(filter);
            }
        }
    }

    pub fn puback(&mut self, client_id: &str, packet_id: u16) -> bool {
        self.clients
            .get_mut(client_id)
            .and_then(|session| session.inflight_qos1.remove(&packet_id))
            .is_some()
    }

    pub fn has_inflight_qos1(&self, client_id: &str, packet_id: u16) -> bool {
        self.clients
            .get(client_id)
            .is_some_and(|session| session.inflight_qos1.contains_key(&packet_id))
    }

    pub fn receive_qos2_publish(
        &mut self,
        client_id: &str,
        publication: Publication,
    ) -> Qos2ReceiveResult {
        let Some(packet_id) = publication.packet_id else {
            return Qos2ReceiveResult {
                accepted: false,
                duplicate: false,
            };
        };
        if publication.qos != 2 || !Self::valid_publication(&publication) {
            return Qos2ReceiveResult {
                accepted: false,
                duplicate: false,
            };
        }

        let Some(session) = self.clients.get_mut(client_id) else {
            return Qos2ReceiveResult {
                accepted: false,
                duplicate: false,
            };
        };
        if let std::collections::btree_map::Entry::Vacant(entry) =
            session.inbound_qos2.entry(packet_id)
        {
            entry.insert(publication);
            Qos2ReceiveResult {
                accepted: true,
                duplicate: false,
            }
        } else {
            Qos2ReceiveResult {
                accepted: true,
                duplicate: true,
            }
        }
    }

    pub fn pubrel(&mut self, client_id: &str, packet_id: u16) -> Option<PublishResult> {
        let publication = self
            .clients
            .get_mut(client_id)
            .and_then(|session| session.inbound_qos2.remove(&packet_id));
        publication.map(|publication| self.publish(client_id, publication))
    }

    pub fn pubrec(&mut self, client_id: &str, packet_id: u16) -> bool {
        let Some(outbound) = self
            .clients
            .get_mut(client_id)
            .and_then(|session| session.inflight_qos2.get_mut(&packet_id))
        else {
            return false;
        };
        outbound.state = Qos2OutboundState::WaitingPubComp;
        true
    }

    pub fn pubcomp(&mut self, client_id: &str, packet_id: u16) -> bool {
        self.clients
            .get_mut(client_id)
            .and_then(|session| session.inflight_qos2.remove(&packet_id))
            .is_some()
    }

    pub fn has_inflight_qos2(&self, client_id: &str, packet_id: u16) -> bool {
        self.clients
            .get(client_id)
            .is_some_and(|session| session.inflight_qos2.contains_key(&packet_id))
    }

    pub fn publish(
        &mut self,
        source_client_id: &str,
        mut publication: Publication,
    ) -> PublishResult {
        if !Self::valid_publication(&publication) {
            return PublishResult {
                accepted: false,
                deliveries: Vec::new(),
            };
        }
        publication.subscription_identifiers.clear();

        if publication.retain {
            if publication.payload.is_empty() {
                self.retained.remove(&publication.topic);
            } else {
                let mut retained = publication.clone();
                retained.packet_id = None;
                self.retained.insert(publication.topic.clone(), retained);
            }
        }

        let mut deliveries = Vec::new();
        let mut delivery_specs = Vec::new();
        for (client_id, session) in &self.clients {
            for subscription in session.subscriptions.values() {
                if subscription.no_local && client_id == source_client_id {
                    continue;
                }
                if topic::matches(&subscription.filter, &publication.topic) {
                    delivery_specs.push((
                        client_id.clone(),
                        subscription.qos.min(publication.qos),
                        subscription.retain_as_published,
                        subscription.identifier,
                        session.online,
                    ));
                    break;
                }
            }
        }

        for (client_id, qos, retain_as_published, identifier, online) in delivery_specs {
            publication.qos = qos;
            let mut outgoing = publication.clone();
            outgoing.retain = retain_as_published && outgoing.retain;
            if let Some(identifier) = identifier {
                outgoing.subscription_identifiers.push(identifier);
            }
            outgoing.packet_id = (outgoing.qos > 0).then(|| self.next_packet_id());
            if online {
                self.track_outgoing(&client_id, &outgoing);
                deliveries.push(Delivery {
                    client_id,
                    publication: outgoing,
                });
            } else if outgoing.qos > 0 {
                if let Some(session) = self.clients.get_mut(&client_id) {
                    session.queued.push(outgoing);
                }
            }
        }

        PublishResult {
            accepted: true,
            deliveries,
        }
    }

    fn valid_publication(publication: &Publication) -> bool {
        topic::check_publish_topic(&publication.topic).is_ok() && publication.qos <= 2
    }

    fn track_outgoing(&mut self, client_id: &str, publication: &Publication) {
        let Some(packet_id) = publication.packet_id else {
            return;
        };
        let Some(session) = self.clients.get_mut(client_id) else {
            return;
        };
        match publication.qos {
            1 => {
                session.inflight_qos1.insert(packet_id, publication.clone());
            }
            2 => {
                session.inflight_qos2.insert(
                    packet_id,
                    Qos2Outbound {
                        publication: publication.clone(),
                        state: Qos2OutboundState::WaitingPubRec,
                    },
                );
            }
            _ => {}
        }
    }

    fn expire_sessions_at(&mut self, now: Instant) {
        self.clients.retain(|_, session| {
            if session.online {
                return true;
            }
            if session.session_expiry_interval == u32::MAX {
                return true;
            }
            let Some(disconnected_at) = session.disconnected_at else {
                return true;
            };
            now.duration_since(disconnected_at)
                < Duration::from_secs(u64::from(session.session_expiry_interval))
        });
    }

    fn next_packet_id(&mut self) -> u16 {
        let id = self.next_outgoing_mid;
        self.next_outgoing_mid = if self.next_outgoing_mid == u16::MAX {
            1
        } else {
            self.next_outgoing_mid + 1
        };
        id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectResult {
    pub session_present: bool,
    pub queued: Vec<Publication>,
    pub pubrels: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeResult {
    pub reason_codes: Vec<u8>,
    pub retained: Vec<Delivery>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishResult {
    pub accepted: bool,
    pub deliveries: Vec<Delivery>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qos2ReceiveResult {
    pub accepted: bool,
    pub duplicate: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publication(topic: &str, retain: bool) -> Publication {
        Publication {
            topic: topic.to_owned(),
            payload: b"payload".to_vec(),
            qos: 0,
            retain,
            packet_id: None,
            dup: false,
            topic_alias: None,
            subscription_identifiers: Vec::new(),
        }
    }

    #[test]
    fn routes_matching_subscriptions() {
        let mut broker = BrokerState::new();
        broker.connect("sub".into(), true, None, 0);
        broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "a/+/c".into(),
                qos: 0,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );
        let result = broker.publish("pub", publication("a/b/c", false));
        assert!(result.accepted);
        assert_eq!(result.deliveries.len(), 1);
        assert_eq!(result.deliveries[0].client_id, "sub");
    }

    #[test]
    fn attaches_subscription_identifier_to_live_deliveries() {
        let mut broker = BrokerState::new();
        broker.connect("sub".into(), true, None, 0);
        broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "identified/#".into(),
                qos: 0,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: Some(42),
            }],
        );

        let mut inbound = publication("identified/topic", false);
        inbound.subscription_identifiers.push(99);
        let result = broker.publish("pub", inbound);

        assert!(result.accepted);
        assert_eq!(result.deliveries.len(), 1);
        assert_eq!(
            result.deliveries[0].publication.subscription_identifiers,
            vec![42]
        );
    }

    #[test]
    fn retains_and_replays_messages() {
        let mut broker = BrokerState::new();
        broker.connect("pub".into(), true, None, 0);
        broker.publish("pub", publication("retain/topic", true));
        broker.connect("sub".into(), true, None, 0);
        let result = broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "retain/#".into(),
                qos: 0,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );
        assert_eq!(result.reason_codes, vec![0]);
        assert_eq!(result.retained.len(), 1);
        assert!(result.retained[0].publication.retain);
    }

    #[test]
    fn attaches_subscription_identifier_to_retained_replays() {
        let mut broker = BrokerState::new();
        broker.connect("pub".into(), true, None, 0);
        broker.publish("pub", publication("retain/identified", true));
        broker.connect("sub".into(), true, None, 0);

        let result = broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "retain/#".into(),
                qos: 0,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: Some(77),
            }],
        );

        assert_eq!(result.retained.len(), 1);
        assert_eq!(
            result.retained[0].publication.subscription_identifiers,
            vec![77]
        );
    }

    #[test]
    fn publishes_will_on_ungraceful_disconnect() {
        let mut broker = BrokerState::new();
        broker.connect("sub".into(), true, None, 0);
        broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "will/topic".into(),
                qos: 0,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );
        broker.connect(
            "will".into(),
            true,
            Some(Will {
                topic: "will/topic".into(),
                payload: b"gone".to_vec(),
                qos: 0,
                retain: false,
            }),
            0,
        );
        let deliveries = broker.disconnect("will", false, None);
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].publication.payload, b"gone");
    }

    #[test]
    fn tracks_qos1_deliveries_until_puback() {
        let mut broker = BrokerState::new();
        broker.connect("sub".into(), false, None, 60);
        broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "online/qos1".into(),
                qos: 1,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );

        let mut outgoing = publication("online/qos1", false);
        outgoing.qos = 1;
        let publish_result = broker.publish("pub", outgoing);
        assert_eq!(publish_result.deliveries.len(), 1);
        let packet_id = publish_result.deliveries[0].publication.packet_id.unwrap();
        assert!(broker.has_inflight_qos1("sub", packet_id));

        assert!(broker.puback("sub", packet_id));
        assert!(!broker.has_inflight_qos1("sub", packet_id));
        assert!(!broker.puback("sub", packet_id));
    }

    #[test]
    fn tracks_qos1_retained_replays_until_puback() {
        let mut broker = BrokerState::new();
        let mut retained = publication("retained/qos1", true);
        retained.qos = 1;
        broker.publish("pub", retained);
        broker.connect("sub".into(), false, None, 60);

        let result = broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "retained/#".into(),
                qos: 1,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );

        assert_eq!(result.retained.len(), 1);
        let packet_id = result.retained[0].publication.packet_id.unwrap();
        assert!(broker.has_inflight_qos1("sub", packet_id));
        assert!(broker.puback("sub", packet_id));
    }

    #[test]
    fn replays_unacked_qos1_with_dup_on_reconnect() {
        let mut broker = BrokerState::new();
        broker.connect("sub".into(), false, None, 60);
        broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "replay/qos1".into(),
                qos: 1,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );

        let mut outgoing = publication("replay/qos1", false);
        outgoing.qos = 1;
        let publish_result = broker.publish("pub", outgoing);
        let packet_id = publish_result.deliveries[0].publication.packet_id.unwrap();
        broker.disconnect("sub", true, None);

        let reconnect = broker.connect("sub".into(), false, None, 60);
        assert!(reconnect.session_present);
        assert_eq!(reconnect.queued.len(), 1);
        assert_eq!(reconnect.queued[0].packet_id, Some(packet_id));
        assert!(reconnect.queued[0].dup);
        assert!(broker.has_inflight_qos1("sub", packet_id));
    }

    #[test]
    fn tracks_qos2_deliveries_until_pubrec_pubcomp() {
        let mut broker = BrokerState::new();
        broker.connect("sub".into(), false, None, 60);
        broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "online/qos2".into(),
                qos: 2,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );

        let mut outgoing = publication("online/qos2", false);
        outgoing.qos = 2;
        let publish_result = broker.publish("pub", outgoing);
        assert_eq!(publish_result.deliveries.len(), 1);
        let packet_id = publish_result.deliveries[0].publication.packet_id.unwrap();
        assert!(broker.has_inflight_qos2("sub", packet_id));
        assert_eq!(
            broker.clients["sub"].inflight_qos2[&packet_id].state,
            Qos2OutboundState::WaitingPubRec
        );

        assert!(broker.pubrec("sub", packet_id));
        assert_eq!(
            broker.clients["sub"].inflight_qos2[&packet_id].state,
            Qos2OutboundState::WaitingPubComp
        );
        assert!(broker.pubrec("sub", packet_id));
        assert!(broker.pubcomp("sub", packet_id));
        assert!(!broker.has_inflight_qos2("sub", packet_id));
        assert!(!broker.pubcomp("sub", packet_id));
    }

    #[test]
    fn holds_inbound_qos2_until_pubrel() {
        let mut broker = BrokerState::new();
        broker.connect("sub".into(), true, None, 0);
        broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "inbound/qos2".into(),
                qos: 0,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );
        broker.connect("pub".into(), true, None, 0);

        let mut inbound = publication("inbound/qos2", false);
        inbound.qos = 2;
        inbound.packet_id = Some(7);
        let first = broker.receive_qos2_publish("pub", inbound.clone());
        assert!(first.accepted);
        assert!(!first.duplicate);
        assert_eq!(broker.clients["pub"].inbound_qos2.len(), 1);

        let duplicate = broker.receive_qos2_publish("pub", inbound);
        assert!(duplicate.accepted);
        assert!(duplicate.duplicate);
        assert_eq!(broker.clients["pub"].inbound_qos2.len(), 1);

        let released = broker.pubrel("pub", 7).unwrap();
        assert!(released.accepted);
        assert_eq!(released.deliveries.len(), 1);
        assert_eq!(released.deliveries[0].client_id, "sub");
        assert!(broker.pubrel("pub", 7).is_none());
    }

    #[test]
    fn replays_qos2_publish_or_pubrel_on_reconnect() {
        let mut broker = BrokerState::new();
        broker.connect("sub".into(), false, None, 60);
        broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "replay/qos2".into(),
                qos: 2,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );

        let mut outgoing = publication("replay/qos2", false);
        outgoing.qos = 2;
        let publish_result = broker.publish("pub", outgoing);
        let packet_id = publish_result.deliveries[0].publication.packet_id.unwrap();
        broker.disconnect("sub", true, None);

        let reconnect = broker.connect("sub".into(), false, None, 60);
        assert!(reconnect.session_present);
        assert_eq!(reconnect.queued.len(), 1);
        assert_eq!(reconnect.queued[0].packet_id, Some(packet_id));
        assert!(reconnect.queued[0].dup);
        assert!(reconnect.pubrels.is_empty());

        assert!(broker.pubrec("sub", packet_id));
        broker.disconnect("sub", true, None);
        let reconnect = broker.connect("sub".into(), false, None, 60);
        assert!(reconnect.queued.is_empty());
        assert_eq!(reconnect.pubrels, vec![packet_id]);
        assert!(broker.pubcomp("sub", packet_id));
    }

    #[test]
    fn queues_qos2_messages_for_offline_durable_sessions() {
        let mut broker = BrokerState::new();
        broker.connect("sub".into(), false, None, 60);
        broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "offline/qos2".into(),
                qos: 2,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );
        broker.disconnect("sub", true, None);

        let mut queued = publication("offline/qos2", false);
        queued.qos = 2;
        let publish_result = broker.publish("pub", queued);
        assert!(publish_result.accepted);
        assert!(publish_result.deliveries.is_empty());

        let reconnect = broker.connect("sub".into(), false, None, 60);
        assert!(reconnect.session_present);
        assert_eq!(reconnect.queued.len(), 1);
        assert_eq!(reconnect.queued[0].topic, "offline/qos2");
        assert_eq!(reconnect.queued[0].qos, 2);
        assert_eq!(reconnect.queued[0].packet_id, Some(1));
        assert!(!reconnect.queued[0].dup);
        assert!(reconnect.pubrels.is_empty());
        assert!(broker.has_inflight_qos2("sub", 1));
    }

    #[test]
    fn queues_qos_messages_for_offline_durable_sessions() {
        let mut broker = BrokerState::new();
        broker.connect("sub".into(), false, None, 60);
        broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "offline/qos1".into(),
                qos: 1,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );
        broker.disconnect("sub", true, None);

        let mut queued = publication("offline/qos1", false);
        queued.qos = 1;
        queued.packet_id = Some(10);
        let publish_result = broker.publish("pub", queued);
        assert!(publish_result.accepted);
        assert!(publish_result.deliveries.is_empty());

        let reconnect = broker.connect("sub".into(), false, None, 60);
        assert!(reconnect.session_present);
        assert_eq!(reconnect.queued.len(), 1);
        assert_eq!(reconnect.queued[0].topic, "offline/qos1");
        assert_eq!(reconnect.queued[0].qos, 1);
        assert_eq!(reconnect.queued[0].packet_id, Some(1));
        assert!(!reconnect.queued[0].dup);
        assert!(broker.has_inflight_qos1("sub", 1));
        assert!(broker.puback("sub", 1));
    }

    #[test]
    fn queues_subscription_identifier_for_offline_durable_sessions() {
        let mut broker = BrokerState::new();
        broker.connect("sub".into(), false, None, 60);
        broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "offline/identified".into(),
                qos: 1,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: Some(88),
            }],
        );
        broker.disconnect("sub", true, None);

        let mut queued = publication("offline/identified", false);
        queued.qos = 1;
        let publish_result = broker.publish("pub", queued);
        assert!(publish_result.accepted);
        assert!(publish_result.deliveries.is_empty());

        let reconnect = broker.connect("sub".into(), false, None, 60);
        assert_eq!(reconnect.queued.len(), 1);
        assert_eq!(reconnect.queued[0].subscription_identifiers, vec![88]);
    }

    #[test]
    fn expires_offline_sessions() {
        let mut broker = BrokerState::new();
        broker.connect("sub".into(), false, None, 1);
        broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "expire/me".into(),
                qos: 1,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );
        broker.disconnect("sub", true, None);
        let disconnected_at = broker.clients["sub"].disconnected_at.unwrap();
        broker.expire_sessions_at(disconnected_at + Duration::from_secs(2));

        let reconnect = broker.connect("sub".into(), false, None, 1);
        assert!(!reconnect.session_present);
        assert!(reconnect.queued.is_empty());
    }

    #[test]
    fn disconnect_can_clear_session_with_expiry_zero() {
        let mut broker = BrokerState::new();
        broker.connect("sub".into(), false, None, 60);
        broker.disconnect("sub", true, Some(0));
        let reconnect = broker.connect("sub".into(), false, None, 60);
        assert!(!reconnect.session_present);
    }
}
