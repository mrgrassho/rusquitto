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
    pub order: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedSession {
    pub client_id: String,
    pub session_expiry_interval: u32,
    pub subscriptions: Vec<Subscription>,
    pub queued: Vec<Publication>,
    pub inflight_qos1: Vec<Publication>,
    pub inflight_qos2: Vec<Qos2Outbound>,
    pub inbound_qos2: Vec<Publication>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeliverySpec {
    client_id: String,
    qos: u8,
    retain_as_published: bool,
    identifier: Option<u32>,
    online: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SharedDeliveryCandidate {
    order: u64,
    spec: DeliverySpec,
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
    pub next_outgoing_mid: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub client_id: String,
    pub publication: Publication,
}

#[derive(Debug, Clone, Default)]
pub struct BrokerState {
    clients: HashMap<String, ClientSession>,
    retained: BTreeMap<String, Publication>,
    shared_cursors: HashMap<(String, String), usize>,
    upgrade_outgoing_qos: bool,
    next_subscription_order: u64,
}

impl BrokerState {
    pub fn new() -> Self {
        Self {
            next_subscription_order: 1,
            ..Self::default()
        }
    }

    pub fn set_upgrade_outgoing_qos(&mut self, value: bool) {
        self.upgrade_outgoing_qos = value;
    }

    pub fn restore_retained(&mut self, retained: Vec<Publication>) {
        self.retained.clear();
        for mut publication in retained {
            publication.retain = true;
            publication.packet_id = None;
            publication.dup = false;
            publication.topic_alias = None;
            publication.subscription_identifiers.clear();
            if Self::valid_publication(&publication) && !publication.payload.is_empty() {
                self.retained.insert(publication.topic.clone(), publication);
            }
        }
    }

    pub fn retained_snapshot(&self) -> Vec<Publication> {
        self.retained.values().cloned().collect()
    }

    pub fn restore_sessions(&mut self, sessions: Vec<PersistedSession>) {
        for session in sessions {
            if session.client_id.is_empty() || session.session_expiry_interval == 0 {
                continue;
            }
            let mut max_packet_id: Option<u16> = None;

            let mut subscriptions = HashMap::new();
            for mut subscription in session.subscriptions {
                if !Self::valid_subscription(&subscription) {
                    continue;
                }
                subscription.order = self.next_subscription_order;
                self.next_subscription_order += 1;
                subscriptions.insert(subscription.filter.clone(), subscription);
            }

            let queued: Vec<_> = session
                .queued
                .into_iter()
                .filter_map(Self::valid_queued_publication)
                .inspect(|publication| {
                    if let Some(packet_id) = publication.packet_id {
                        Self::record_packet_id(&mut max_packet_id, packet_id);
                    }
                })
                .collect();

            let mut inflight_qos1 = BTreeMap::new();
            for publication in session.inflight_qos1 {
                let Some(publication) = Self::valid_inflight_publication(publication, 1) else {
                    continue;
                };
                let packet_id = publication.packet_id.expect("validated packet id");
                Self::record_packet_id(&mut max_packet_id, packet_id);
                inflight_qos1.insert(packet_id, publication);
            }

            let mut inflight_qos2 = BTreeMap::new();
            for mut outbound in session.inflight_qos2 {
                let Some(publication) = Self::valid_inflight_publication(outbound.publication, 2)
                else {
                    continue;
                };
                let packet_id = publication.packet_id.expect("validated packet id");
                Self::record_packet_id(&mut max_packet_id, packet_id);
                outbound.publication = publication;
                inflight_qos2.insert(packet_id, outbound);
            }

            let mut inbound_qos2 = BTreeMap::new();
            for publication in session.inbound_qos2 {
                let Some(publication) = Self::valid_inflight_publication(publication, 2) else {
                    continue;
                };
                let packet_id = publication.packet_id.expect("validated packet id");
                inbound_qos2.insert(packet_id, publication);
            }

            self.clients.insert(
                session.client_id.clone(),
                ClientSession {
                    client_id: session.client_id,
                    subscriptions,
                    will: None,
                    queued,
                    inflight_qos1,
                    inflight_qos2,
                    inbound_qos2,
                    session_expiry_interval: session.session_expiry_interval,
                    disconnected_at: None,
                    online: false,
                    next_outgoing_mid: Self::next_after_packet_id(max_packet_id),
                },
            );
        }
    }

    pub fn session_snapshot(&self) -> Vec<PersistedSession> {
        let mut sessions: Vec<_> = self
            .clients
            .values()
            .filter(|session| session.session_expiry_interval != 0)
            .map(|session| {
                let mut subscriptions: Vec<_> = session.subscriptions.values().cloned().collect();
                subscriptions.sort_by(|left, right| {
                    left.order
                        .cmp(&right.order)
                        .then_with(|| left.filter.cmp(&right.filter))
                });
                let queued = session
                    .queued
                    .iter()
                    .filter(|publication| {
                        publication.qos > 0
                            && publication.packet_id.is_some()
                            && Self::valid_publication(publication)
                    })
                    .cloned()
                    .collect();
                let inflight_qos1 = session
                    .inflight_qos1
                    .values()
                    .filter(|publication| Self::valid_publication(publication))
                    .cloned()
                    .collect();
                let inflight_qos2 = session
                    .inflight_qos2
                    .values()
                    .filter(|outbound| Self::valid_publication(&outbound.publication))
                    .cloned()
                    .collect();
                let inbound_qos2 = session
                    .inbound_qos2
                    .values()
                    .filter(|publication| Self::valid_publication(publication))
                    .cloned()
                    .collect();
                PersistedSession {
                    client_id: session.client_id.clone(),
                    session_expiry_interval: session.session_expiry_interval,
                    subscriptions,
                    queued,
                    inflight_qos1,
                    inflight_qos2,
                    inbound_qos2,
                }
            })
            .collect();
        sessions.sort_by(|left, right| left.client_id.cmp(&right.client_id));
        sessions
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
                    next_outgoing_mid: 1,
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
                let mut pending = Vec::new();
                for publication in session.inflight_qos1.values_mut() {
                    publication.dup = true;
                    pending.push(publication.clone());
                }

                pending.extend(session.inflight_qos2.values_mut().filter_map(|outbound| {
                    if outbound.state == Qos2OutboundState::WaitingPubRec {
                        outbound.publication.dup = true;
                        Some(outbound.publication.clone())
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
        let mut next_subscription_order = self.next_subscription_order;

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
            let order = session.subscriptions.get(&request.filter).map_or_else(
                || {
                    let order = next_subscription_order;
                    next_subscription_order += 1;
                    order
                },
                |subscription| subscription.order,
            );
            let subscription = Subscription {
                filter: request.filter.clone(),
                qos: request.qos,
                no_local: request.no_local,
                retain_as_published: request.retain_as_published,
                retain_handling: request.retain_handling,
                identifier: request.identifier,
                order,
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
        self.next_subscription_order = next_subscription_order;

        for subscription in replay_filters {
            let matching: Vec<Publication> = self
                .retained
                .values()
                .filter(|publication| topic::matches(&subscription.filter, &publication.topic))
                .cloned()
                .collect();

            for publication in matching {
                let mut retained_publication = publication.clone();
                retained_publication.qos = self.delivery_qos(publication.qos, subscription.qos);
                retained_publication.retain =
                    !subscription.retain_as_published || publication.retain;
                retained_publication.subscription_identifiers.clear();
                if let Some(identifier) = subscription.identifier {
                    retained_publication
                        .subscription_identifiers
                        .push(identifier);
                }
                if retained_publication.qos > 0 {
                    retained_publication.packet_id = self.next_packet_id_for(client_id);
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
        let mut shared_candidates: HashMap<(String, String), Vec<SharedDeliveryCandidate>> =
            HashMap::new();
        for (client_id, session) in &self.clients {
            let mut normal_delivery = None;
            for subscription in session.subscriptions.values() {
                if subscription.no_local && client_id == source_client_id {
                    continue;
                }
                let spec = DeliverySpec {
                    client_id: client_id.clone(),
                    qos: self.delivery_qos(publication.qos, subscription.qos),
                    retain_as_published: subscription.retain_as_published,
                    identifier: subscription.identifier,
                    online: session.online,
                };
                if let Some((group, shared_filter)) = topic::shared_filter(&subscription.filter) {
                    if topic::matches(shared_filter, &publication.topic) {
                        shared_candidates
                            .entry((group.to_owned(), shared_filter.to_owned()))
                            .or_default()
                            .push(SharedDeliveryCandidate {
                                order: subscription.order,
                                spec,
                            });
                    }
                } else if normal_delivery.is_none()
                    && topic::matches(&subscription.filter, &publication.topic)
                {
                    normal_delivery = Some(spec);
                }
            }
            if let Some(spec) = normal_delivery {
                delivery_specs.push(spec);
            }
        }

        for (key, mut candidates) in shared_candidates {
            candidates.sort_by_key(|candidate| candidate.order);
            let cursor = self.shared_cursors.entry(key).or_default();
            let selected = *cursor % candidates.len();
            delivery_specs.push(candidates[selected].spec.clone());
            *cursor = (*cursor + 1) % candidates.len();
        }

        for spec in delivery_specs {
            let mut outgoing = publication.clone();
            outgoing.qos = spec.qos;
            outgoing.retain = spec.retain_as_published && outgoing.retain;
            if let Some(identifier) = spec.identifier {
                outgoing.subscription_identifiers.push(identifier);
            }
            outgoing.packet_id = if outgoing.qos > 0 {
                self.next_packet_id_for(&spec.client_id)
            } else {
                None
            };
            if spec.online {
                self.track_outgoing(&spec.client_id, &outgoing);
                deliveries.push(Delivery {
                    client_id: spec.client_id,
                    publication: outgoing,
                });
            } else if outgoing.qos > 0 {
                if let Some(session) = self.clients.get_mut(&spec.client_id) {
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

    fn valid_subscription(subscription: &Subscription) -> bool {
        topic::check_subscribe_topic(&subscription.filter).is_ok()
            && subscription.qos <= 2
            && subscription.retain_handling <= 2
            && subscription
                .identifier
                .map_or(true, |identifier| identifier > 0)
    }

    fn valid_queued_publication(mut publication: Publication) -> Option<Publication> {
        if publication.qos == 0
            || publication.packet_id.is_none()
            || !Self::valid_publication(&publication)
        {
            return None;
        }
        publication.topic_alias = None;
        publication
            .subscription_identifiers
            .retain(|identifier| *identifier > 0);
        Some(publication)
    }

    fn valid_inflight_publication(
        mut publication: Publication,
        expected_qos: u8,
    ) -> Option<Publication> {
        if publication.qos != expected_qos
            || publication.packet_id.is_none()
            || !Self::valid_publication(&publication)
        {
            return None;
        }
        publication.topic_alias = None;
        publication
            .subscription_identifiers
            .retain(|identifier| *identifier > 0);
        Some(publication)
    }

    fn record_packet_id(max_packet_id: &mut Option<u16>, packet_id: u16) {
        *max_packet_id = Some(max_packet_id.map_or(packet_id, |max| max.max(packet_id)));
    }

    fn delivery_qos(&self, publish_qos: u8, subscription_qos: u8) -> u8 {
        if self.upgrade_outgoing_qos {
            subscription_qos
        } else {
            publish_qos.min(subscription_qos)
        }
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

    fn next_packet_id_for(&mut self, client_id: &str) -> Option<u16> {
        let session = self.clients.get_mut(client_id)?;
        let id = session.next_outgoing_mid;
        session.next_outgoing_mid = if session.next_outgoing_mid == u16::MAX {
            1
        } else {
            session.next_outgoing_mid + 1
        };
        Some(id)
    }

    fn next_after_packet_id(max_packet_id: Option<u16>) -> u16 {
        match max_packet_id {
            Some(u16::MAX) | None => 1,
            Some(packet_id) => packet_id + 1,
        }
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

    fn delivered_clients(result: &PublishResult) -> Vec<&str> {
        let mut clients: Vec<_> = result
            .deliveries
            .iter()
            .map(|delivery| delivery.client_id.as_str())
            .collect();
        clients.sort_unstable();
        clients
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
    fn assigns_outbound_packet_ids_per_client_session() {
        let mut broker = BrokerState::new();
        for client_id in ["sub-a", "sub-b"] {
            broker.connect(client_id.into(), true, None, 0);
            broker.subscribe(
                client_id,
                vec![SubscriptionRequest {
                    filter: "topic".into(),
                    qos: 1,
                    no_local: false,
                    retain_as_published: false,
                    retain_handling: 0,
                    identifier: None,
                }],
            );
        }

        let mut first = publication("topic", false);
        first.qos = 1;
        first.packet_id = Some(10);
        let first = broker.publish("pub-a", first);
        let mut mids: Vec<_> = first
            .deliveries
            .iter()
            .map(|delivery| (delivery.client_id.as_str(), delivery.publication.packet_id))
            .collect();
        mids.sort_unstable();
        assert_eq!(mids, vec![("sub-a", Some(1)), ("sub-b", Some(1))]);

        broker.puback("sub-a", 1);
        broker.puback("sub-b", 1);

        let mut second = publication("topic", false);
        second.qos = 1;
        second.packet_id = Some(11);
        let second = broker.publish("pub-b", second);
        let mut mids: Vec<_> = second
            .deliveries
            .iter()
            .map(|delivery| (delivery.client_id.as_str(), delivery.publication.packet_id))
            .collect();
        mids.sort_unstable();
        assert_eq!(mids, vec![("sub-a", Some(2)), ("sub-b", Some(2))]);
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
    fn routes_shared_subscriptions_round_robin_by_group() {
        let mut broker = BrokerState::new();
        for client_id in ["client1", "client2", "client3", "client4", "client5"] {
            broker.connect(client_id.into(), true, None, 0);
        }

        broker.subscribe(
            "client1",
            vec![SubscriptionRequest {
                filter: "shared/#".into(),
                qos: 0,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );
        for client_id in ["client2", "client3", "client5"] {
            broker.subscribe(
                client_id,
                vec![SubscriptionRequest {
                    filter: "$share/one/shared/topic".into(),
                    qos: 0,
                    no_local: false,
                    retain_as_published: false,
                    retain_handling: 0,
                    identifier: None,
                }],
            );
        }
        for client_id in ["client3", "client4"] {
            broker.subscribe(
                client_id,
                vec![SubscriptionRequest {
                    filter: "$share/two/shared/topic".into(),
                    qos: 0,
                    no_local: false,
                    retain_as_published: false,
                    retain_handling: 0,
                    identifier: None,
                }],
            );
        }

        let first = broker.publish("client1", publication("shared/topic", false));
        assert_eq!(
            delivered_clients(&first),
            vec!["client1", "client2", "client3"]
        );

        let second = broker.publish("client1", publication("shared/topic", false));
        assert_eq!(
            delivered_clients(&second),
            vec!["client1", "client3", "client4"]
        );

        let third = broker.publish("client1", publication("shared/topic", false));
        assert_eq!(
            delivered_clients(&third),
            vec!["client1", "client3", "client5"]
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
    fn replays_retained_messages_in_topic_order_and_clears_deleted_topics() {
        let mut broker = BrokerState::new();
        broker.connect("pub".into(), true, None, 0);
        broker.publish("pub", publication("1/2/3/4/5/6/7", true));
        broker.publish("pub", publication("1/2/3/4", true));
        broker.publish("pub", publication("1", true));

        broker.connect("sub1".into(), true, None, 0);
        let result = broker.subscribe(
            "sub1",
            vec![SubscriptionRequest {
                filter: "#".into(),
                qos: 0,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );
        assert_eq!(
            result
                .retained
                .iter()
                .map(|delivery| delivery.publication.topic.as_str())
                .collect::<Vec<_>>(),
            vec!["1", "1/2/3/4", "1/2/3/4/5/6/7"]
        );

        let mut clear = publication("1/2/3/4", true);
        clear.payload.clear();
        broker.publish("pub", clear);

        broker.connect("sub2".into(), true, None, 0);
        let result = broker.subscribe(
            "sub2",
            vec![SubscriptionRequest {
                filter: "#".into(),
                qos: 0,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );
        assert_eq!(
            result
                .retained
                .iter()
                .map(|delivery| delivery.publication.topic.as_str())
                .collect::<Vec<_>>(),
            vec!["1", "1/2/3/4/5/6/7"]
        );
    }

    #[test]
    fn can_upgrade_retained_replay_qos_to_subscription_qos() {
        let mut broker = BrokerState::new();
        broker.set_upgrade_outgoing_qos(true);
        broker.connect("pub".into(), true, None, 0);
        broker.publish("pub", publication("retain/upgrade", true));
        broker.connect("sub".into(), true, None, 0);

        let result = broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "retain/upgrade".into(),
                qos: 1,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );

        assert_eq!(result.retained.len(), 1);
        assert_eq!(result.retained[0].publication.qos, 1);
        assert_eq!(result.retained[0].publication.packet_id, Some(1));
        assert!(broker.has_inflight_qos1("sub", 1));
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
    fn snapshots_durable_sessions_for_persistence() {
        let mut broker = BrokerState::new();
        broker.connect("durable".into(), false, None, 60);
        broker.subscribe(
            "durable",
            vec![SubscriptionRequest {
                filter: "persist/b".into(),
                qos: 1,
                no_local: true,
                retain_as_published: true,
                retain_handling: 2,
                identifier: Some(9),
            }],
        );
        broker.connect("clean".into(), true, None, 0);

        let snapshot = broker.session_snapshot();

        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].client_id, "durable");
        assert_eq!(snapshot[0].session_expiry_interval, 60);
        assert_eq!(snapshot[0].subscriptions.len(), 1);
        let subscription = &snapshot[0].subscriptions[0];
        assert_eq!(subscription.filter, "persist/b");
        assert_eq!(subscription.qos, 1);
        assert!(subscription.no_local);
        assert!(subscription.retain_as_published);
        assert_eq!(subscription.retain_handling, 2);
        assert_eq!(subscription.identifier, Some(9));
    }

    #[test]
    fn restores_persisted_sessions_for_reconnect_and_routing() {
        let mut broker = BrokerState::new();
        broker.restore_sessions(vec![PersistedSession {
            client_id: "durable".into(),
            session_expiry_interval: 60,
            subscriptions: vec![Subscription {
                filter: "persist/#".into(),
                qos: 1,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: Some(12),
                order: 99,
            }],
            queued: Vec::new(),
            inflight_qos1: Vec::new(),
            inflight_qos2: Vec::new(),
            inbound_qos2: Vec::new(),
        }]);

        let mut queued = publication("persist/topic", false);
        queued.qos = 1;
        let publish_result = broker.publish("pub", queued);
        assert!(publish_result.accepted);
        assert!(publish_result.deliveries.is_empty());

        let reconnect = broker.connect("durable".into(), false, None, 60);
        assert!(reconnect.session_present);
        assert_eq!(reconnect.queued.len(), 1);
        assert_eq!(reconnect.queued[0].topic, "persist/topic");
        assert_eq!(reconnect.queued[0].qos, 1);
        assert_eq!(reconnect.queued[0].subscription_identifiers, vec![12]);
    }

    #[test]
    fn snapshots_and_restores_queued_messages_for_persistence() {
        let mut broker = BrokerState::new();
        broker.connect("durable".into(), false, None, 60);
        broker.subscribe(
            "durable",
            vec![SubscriptionRequest {
                filter: "persist/#".into(),
                qos: 1,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: Some(5),
            }],
        );
        broker.disconnect("durable", true, None);

        let mut queued = publication("persist/queued", false);
        queued.qos = 1;
        let publish_result = broker.publish("pub", queued);
        assert!(publish_result.accepted);
        assert!(publish_result.deliveries.is_empty());

        let snapshot = broker.session_snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].queued.len(), 1);
        assert_eq!(snapshot[0].queued[0].packet_id, Some(1));

        let mut restored = BrokerState::new();
        restored.restore_sessions(snapshot);
        let reconnect = restored.connect("durable".into(), false, None, 60);
        assert!(reconnect.session_present);
        assert_eq!(reconnect.queued.len(), 1);
        assert_eq!(reconnect.queued[0].topic, "persist/queued");
        assert_eq!(reconnect.queued[0].packet_id, Some(1));
        assert_eq!(reconnect.queued[0].subscription_identifiers, vec![5]);
        assert!(restored.puback("durable", 1));

        restored.disconnect("durable", true, None);
        let mut next = publication("persist/next", false);
        next.qos = 1;
        restored.publish("pub", next);
        let reconnect = restored.connect("durable".into(), false, None, 60);
        assert_eq!(reconnect.queued.len(), 1);
        assert_eq!(reconnect.queued[0].packet_id, Some(2));
    }

    #[test]
    fn snapshots_and_restores_outbound_qos1_inflight_for_persistence() {
        let mut broker = BrokerState::new();
        broker.connect("sub".into(), false, None, 60);
        broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "persist/qos1".into(),
                qos: 1,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );

        let mut publication = publication("persist/qos1", false);
        publication.qos = 1;
        let result = broker.publish("pub", publication);
        let packet_id = result.deliveries[0].publication.packet_id.unwrap();

        let snapshot = broker.session_snapshot();
        assert_eq!(snapshot[0].inflight_qos1.len(), 1);

        let mut restored = BrokerState::new();
        restored.restore_sessions(snapshot);
        let reconnect = restored.connect("sub".into(), false, None, 60);
        assert!(reconnect.session_present);
        assert_eq!(reconnect.queued.len(), 1);
        assert_eq!(reconnect.queued[0].packet_id, Some(packet_id));
        assert!(reconnect.queued[0].dup);
    }

    #[test]
    fn snapshots_and_restores_outbound_qos2_inflight_for_persistence() {
        let mut broker = BrokerState::new();
        broker.connect("sub".into(), false, None, 60);
        broker.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "persist/qos2".into(),
                qos: 2,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );

        let mut publication = publication("persist/qos2", false);
        publication.qos = 2;
        let result = broker.publish("pub", publication);
        let packet_id = result.deliveries[0].publication.packet_id.unwrap();

        let snapshot = broker.session_snapshot();
        assert_eq!(snapshot[0].inflight_qos2.len(), 1);
        assert_eq!(
            snapshot[0].inflight_qos2[0].state,
            Qos2OutboundState::WaitingPubRec
        );

        let mut restored = BrokerState::new();
        restored.restore_sessions(snapshot);
        let reconnect = restored.connect("sub".into(), false, None, 60);
        assert_eq!(reconnect.queued.len(), 1);
        assert_eq!(reconnect.queued[0].packet_id, Some(packet_id));
        assert!(reconnect.queued[0].dup);

        assert!(restored.pubrec("sub", packet_id));
        let snapshot = restored.session_snapshot();
        assert_eq!(
            snapshot[0].inflight_qos2[0].state,
            Qos2OutboundState::WaitingPubComp
        );

        let mut restored = BrokerState::new();
        restored.restore_sessions(snapshot);
        let reconnect = restored.connect("sub".into(), false, None, 60);
        assert!(reconnect.queued.is_empty());
        assert_eq!(reconnect.pubrels, vec![packet_id]);
    }

    #[test]
    fn snapshots_and_restores_inbound_qos2_for_persistence() {
        let mut broker = BrokerState::new();
        broker.connect("pub".into(), false, None, 60);

        let mut inbound = publication("persist/inbound", false);
        inbound.qos = 2;
        inbound.packet_id = Some(17);
        let result = broker.receive_qos2_publish("pub", inbound);
        assert!(result.accepted);

        let snapshot = broker.session_snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].inbound_qos2.len(), 1);
        assert_eq!(snapshot[0].inbound_qos2[0].packet_id, Some(17));

        let mut restored = BrokerState::new();
        restored.restore_sessions(snapshot);
        restored.connect("sub".into(), true, None, 0);
        restored.subscribe(
            "sub",
            vec![SubscriptionRequest {
                filter: "persist/inbound".into(),
                qos: 2,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
                identifier: None,
            }],
        );

        let reconnect = restored.connect("pub".into(), false, None, 60);
        assert!(reconnect.session_present);
        let result = restored.pubrel("pub", 17).expect("pubrel should release");
        assert!(result.accepted);
        assert_eq!(result.deliveries.len(), 1);
        assert_eq!(result.deliveries[0].client_id, "sub");
        assert_eq!(result.deliveries[0].publication.topic, "persist/inbound");
        assert_eq!(result.deliveries[0].publication.payload, b"payload");
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
