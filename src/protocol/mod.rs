#[cfg(feature = "elgamal")]
pub mod elgamal;
#[cfg(feature = "frost")]
pub mod frost;
#[cfg(feature = "gg18")]
pub mod gg18;

mod apdu;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use crate::proto::{MessageType, ProtocolMessage, ProtocolType};
use prost::Message;
use serde::{Deserialize, Serialize};

pub enum Recipient {
    Card,
    Server,
}

#[typetag::serde]
pub trait Protocol {
    fn advance(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)>;
    fn finish(self: Box<Self>) -> Result<Vec<u8>>;
}

pub trait KeygenProtocol: Protocol {
    fn new() -> Self
    where
        Self: Sized;
}

pub trait ThresholdProtocol: Protocol {
    fn new(group: &[u8]) -> Self
    where
        Self: Sized;
}

fn deserialize_vec<'de, T: Deserialize<'de>>(vec: &'de [Vec<u8>]) -> serde_json::Result<Vec<T>> {
    vec.iter()
        .map(|item| serde_json::from_slice::<T>(item))
        .collect()
}

/// Encode a broadcast message
fn encode_raw_bcast(message: Vec<u8>, protocol_type: ProtocolType) -> Vec<u8> {
    ProtocolMessage {
        protocol_type: protocol_type.into(),
        message_type: MessageType::Broadcast.into(),
        messages: vec![message],
    }.encode_to_vec()
}

/// Serialize and encode a broadcast message
fn serialize_bcast<T: Serialize>(value: &T, protocol_type: ProtocolType) -> serde_json::Result<Vec<u8>> {
    let message = serde_json::to_vec(value)?;
    Ok(encode_raw_bcast(message, protocol_type))
}

/// Encode a Vec of unicast messages
fn encode_raw_uni(messages: Vec<Vec<u8>>, protocol_type: ProtocolType) -> Vec<u8> {
    ProtocolMessage {
        protocol_type: protocol_type.into(),
        message_type: MessageType::Unicast.into(),
        messages,
    }.encode_to_vec()
}

/// Serialize and encode a Vec of unicast messages
fn serialize_uni<T: Serialize>(vec: Vec<T>, protocol_type: ProtocolType) -> serde_json::Result<Vec<u8>> {
    let messages = vec.iter()
        .map(serde_json::to_vec)
        .collect::<serde_json::Result<Vec<_>>>()?;
    Ok(encode_raw_uni(messages, protocol_type))
}

/// Decode a protobuf message from the server
fn decode(data: &[u8]) -> std::result::Result<Vec<Vec<u8>>, prost::DecodeError> {
    Ok(ProtocolMessage::decode(data)?.messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    use prost::bytes::Bytes;

    use crate::{
        proto::{ProtocolGroupInit, ProtocolInit},
        protocol::{KeygenProtocol, ThresholdProtocol},
    };

    /// Translate a message from a client to a Vec of messages for every other client
    fn distribute_client_message(message: ProtocolMessage, parties: u32) -> Vec<Vec<u8>> {
        match message.message_type() {
            MessageType::Broadcast => {
                let messages = message.messages;
                assert_eq!(messages.len(), 1);
                std::iter::repeat(messages[0].clone()).take(parties as usize).collect()
            },
            MessageType::Unicast => {
                let messages = message.messages;
                assert_eq!(messages.len(), parties as usize);
                messages
            },
        }
    }

    pub(super) trait KeygenProtocolTest: KeygenProtocol + Sized {
        // Cannot be added in Protocol (yet) due to typetag Trait limitations
        const PROTOCOL_TYPE: ProtocolType;
        const ROUNDS: usize;
        const INDEX_OFFSET: u32 = 0;

        fn run(threshold: u32, parties: u32) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
            assert!(threshold <= parties);

            // initialize
            let mut ctxs: Vec<Self> = (0..parties).map(|_| Self::new()).collect();
            let mut messages: Vec<_> = ctxs
                .iter_mut()
                .enumerate()
                .map(|(idx, ctx)| {
                    ProtocolMessage::decode::<Bytes>(
                        ctx.advance(
                            &(ProtocolGroupInit {
                                protocol_type: Self::PROTOCOL_TYPE as i32,
                                index: idx as u32 + Self::INDEX_OFFSET,
                                parties,
                                threshold,
                            })
                            .encode_to_vec(),
                        )
                        .unwrap()
                        .0
                        .into(),
                    )
                    .unwrap()
                })
                .map(|msg| distribute_client_message(msg, parties - 1))
                .collect();

            // protocol rounds
            for _ in 0..(Self::ROUNDS - 1) {
                messages = ctxs
                    .iter_mut()
                    .enumerate()
                    .map(|(idx, ctx)| {
                        let relay = messages
                            .iter()
                            .enumerate()
                            .map(|(sender, msg)| {
                                if sender < idx {
                                    Some(msg[idx - 1].clone())
                                } else if sender > idx {
                                    Some(msg[idx].clone())
                                } else {
                                    None
                                }
                            })
                            .filter(Option::is_some)
                            .map(Option::unwrap)
                            .collect();

                        ProtocolMessage::decode::<Bytes>(
                            ctx.advance(
                                &(ProtocolMessage {
                                    protocol_type: Self::PROTOCOL_TYPE as i32,
                                    message_type: MessageType::Unicast.into(),
                                    messages: relay,
                                })
                                .encode_to_vec(),
                            )
                            .unwrap()
                            .0
                            .into(),
                        )
                        .unwrap()
                    })
                    .map(|msg| distribute_client_message(msg, parties - 1))
                    .collect();
            }

            let pks: Vec<_> = messages.iter().map(|x| x[0].clone()).collect();

            let results = ctxs
                .into_iter()
                .map(|ctx| Box::new(ctx).finish().unwrap())
                .collect();

            (pks, results)
        }
    }

    pub(super) trait ThresholdProtocolTest: ThresholdProtocol + Sized {
        // Cannot be added in Protocol (yet) due to typetag Trait limitations
        const PROTOCOL_TYPE: ProtocolType;
        const ROUNDS: usize;
        const INDEX_OFFSET: u32 = 0;

        fn run(ctxs: Vec<Vec<u8>>, indices: Vec<u16>, data: Vec<u8>) -> Vec<Vec<u8>> {
            // initialize
            let mut ctxs: Vec<Self> = ctxs
                .iter()
                .enumerate()
                .filter(|(idx, _)| indices.contains(&(*idx as u16)))
                .map(|(_, ctx)| Self::new(&ctx))
                .collect();
            let mut messages: Vec<_> = indices
                .iter()
                .zip(ctxs.iter_mut())
                .map(|(idx, ctx)| {
                    ProtocolMessage::decode::<Bytes>(
                        ctx.advance(
                            &(ProtocolInit {
                                protocol_type: Self::PROTOCOL_TYPE as i32,
                                indices: indices
                                    .iter()
                                    .map(|x| *x as u32 + Self::INDEX_OFFSET)
                                    .collect(),
                                index: *idx as u32 + Self::INDEX_OFFSET,
                                data: data.clone(),
                            })
                            .encode_to_vec(),
                        )
                        .unwrap()
                        .0
                        .into(),
                    )
                    .unwrap()
                })
                .map(|msg| distribute_client_message(msg, indices.len() as u32 - 1))
                .collect();

            // protocol rounds
            for _ in 0..(Self::ROUNDS - 1) {
                messages = ctxs
                    .iter_mut()
                    .enumerate()
                    .map(|(idx, ctx)| {
                        let relay = messages
                            .iter()
                            .enumerate()
                            .map(|(sender, msg)| {
                                if sender < idx {
                                    Some(msg[idx - 1].clone())
                                } else if sender > idx {
                                    Some(msg[idx].clone())
                                } else {
                                    None
                                }
                            })
                            .filter(Option::is_some)
                            .map(Option::unwrap)
                            .collect();

                        ProtocolMessage::decode::<Bytes>(
                            ctx.advance(
                                &(ProtocolMessage {
                                    protocol_type: Self::PROTOCOL_TYPE as i32,
                                    message_type: MessageType::Unicast.into(),
                                    messages: relay,
                                })
                                .encode_to_vec(),
                            )
                            .unwrap()
                            .0
                            .into(),
                        )
                        .unwrap()
                    })
                    .map(|msg| distribute_client_message(msg, indices.len() as u32 - 1))
                    .collect();
            }

            ctxs.into_iter()
                .map(|ctx| Box::new(ctx).finish().unwrap())
                .collect()
        }
    }
}
