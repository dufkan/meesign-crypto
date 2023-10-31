#[cfg(feature = "elgamal")]
pub mod elgamal;
#[cfg(feature = "frost")]
pub mod frost;
#[cfg(feature = "gg18")]
pub mod gg18;

mod apdu;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use crate::proto::{ProtocolMessage, ProtocolType};
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

fn inflate<T: Clone>(value: T, n: usize) -> Vec<T> {
    std::iter::repeat(value).take(n).collect()
}

/// Serialize value and repeat the result n times,
/// as the current server always expects one message for each party
fn serialize_bcast<T: Serialize>(value: &T, n: usize) -> serde_json::Result<Vec<Vec<u8>>> {
    let ser = serde_json::to_vec(value)?;
    Ok(inflate(ser, n))
}

/// Serialize vector of unicast messages
fn serialize_uni<T: Serialize>(vec: Vec<T>) -> serde_json::Result<Vec<Vec<u8>>> {
    vec.iter().map(|item| serde_json::to_vec(item)).collect()
}

/// Decode a protobuf message from the server
fn unpack(data: &[u8]) -> std::result::Result<Vec<Vec<u8>>, prost::DecodeError> {
    let msgs = ProtocolMessage::decode(data)?.message;
    Ok(msgs)
}

/// Encode msgs as a protobuf message for the server
fn pack(msgs: Vec<Vec<u8>>, protocol_type: ProtocolType) -> Vec<u8> {
    ProtocolMessage {
        protocol_type: protocol_type.into(),
        message: msgs,
    }
    .encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    use prost::bytes::Bytes;

    use crate::{
        proto::{ProtocolGroupInit, ProtocolInit},
        protocol::{KeygenProtocol, ThresholdProtocol},
    };

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
                    .message
                })
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
                                    message: relay,
                                })
                                .encode_to_vec(),
                            )
                            .unwrap()
                            .0
                            .into(),
                        )
                        .unwrap()
                        .message
                    })
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
                    .message
                })
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
                                    message: relay,
                                })
                                .encode_to_vec(),
                            )
                            .unwrap()
                            .0
                            .into(),
                        )
                        .unwrap()
                        .message
                    })
                    .collect();
            }

            ctxs.into_iter()
                .map(|ctx| Box::new(ctx).finish().unwrap())
                .collect()
        }
    }
}
