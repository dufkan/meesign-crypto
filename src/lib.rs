pub mod auth;
pub mod c_api;
#[cfg(feature = "protocol")]
pub mod protocol;

pub mod proto {
    pub use prost::Message;
    include!(concat!(env!("OUT_DIR"), "/meesign.rs"));
}
