//! The network front door of the supervisor: the shared WebRTC UDP socket
//! and its receive thread with the demux, the host addresses on every
//! interface, the ICE-TCP listener, the STUN
//! codec and Binding client, and the TURN client: the codec, the
//! long-term credential mechanism, the allocation state machine and the
//! task that drives each allocation.

pub mod allocation;
pub mod credential;
pub mod demux;
mod hosts;
pub mod stun;
pub mod stun_client;
pub mod tcp;
pub mod turn;
pub mod turn_client;
pub mod udp;
