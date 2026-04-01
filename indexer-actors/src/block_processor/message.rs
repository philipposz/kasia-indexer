use indexer_db::AddressPayload;
use kaspa_rpc_core::RpcBlock;
use std::sync::Arc;

#[derive(Debug)]
pub enum BlockNotification {
    Connected { sink: [u8; 32], pp: [u8; 32] },
    Disconnected,
    Shutdown,
    Notification(Arc<RpcBlock>),
}

#[derive(Debug)]
pub enum GapFillingProgress {
    Update {
        target: [u8; 32],
        blocks: Vec<RpcBlock>,
    },
    Interrupted {
        target: [u8; 32],
    },
    Finished {
        target: [u8; 32],
        blocks: Vec<RpcBlock>,
    },
    Error {
        target: [u8; 32],
        err: workflow_rpc::client::error::Error,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum PushMessageType {
    Handshake,
    Payment,
    Contextual,
    PulseReply,
}

#[derive(Debug, Clone)]
pub struct PushDispatchEvent {
    pub message_type: PushMessageType,
    pub tx_id: [u8; 32],
    pub sender: Option<AddressPayload>,
    pub receiver: AddressPayload,
    pub amount: Option<u64>,
    pub payload: Option<Vec<u8>>,
    pub timestamp: u64,
}
