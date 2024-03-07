use crate::core::SeqNumber;
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::Block;
use crypto::Digest;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;

#[derive(Debug)]
pub enum PayloadStatus {
    Accept,
    Reject,
    Wait,
}

#[derive(Debug)]
pub enum ConsensusMempoolMessage {
    Get(usize, oneshot::Sender<Vec<Digest>>),
    Verify(Box<Block>, oneshot::Sender<PayloadStatus>),
    Cleanup(Vec<Digest>, SeqNumber, SeqNumber),
}

pub struct MempoolDriver {
    mempool_channel: Sender<ConsensusMempoolMessage>,
}

impl MempoolDriver {
    pub fn new(mempool_channel: Sender<ConsensusMempoolMessage>) -> Self {
        Self { mempool_channel }
    }

    pub async fn get(&mut self, max: usize) -> Vec<Digest> {
        let (sender, receiver) = oneshot::channel();
        let message = ConsensusMempoolMessage::Get(max, sender);
        self.mempool_channel
            .send(message)
            .await
            .expect("Failed to send message to mempool");
        receiver
            .await
            .expect("Failed to receive payload from mempool")
    }

    //验证mempool是否已经收到了区块
    pub async fn verify(&mut self, block: Block) -> ConsensusResult<bool> {
        let (sender, receiver) = oneshot::channel();
        let message = ConsensusMempoolMessage::Verify(Box::new(block), sender);
        self.mempool_channel
            .send(message)
            .await
            .expect("Failed to send message to mempool");
        match receiver
            .await
            .expect("Failed to receive payload status from mempool")
        {
            PayloadStatus::Accept => Ok(true),
            PayloadStatus::Reject => Err(ConsensusError::InvalidPayload),
            PayloadStatus::Wait => Ok(false),
        }
    }

    pub async fn cleanup(&mut self, digest: Vec<Digest>, epoch: SeqNumber, height: SeqNumber) {
        let message = ConsensusMempoolMessage::Cleanup(digest, epoch, height);
        self.mempool_channel
            .send(message)
            .await
            .expect("Failed to send message to mempool");
    }
}
