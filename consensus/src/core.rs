use std::collections::HashMap;

use crate::aggregator::Aggregator;
use crate::commitor::Commitor;
use crate::config::{Committee, Parameters};
use crate::error::{ConsensusError, ConsensusResult};
use crate::filter::FilterInput;
use crate::mempool::MempoolDriver;
use crate::messages::{
    ABAOutput, ABAVal, Block, EchoVote, Prepare, RBCProof, RandomnessShare, ReadyVote,
};
use crate::synchronizer::Synchronizer;
use crate::timer::Timer;
use async_recursion::async_recursion;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, error, info, warn};
// use serde::ser::SerializeTuple;
use serde::{Deserialize, Serialize};
// use std::collections::VecDeque;
// use std::io::Read;
// use std::process::Output;
use store::Store;
use threshold_crypto::PublicKeySet;
use tokio::sync::mpsc::{Receiver, Sender};
// use tokio::time::{sleep, Duration};

#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub type SeqNumber = u64; // For both round and view
pub type HeightNumber = u8; // height={1,2} in fallback chain, height=0 for sync block
pub type Bool = u8;

pub const RBC_ECHO: u8 = 0;
pub const RBC_READY: u8 = 1;

pub const VAL_PHASE: u8 = 0;
pub const MUX_PHASE: u8 = 1;

pub const OPT: u8 = 0;
pub const PES: u8 = 1;

#[derive(Serialize, Deserialize, Debug)]
pub enum ConsensusMessage {
    RBCValMsg(Block),
    RBCEchoMsg(EchoVote),
    RBCReadyMsg(ReadyVote),
    ABAValMsg(ABAVal),
    ABACoinShareMsg(RandomnessShare),
    ABAOutputMsg(ABAOutput),
    PrePareMsg(Prepare),
    LoopBackMsg(Block),
    SyncRequestMsg(Digest, PublicKey),
    SyncReplyMsg(Block),
}

pub struct Core {
    name: PublicKey,
    committee: Committee,
    parameters: Parameters,
    store: Store,
    signature_service: SignatureService,
    pk_set: PublicKeySet,
    mempool_driver: MempoolDriver,
    synchronizer: Synchronizer,
    core_channel: Receiver<ConsensusMessage>,
    network_filter: Sender<FilterInput>,
    commit_channel: Sender<Block>,
    epoch: SeqNumber,
    height: SeqNumber,
    timer: Timer,
    aggregator: Aggregator,
    commitor: Commitor,
    rank_to_digest: HashMap<usize, Digest>,
    rbc_proofs: HashMap<(SeqNumber, SeqNumber, u8), RBCProof>,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        signature_service: SignatureService,
        pk_set: PublicKeySet,
        store: Store,
        mempool_driver: MempoolDriver,
        synchronizer: Synchronizer,
        core_channel: Receiver<ConsensusMessage>,
        network_filter: Sender<FilterInput>,
        commit_channel: Sender<Block>,
    ) -> Self {
        let aggregator = Aggregator::new(committee.clone());
        let timer = Timer::new(parameters.timeout_delay);
        let commitor = Commitor::new(commit_channel.clone(), &committee);
        Self {
            name,
            committee,
            parameters,
            signature_service,
            pk_set,
            store,
            mempool_driver,
            synchronizer,
            network_filter,
            commit_channel,
            core_channel,
            epoch: 0,
            height: committee.id(name) as u64,
            timer,
            aggregator,
            commitor,
            rank_to_digest: HashMap::new(),
            rbc_proofs: HashMap::new(),
        }
    }

    async fn store_block(&mut self, block: &Block) {
        let key = block.digest().to_vec();
        let value = bincode::serialize(block).expect("Failed to serialize block");
        self.store.write(key, value).await;
    }

    // async fn commit(&mut self, block: Block) -> ConsensusResult<()> {
    //     //防止分叉提交
    //     if self.last_committed_round >= block.round {
    //         return Ok(());
    //     }

    //     let mut to_commit = VecDeque::new();
    //     to_commit.push_back(block.clone());

    //     // Ensure we commit the entire chain. This is needed after view-change.
    //     let mut parent = block.clone();
    //     while self.last_committed_round + 1 < parent.round {
    //         let ancestor = self
    //             .synchronizer
    //             .get_parent_block(&parent)
    //             .await?
    //             .expect("We should have all the ancestors by now");
    //         to_commit.push_front(ancestor.clone());
    //         parent = ancestor;
    //     }

    //     // Save the last committed block.
    //     self.last_committed_round = block.round;

    //     // Send all the newly committed blocks to the node's application layer.
    //     while let Some(block) = to_commit.pop_back() {
    //         if !block.payload.is_empty() {
    //             info!("Committed {}", block);

    //             #[cfg(feature = "benchmark")]
    //             for x in &block.payload {
    //                 // NOTE: This log entry is used to compute performance.
    //                 info!("Committed B{}({})", block.round, base64::encode(x));
    //             }
    //         }
    //         debug!("Committed {:?}", block);
    //         if let Err(e) = self.commit_channel.send(block).await {
    //             warn!("Failed to send block through the commit channel: {}", e);
    //         }
    //     }
    //     Ok(())
    // }
    // -- End Safety Module --

    #[async_recursion]
    async fn generate_proposal(&mut self) -> ConsensusResult<Block> {
        // Make a new block.
        let payload = self
            .mempool_driver
            .get(self.parameters.max_payload_size)
            .await;
        let block = Block::new(
            self.name,
            self.epoch,
            self.height,
            payload,
            self.signature_service.clone(),
        )
        .await;
        if !block.payload.is_empty() {
            info!("Created {}", block);

            #[cfg(feature = "benchmark")]
            for x in &block.payload {
                // NOTE: This log entry is used to compute performance.
                info!("Created B{}({})", block.round, base64::encode(x));
            }
        }
        debug!("Created {:?}", block);

        // // Process our new block and broadcast it.
        // let message = ConsensusMessage::Propose(block.clone());
        // Synchronizer::transmit(
        //     message,
        //     &self.name,
        //     None,
        //     &self.network_filter,
        //     &self.committee,
        // )
        // .await?;
        // self.process_block(&block).await?;

        // // Wait for the minimum block delay.
        // sleep(Duration::from_millis(self.parameters.min_block_delay)).await;
        Ok(block)
    }

    async fn handle_sync_request(
        &mut self,
        digest: Digest,
        sender: PublicKey,
    ) -> ConsensusResult<()> {
        if let Some(bytes) = self.store.read(digest.to_vec()).await? {
            let block = bincode::deserialize(&bytes)?;
            let message = ConsensusMessage::SyncReplyMsg(block);
            Synchronizer::transmit(
                message,
                &self.name,
                Some(&sender),
                &self.network_filter,
                &self.committee,
            )
            .await?;
        }
        Ok(())
    }

    /************* RBC Protocol ******************/

    async fn handle_rbc_val(&mut self, block: &Block) -> ConsensusResult<()> {
        Ok(())
    }

    async fn handle_rbc_echo(&mut self, vote: &EchoVote) -> ConsensusResult<()> {
        Ok(())
    }

    async fn handle_rbc_ready(&mut self, vote: &ReadyVote) -> ConsensusResult<()> {
        Ok(())
    }

    /************* RBC Protocol ******************/

    /************* PrePare Protocol ******************/
    async fn handle_prepare(&mut self, prepare: &Prepare) -> ConsensusResult<()> {
        Ok(())
    }
    /************* PrePare Protocol ******************/

    /************* ABA Protocol ******************/
    async fn handle_aba_val(&mut self, val: &ABAVal) -> ConsensusResult<()> {
        Ok(())
    }

    async fn handle_aba_share(&mut self, share: &RandomnessShare) -> ConsensusResult<()> {
        Ok(())
    }

    async fn handle_aba_output(&mut self, output: &ABAOutput) -> ConsensusResult<()> {
        Ok(())
    }
    /************* ABA Protocol ******************/

    pub async fn run(&mut self) {
        // // Upon booting, generate the very first block (if we are the leader).
        // // Also, schedule a timer in case we don't hear from the leader.
        // self.timer.reset();
        // if self.name == self.leader_elector.get_leader(self.round) {
        //     //如果是leader就发送propose
        //     self.generate_proposal(None)
        //         .await
        //         .expect("Failed to send the first block");
        // }

        // This is the main loop: it processes incoming blocks and votes,
        // and receive timeout notifications from our Timeout Manager.
        loop {
            let result = tokio::select! {
                Some(message) = self.core_channel.recv() => {
                    match message {
                        ConsensusMessage::RBCValMsg(block)=> self.handle_rbc_val(&block).await,
                        ConsensusMessage::RBCEchoMsg(evote)=> self.handle_rbc_echo(&evote).await,
                        ConsensusMessage::RBCReadyMsg(rvote)=> self.handle_rbc_ready(&rvote).await,
                        ConsensusMessage::ABAValMsg(val)=>self.handle_aba_val(&val).await,
                        ConsensusMessage::ABACoinShareMsg(share)=>self.handle_aba_share(&share).await,
                        ConsensusMessage::ABAOutputMsg(output)=>self.handle_aba_output(&output).await,
                        ConsensusMessage::PrePareMsg(prepare)=>self.handle_prepare(&prepare).await,
                        ConsensusMessage::LoopBackMsg(block) => self.handle_rbc_val(&block).await,  //有问题/////////////////
                        ConsensusMessage::SyncRequestMsg(digest, sender) => self.handle_sync_request(digest, sender).await,//收到其他节点请求区块
                        ConsensusMessage::SyncReplyMsg(block) => self.handle_rbc_val(&block).await,   //收到区块后存储
                    }
                },
                else => break,
            };
            match result {
                Ok(()) => (),
                Err(ConsensusError::StoreError(e)) => error!("{}", e),
                Err(ConsensusError::SerializationError(e)) => error!("Store corrupted. {}", e),
                Err(e) => warn!("{}", e),
            }
        }
    }
}
