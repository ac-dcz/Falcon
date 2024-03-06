use std::collections::{HashMap, HashSet};

use crate::aggregator::Aggregator;
use crate::commitor::{Commitor, MAX_BLOCK_BUFFER};
use crate::config::{Committee, Parameters, Stake};
use crate::error::{ConsensusError, ConsensusResult};
use crate::filter::FilterInput;
use crate::mempool::MempoolDriver;
use crate::messages::{
    ABAOutput, ABAVal, Block, EchoVote, Prepare, RBCProof, RandomnessShare, ReadyVote,
};
use crate::synchronizer::Synchronizer;
use crate::timer::Timer;
use async_recursion::async_recursion;
use crypto::{PublicKey, SignatureService};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use store::Store;
use threshold_crypto::PublicKeySet;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::{sleep, Duration};
#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub type SeqNumber = u64; // For both round and view
pub type HeightNumber = u8; // height={1,2} in fallback chain, height=0 for sync block

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
    LoopBackMsg(SeqNumber, SeqNumber),
    SyncRequestMsg(SeqNumber, SeqNumber, PublicKey),
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
    rx_commit: Receiver<Block>,
    epoch: SeqNumber,
    height: SeqNumber,
    timer: Timer,
    aggregator: Aggregator,
    commitor: Commitor,
    buffers: HashMap<(SeqNumber, SeqNumber), bool>,
    rbc_blocks: HashMap<(SeqNumber, SeqNumber), Option<Block>>, //需要update
    rbc_proofs: HashMap<(SeqNumber, SeqNumber, u8), RBCProof>,  //需要update
    rbc_ready: HashSet<(SeqNumber, SeqNumber)>,
    rbc_outputs: HashMap<(SeqNumber, SeqNumber), bool>,
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
        let (tx_commit, rx_commit): (_, Receiver<Block>) = channel(10000);
        let aggregator = Aggregator::new(committee.clone());
        let timer = Timer::new(parameters.timeout_delay);
        let commitor = Commitor::new(tx_commit.clone(), committee.clone());
        Self {
            epoch: 0,
            height: committee.id(name) as u64,
            name,
            committee,
            parameters,
            signature_service,
            pk_set,
            store,
            mempool_driver,
            synchronizer,
            network_filter,
            rx_commit,
            commit_channel,
            core_channel,
            timer,
            aggregator,
            commitor,
            buffers: HashMap::new(),
            rbc_proofs: HashMap::new(),
            rbc_blocks: HashMap::new(),
            rbc_ready: HashSet::new(),
            rbc_outputs: HashMap::new(),
        }
    }

    pub fn rank(epoch: SeqNumber, height: SeqNumber, committee: &Committee) -> usize {
        let r = ((epoch as usize) * committee.size() + (height as usize)) % MAX_BLOCK_BUFFER;
        r
    }

    async fn store_block(&mut self, block: &Block) {
        self.buffers.insert((block.epoch, block.height), true);
        let key: Vec<u8> = block.rank(&self.committee).to_le_bytes().into();
        let value = bincode::serialize(block).expect("Failed to serialize block");
        self.store.write(key, value).await;
    }

    fn commit_block(&mut self, _block: &Block) -> ConsensusResult<()> {
        Ok(())
    }

    async fn handle_sync_request(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
        sender: PublicKey,
    ) -> ConsensusResult<()> {
        let rank = Core::rank(epoch, height, &self.committee);
        if let Some(bytes) = self.store.read(rank.to_le_bytes().into()).await? {
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

    async fn handle_sync_reply(&mut self, block: &Block) -> ConsensusResult<()> {
        block.verify(&self.committee)?;
        self.store_block(block).await;
        self.rbc_blocks
            .insert((block.epoch, block.height), Some(block.clone()));
        self.process_rbc_output(block.epoch, block.height).await?;
        Ok(())
    }

    /************* RBC Protocol ******************/
    #[async_recursion]
    async fn generate_rbc_proposal(&mut self) -> ConsensusResult<Block> {
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

        // Process our new block and broadcast it.
        let message = ConsensusMessage::RBCValMsg(block.clone());
        Synchronizer::transmit(
            message,
            &self.name,
            None,
            &self.network_filter,
            &self.committee,
        )
        .await?;
        self.handle_rbc_val(&block).await?;

        // Wait for the minimum block delay.
        sleep(Duration::from_millis(self.parameters.min_block_delay)).await;

        Ok(block)
    }

    async fn handle_rbc_val(&mut self, block: &Block) -> ConsensusResult<()> {
        block.verify(&self.committee)?;
        self.store_block(block).await;
        self.rbc_blocks
            .insert((block.epoch, block.height), Some(block.clone()));
        let vote = EchoVote::new(
            self.name,
            block.epoch,
            block.height,
            block,
            self.signature_service.clone(),
        )
        .await;
        let message = ConsensusMessage::RBCEchoMsg(vote.clone());

        Synchronizer::transmit(
            message,
            &self.name,
            None,
            &self.network_filter,
            &self.committee,
        )
        .await?;

        self.handle_rbc_echo(&vote).await?;
        Ok(())
    }

    async fn handle_rbc_echo(&mut self, vote: &EchoVote) -> ConsensusResult<()> {
        vote.verify(&self.committee)?;

        if let Some(proof) = self.aggregator.add_rbc_echo_vote(vote.clone())? {
            self.rbc_proofs
                .insert((proof.epoch, proof.height, proof.tag), proof);
            let ready = ReadyVote::new(
                self.name,
                vote.epoch,
                vote.height,
                vote.digest.clone(),
                self.signature_service.clone(),
            )
            .await;
            let message = ConsensusMessage::RBCReadyMsg(ready.clone());
            Synchronizer::transmit(
                message,
                &self.name,
                None,
                &self.network_filter,
                &self.committee,
            )
            .await?;
            self.handle_rbc_ready(&ready).await?;
        }

        Ok(())
    }

    #[async_recursion]
    async fn handle_rbc_ready(&mut self, vote: &ReadyVote) -> ConsensusResult<()> {
        vote.verify(&self.committee)?;

        if let Some(proof) = self.aggregator.add_rbc_ready_vote(vote.clone())? {
            let flag = self.rbc_ready.contains(&(vote.epoch, vote.height));

            self.rbc_proofs
                .insert((proof.epoch, proof.height, proof.tag), proof.clone());

            if !flag && proof.votes.len() as Stake == self.committee.random_coin_threshold() {
                self.rbc_ready.insert((vote.epoch, vote.height));
                let ready = ReadyVote::new(
                    self.name,
                    vote.epoch,
                    vote.height,
                    vote.digest.clone(),
                    self.signature_service.clone(),
                )
                .await;
                let message = ConsensusMessage::RBCReadyMsg(ready.clone());
                Synchronizer::transmit(
                    message,
                    &self.name,
                    None,
                    &self.network_filter,
                    &self.committee,
                )
                .await?;
                self.handle_rbc_ready(&ready).await?;
                return Ok(());
            }
            self.process_rbc_output(vote.epoch, vote.height).await?;
            self.invoke_prepare(vote.epoch, vote.height, OPT).await?;
            self.rbc_advance().await?
        }

        Ok(())
    }

    async fn process_rbc_output(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
    ) -> ConsensusResult<()> {
        //rbc 输出处理
        /*
           1. 是否收到RBC的输出？ 没有 => 发送request
           2. mempool是否收到了所有  payload？ 没有 => loopback
           3. 缓存入commitor
        */
        if *self.rbc_outputs.entry((epoch, height)).or_insert(false) {
            return Ok(());
        }
        if let Some(block) = self.rbc_blocks.entry((epoch, height)).or_insert(None) {
            if !self.mempool_driver.verify(block.clone()).await? {
                // debug!(
                //     "Processing of {} suspended: missing payload",
                //     block.digest()
                // );
                return Ok(());
            }
            self.rbc_outputs.insert((epoch, height), true);
            self.commitor.buffer_block(block.clone()).await;
        } else {
            self.synchronizer
                .block_request(epoch, height, &self.committee)
                .await?;
        }
        Ok(())
    }

    async fn rbc_advance(&mut self) -> ConsensusResult<()> {
        self.epoch += 1;
        self.generate_rbc_proposal().await?; //继续下一轮发送
                                             //清除之前的缓存
        Ok(())
    }

    /************* RBC Protocol ******************/

    /************* PrePare Protocol ******************/
    async fn invoke_prepare(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
        val: u8,
    ) -> ConsensusResult<()> {
        //启动prepare投票
        let prepare = Prepare::new(
            self.name,
            epoch,
            height,
            val,
            self.signature_service.clone(),
        )
        .await;
        let message = ConsensusMessage::PrePareMsg(prepare.clone());
        Synchronizer::transmit(
            message,
            &self.name,
            None,
            &self.network_filter,
            &self.committee,
        )
        .await?;
        self.handle_prepare(&prepare).await?;
        Ok(())
    }

    async fn handle_prepare(&mut self, prepare: &Prepare) -> ConsensusResult<()> {
        prepare.verify(&self.committee)?;
        if let Some((val, flag)) = self.aggregator.add_prepare_vote(prepare.clone())? {
            if flag {
                //可以直接提交
                self.process_rbc_output(prepare.epoch, prepare.height)
                    .await?;
            }
            //发送ABA
            let aba_val = ABAVal::new(
                self.name,
                prepare.epoch,
                prepare.height,
                0,
                val as usize,
                VAL_PHASE,
                self.signature_service.clone(),
            )
            .await;
            let message = ConsensusMessage::ABAValMsg(aba_val.clone());
            Synchronizer::transmit(
                message,
                &self.name,
                None,
                &self.network_filter,
                &self.committee,
            )
            .await?;
            self.handle_aba_val(&aba_val).await?;
        }
        Ok(())
    }
    /************* PrePare Protocol ******************/

    /************* ABA Protocol ******************/
    async fn handle_aba_val(&mut self, aba_val: &ABAVal) -> ConsensusResult<()> {
        Ok(())
    }

    async fn handle_aba_share(&mut self, share: &RandomnessShare) -> ConsensusResult<()> {
        share.verify(&self.committee, &self.pk_set)?;
        if let Some(_id) = self
            .aggregator
            .add_aba_share_coin(share.clone(), &self.pk_set)?
        {}
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
                        ConsensusMessage::LoopBackMsg(epoch,height) => self.process_rbc_output(epoch,height).await,  //有问题/////////////////
                        ConsensusMessage::SyncRequestMsg(epoch,height, sender) => self.handle_sync_request(epoch,height, sender).await,//收到其他节点请求区块
                        ConsensusMessage::SyncReplyMsg(block) => self.handle_sync_reply(&block).await,   //收到区块后存储
                    }
                },
                Some(block) = self.rx_commit.recv()=>{
                    self.commit_block(&block)
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
