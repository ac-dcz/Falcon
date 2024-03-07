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
use async_recursion::async_recursion;
use crypto::{Digest, PublicKey, SignatureService};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
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
    ABAMuxMsg(ABAVal),
    ABACoinShareMsg(RandomnessShare),
    ABAOutputMsg(ABAOutput),
    PrePareMsg(Prepare),
    LoopBackMsg(SeqNumber, SeqNumber),
    SyncRequestMsg(SeqNumber, SeqNumber, PublicKey),
    SyncReplyMsg(Block),
    RBCTimeDelay(SeqNumber),
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
    tx_core: Sender<ConsensusMessage>,
    rx_core: Receiver<ConsensusMessage>,
    network_filter: Sender<FilterInput>,
    _commit_channel: Sender<Block>,
    rx_commit: Receiver<(Vec<Digest>, SeqNumber, SeqNumber)>,
    epoch: SeqNumber,
    height: SeqNumber,
    aggregator: Aggregator,
    commitor: Commitor,
    buffers: HashMap<(SeqNumber, SeqNumber), bool>,
    rbc_proofs: HashMap<(SeqNumber, SeqNumber, u8), RBCProof>, //需要update
    rbc_ready: HashSet<(SeqNumber, SeqNumber)>,
    rbc_outputs: HashMap<(SeqNumber, SeqNumber), bool>,
    prepare_flags: HashSet<(SeqNumber, SeqNumber)>,
    aba_values: HashMap<(SeqNumber, SeqNumber, SeqNumber), [HashSet<PublicKey>; 2]>,
    aba_values_flag: HashMap<(SeqNumber, SeqNumber, SeqNumber), [bool; 2]>,
    aba_mux_values: HashMap<(SeqNumber, SeqNumber, SeqNumber), [HashSet<PublicKey>; 2]>,
    aba_mux_flags: HashMap<(SeqNumber, SeqNumber, SeqNumber), [bool; 2]>,
    aba_outputs: HashMap<(SeqNumber, SeqNumber, SeqNumber), HashSet<PublicKey>>,
    aba_ends: HashMap<(SeqNumber, SeqNumber), bool>,
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
        tx_core: Sender<ConsensusMessage>,
        rx_core: Receiver<ConsensusMessage>,
        network_filter: Sender<FilterInput>,
        commit_channel: Sender<Block>,
    ) -> Self {
        let (tx_commit, rx_commit) = channel(10000);
        let aggregator = Aggregator::new(committee.clone());
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
            _commit_channel: commit_channel,
            tx_core,
            rx_core,
            aggregator,
            commitor,
            buffers: HashMap::new(),
            rbc_proofs: HashMap::new(),
            rbc_ready: HashSet::new(),
            rbc_outputs: HashMap::new(),
            prepare_flags: HashSet::new(),
            aba_values: HashMap::new(),
            aba_mux_values: HashMap::new(),
            aba_values_flag: HashMap::new(),
            aba_mux_flags: HashMap::new(),
            aba_outputs: HashMap::new(),
            aba_ends: HashMap::new(),
        }
    }

    async fn delay_rbc_time(epoch: SeqNumber, time_out: SeqNumber) -> SeqNumber {
        sleep(Duration::from_millis(time_out)).await;
        epoch
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

    async fn cleanup(
        &mut self,
        digest: Vec<Digest>,
        epoch: SeqNumber,
        height: SeqNumber,
    ) -> ConsensusResult<()> {
        let size = self.committee.size() as SeqNumber;
        let rank = epoch * size + height;
        self.aggregator.cleanup(epoch, height);
        self.mempool_driver.cleanup(digest, epoch, height).await;
        self.buffers.retain(|(e, h, ..), _| e * size + h > rank);
        self.rbc_proofs.retain(|(e, h, ..), _| e * size + h > rank);
        self.rbc_ready.retain(|(e, h)| e * size + h > rank);
        // self.rbc_outputs.retain(|(e, h, ..), _| e * size + h > rank);
        // self.prepare_flags.retain(|(e, h), _| e * size + h > rank);
        self.aba_values.retain(|(e, h, ..), _| e * size + h > rank);
        self.aba_mux_values
            .retain(|(e, h, ..), _| e * size + h > rank);
        self.aba_values_flag
            .retain(|(e, h, ..), _| e * size + h > rank);
        self.aba_mux_flags
            .retain(|(e, h, ..), _| e * size + h > rank);
        // self.aba_outputs.retain(|(e, h, ..), _| e * size + h > rank);
        // self.aba_ends.retain(|(e, h, ..), _| e * size + h > rank);
        Ok(())
    }

    async fn handle_sync_request(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
        sender: PublicKey,
    ) -> ConsensusResult<()> {
        debug!("processing sync request epoch {} height {}", epoch, height);
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
        debug!(
            "processing sync reply epoch {} height {}",
            block.epoch, block.height
        );
        block.verify(&self.committee)?;
        self.store_block(block).await;
        self.process_rbc_output(block.epoch, block.height).await?;
        Ok(())
    }

    /************* RBC Protocol ******************/
    #[async_recursion]
    async fn generate_rbc_proposal(&mut self) -> ConsensusResult<Block> {
        // Make a new block.
        debug!("start rbc epoch {}", self.epoch);
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
                info!(
                    "Created B{}({}) epoch {}",
                    block.height,
                    base64::encode(x),
                    block.epoch
                );
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
        debug!(
            "processing RBC val epoch {} height {}",
            block.epoch, block.height
        );
        block.verify(&self.committee)?;
        self.store_block(block).await;

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
        debug!(
            "processing RBC echo_vote epoch {} height {}",
            vote.epoch, vote.height
        );
        vote.verify(&self.committee)?;

        if let Some(proof) = self.aggregator.add_rbc_echo_vote(vote.clone())? {
            self.rbc_proofs
                .insert((proof.epoch, proof.height, proof.tag), proof);
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
        }

        Ok(())
    }

    #[async_recursion]
    async fn handle_rbc_ready(&mut self, vote: &ReadyVote) -> ConsensusResult<()> {
        debug!(
            "processing RBC ready_vote epoch {} height {}",
            vote.epoch, vote.height
        );
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
            if proof.votes.len() as Stake == self.committee.quorum_threshold() {
                self.process_rbc_output(vote.epoch, vote.height).await?;
                self.invoke_prepare(vote.epoch, vote.height, OPT).await?;
                if proof.height == self.height {
                    self.rbc_advance(proof.epoch + 1).await?
                }
            }
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
        debug!("processing RBC output epoch {} height {}", epoch, height);
        if *self.rbc_outputs.entry((epoch, height)).or_insert(false) {
            return Ok(());
        }
        if let Some(block) = self
            .synchronizer
            .block_request(epoch, height, &self.committee)
            .await?
        {
            if !self.mempool_driver.verify(block.clone()).await? {
                return Ok(());
            }
            self.rbc_outputs.insert((epoch, height), true);
            self.commitor.buffer_block(block.clone()).await;
        }
        Ok(())
    }

    async fn rbc_advance(&mut self, epoch: SeqNumber) -> ConsensusResult<()> {
        if epoch > self.epoch {
            self.epoch = epoch;
            //清除之前的缓存
            self.generate_rbc_proposal().await?; //继续下一轮发送
            let message = ConsensusMessage::RBCTimeDelay(self.epoch);
            if let Err(e) = self.tx_core.send(message).await {
                panic!("Failed to send ConsensusMessage to core: {}", e);
            }
        }
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
        if self.prepare_flags.insert((epoch, height)) {
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
        }
        Ok(())
    }

    async fn handle_prepare(&mut self, prepare: &Prepare) -> ConsensusResult<()> {
        debug!(
            "processing prepare epoch {} height {}",
            prepare.epoch, prepare.height
        );
        prepare.verify(&self.committee)?;
        if let Some((val, flag)) = self.aggregator.add_prepare_vote(prepare.clone())? {
            debug!("prepare=> val {}", val);
            if flag {
                //可以直接提交
                self.process_rbc_output(prepare.epoch, prepare.height)
                    .await?;
            } else {
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
        }
        Ok(())
    }
    /************* PrePare Protocol ******************/

    /************* ABA Protocol ******************/
    #[async_recursion]
    async fn handle_aba_val(&mut self, aba_val: &ABAVal) -> ConsensusResult<()> {
        debug!(
            "processing aba val epoch {} height {}",
            aba_val.epoch, aba_val.height
        );

        aba_val.verify()?;

        let values = self
            .aba_values
            .entry((aba_val.epoch, aba_val.height, aba_val.round))
            .or_insert([HashSet::new(), HashSet::new()]);

        if values[aba_val.val].insert(aba_val.author) {
            let mut nums = values[aba_val.val].len() as Stake;
            if nums == self.committee.random_coin_threshold()
                && !values[aba_val.val].contains(&self.name)
            {
                //f+1
                let other = ABAVal::new(
                    self.name,
                    aba_val.epoch,
                    aba_val.height,
                    aba_val.round,
                    aba_val.val,
                    VAL_PHASE,
                    self.signature_service.clone(),
                )
                .await;
                let message = ConsensusMessage::ABAValMsg(other);
                Synchronizer::transmit(
                    message,
                    &self.name,
                    None,
                    &self.network_filter,
                    &self.committee,
                )
                .await?;
                values[aba_val.val].insert(self.name);
                nums += 1;
            }

            if nums == self.committee.quorum_threshold() {
                let values_flag = self
                    .aba_values_flag
                    .entry((aba_val.epoch, aba_val.height, aba_val.round))
                    .or_insert([false, false]);

                if !values_flag[0] && !values_flag[1] {
                    values_flag[aba_val.val] = true;
                    let mux = ABAVal::new(
                        self.name,
                        aba_val.epoch,
                        aba_val.height,
                        aba_val.round,
                        aba_val.val,
                        MUX_PHASE,
                        self.signature_service.clone(),
                    )
                    .await;
                    let message = ConsensusMessage::ABAMuxMsg(mux.clone());
                    Synchronizer::transmit(
                        message,
                        &self.name,
                        None,
                        &self.network_filter,
                        &self.committee,
                    )
                    .await?;
                    self.handle_aba_mux(&mux).await?;
                } else {
                    values_flag[aba_val.val] = true;
                }
            }
        }
        Ok(())
    }

    async fn handle_aba_mux(&mut self, aba_mux: &ABAVal) -> ConsensusResult<()> {
        debug!(
            "processing aba mux epoch {} height {}",
            aba_mux.epoch, aba_mux.height
        );
        aba_mux.verify()?;
        let values = self
            .aba_mux_values
            .entry((aba_mux.epoch, aba_mux.height, aba_mux.round))
            .or_insert([HashSet::new(), HashSet::new()]);
        if values[aba_mux.val].insert(aba_mux.author) {
            let mux_flags = self
                .aba_mux_flags
                .entry((aba_mux.epoch, aba_mux.height, aba_mux.round))
                .or_insert([false, false]);

            if !mux_flags[0] && !mux_flags[1] {
                let nums_opt = values[OPT as usize].len();
                let nums_pes = values[PES as usize].len();
                if nums_opt + nums_pes >= self.committee.quorum_threshold() as usize {
                    let value_flags = self
                        .aba_values_flag
                        .entry((aba_mux.epoch, aba_mux.height, aba_mux.round))
                        .or_insert([false, false]);
                    if value_flags[0] && value_flags[1] {
                        mux_flags[0] = nums_opt > 0;
                        mux_flags[1] = nums_pes > 1;
                    } else if value_flags[0] {
                        mux_flags[0] = nums_opt >= self.committee.quorum_threshold() as usize;
                    } else {
                        mux_flags[1] = nums_pes >= self.committee.quorum_threshold() as usize;
                    }
                }

                if mux_flags[0] || mux_flags[1] {
                    let share = RandomnessShare::new(
                        aba_mux.epoch,
                        aba_mux.height,
                        aba_mux.round,
                        self.name,
                        self.signature_service.clone(),
                    )
                    .await;
                    let message = ConsensusMessage::ABACoinShareMsg(share.clone());
                    Synchronizer::transmit(
                        message,
                        &self.name,
                        None,
                        &self.network_filter,
                        &self.committee,
                    )
                    .await?;
                    self.handle_aba_share(&share).await?;
                }
            }
        }

        Ok(())
    }

    async fn handle_aba_share(&mut self, share: &RandomnessShare) -> ConsensusResult<()> {
        debug!(
            "processing coin share epoch {} height {}",
            share.epoch, share.height
        );
        share.verify(&self.committee, &self.pk_set)?;
        if let Some(coin) = self
            .aggregator
            .add_aba_share_coin(share.clone(), &self.pk_set)?
        {
            let mux_flags = self
                .aba_mux_flags
                .entry((share.epoch, share.height, share.round))
                .or_insert([false, false]);
            let mut val = coin;
            if mux_flags[coin] && !mux_flags[coin ^ 1] {
                self.process_aba_output(share.epoch, share.height, share.round, coin)
                    .await?;
            } else if !mux_flags[coin] && mux_flags[coin ^ 1] {
                val = coin ^ 1;
            }
            self.aba_adcance_round(share.epoch, share.height, share.round + 1, val)
                .await?;
        }
        Ok(())
    }

    async fn handle_aba_output(&mut self, output: &ABAOutput) -> ConsensusResult<()> {
        debug!(
            "processing aba output epoch {} height {}",
            output.epoch, output.height
        );
        output.verify()?;
        let used = self
            .aba_outputs
            .entry((output.epoch, output.height, output.round))
            .or_insert(HashSet::new());
        if used.insert(output.author)
            && used.len() == self.committee.random_coin_threshold() as usize
        {
            if !used.contains(&self.name) {
                let output = ABAOutput::new(
                    self.name,
                    output.epoch,
                    output.height,
                    output.round,
                    output.val,
                    self.signature_service.clone(),
                )
                .await;
                let message = ConsensusMessage::ABAOutputMsg(output);
                Synchronizer::transmit(
                    message,
                    &self.name,
                    None,
                    &self.network_filter,
                    &self.committee,
                )
                .await?;
                used.insert(self.name);
            }
            self.process_aba_output(output.epoch, output.height, output.round, output.val)
                .await?;
        }

        Ok(())
    }

    async fn process_aba_output(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
        round: SeqNumber,
        val: usize,
    ) -> ConsensusResult<()> {
        info!("ABA(epoch {} height {}) end output({})", epoch, height, val);
        if *self.aba_ends.entry((epoch, height)).or_insert(false) {
            return Ok(());
        }
        let used = self
            .aba_outputs
            .entry((epoch, height, round))
            .or_insert(HashSet::new());
        if used.insert(self.name) {
            let output = ABAOutput::new(
                self.name,
                epoch,
                height,
                round,
                val,
                self.signature_service.clone(),
            )
            .await;
            let message = ConsensusMessage::ABAOutputMsg(output);
            Synchronizer::transmit(
                message,
                &self.name,
                None,
                &self.network_filter,
                &self.committee,
            )
            .await?;
        }

        self.aba_ends.insert((epoch, height), true);

        if val == OPT as usize {
            self.process_rbc_output(epoch, height).await?;
        } else {
            self.commitor
                .filter_block(Self::rank(epoch, height, &self.committee))
                .await;
        }

        Ok(())
    }

    async fn aba_adcance_round(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
        round: SeqNumber,
        val: usize,
    ) -> ConsensusResult<()> {
        if !*self.aba_ends.entry((epoch, height)).or_insert(false) {
            let aba_val = ABAVal::new(
                self.name,
                epoch,
                height,
                round,
                val,
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
    /************* ABA Protocol ******************/
    pub async fn run(&mut self) {
        let total_nums = self.committee.size() as SeqNumber;
        let mut pending_rbc = FuturesUnordered::new();
        if let Err(e) = self.generate_rbc_proposal().await {
            panic!("protocol invoke failed! error {}", e);
        }
        let message = ConsensusMessage::RBCTimeDelay(self.epoch);
        if let Err(e) = self.tx_core.send(message).await {
            panic!("Failed to send ConsensusMessage to core: {}", e);
        }
        loop {
            let result = tokio::select! {
                Some(message) = self.rx_core.recv() => {
                    match message {
                        ConsensusMessage::RBCValMsg(block)=> self.handle_rbc_val(&block).await,
                        ConsensusMessage::RBCEchoMsg(evote)=> self.handle_rbc_echo(&evote).await,
                        ConsensusMessage::RBCReadyMsg(rvote)=> self.handle_rbc_ready(&rvote).await,
                        ConsensusMessage::ABAValMsg(val)=>self.handle_aba_val(&val).await,
                        ConsensusMessage::ABAMuxMsg(mux)=> self.handle_aba_mux(&mux).await,
                        ConsensusMessage::ABACoinShareMsg(share)=>self.handle_aba_share(&share).await,
                        ConsensusMessage::ABAOutputMsg(output)=>self.handle_aba_output(&output).await,
                        ConsensusMessage::PrePareMsg(prepare)=>self.handle_prepare(&prepare).await,
                        ConsensusMessage::LoopBackMsg(epoch,height) => self.process_rbc_output(epoch,height).await,
                        ConsensusMessage::SyncRequestMsg(epoch,height, sender) => self.handle_sync_request(epoch,height, sender).await,
                        ConsensusMessage::SyncReplyMsg(block) => self.handle_sync_reply(&block).await,
                        ConsensusMessage::RBCTimeDelay(epoch) =>{
                            pending_rbc.push(Self::delay_rbc_time(epoch, self.parameters.timeout_delay));
                            Ok(())
                        }
                    }
                },
                Some((digest,epoch,height)) = self.rx_commit.recv()=>{
                    self.cleanup(digest,epoch,height).await
                },
                Some(epoch) = pending_rbc.next() =>{//超时处理
                    if !self.prepare_flags.contains(&(epoch,self.height)){
                        let _ = self.rbc_advance(epoch+1).await;
                    }
                    for height in 0..total_nums{
                        if !self.prepare_flags.contains(&(epoch,height)){
                            let _ =self.invoke_prepare(epoch, height, PES).await; ////?
                        }
                    }

                    Ok(())
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
