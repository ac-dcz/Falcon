use crate::config::Committee;
use crate::core::{ConsensusMessage, Core};
use crate::error::ConsensusResult;
use crate::filter::FilterInput;
use crate::{Block, SeqNumber};
use crypto::PublicKey;
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use log::{debug, error, info};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

#[cfg(test)]
#[path = "tests/synchronizer_tests.rs"]
pub mod synchronizer_tests;

const TIMER_ACCURACY: u64 = 5_000;

pub struct Synchronizer {
    store: Store,
    inner_channel: Sender<(SeqNumber, SeqNumber)>,
}

impl Synchronizer {
    pub async fn new(
        name: PublicKey,
        committee: Committee,
        store: Store,
        network_filter: Sender<FilterInput>,
        core_channel: Sender<ConsensusMessage>,
        sync_retry_delay: u64,
    ) -> Self {
        let (tx_inner, mut rx_inner): (_, Receiver<(SeqNumber, SeqNumber)>) = channel(10000);

        let store_copy = store.clone();
        tokio::spawn(async move {
            let mut waiting = FuturesUnordered::new();
            let mut pending = HashSet::new();
            let mut requests = HashMap::new();

            let timer = sleep(Duration::from_millis(TIMER_ACCURACY));
            tokio::pin!(timer);
            loop {
                tokio::select! {
                    Some((epoch,height)) = rx_inner.recv() => {
                        if pending.insert((epoch,height)) {

                            let fut = Self::waiter(store_copy.clone(),epoch,height,&committee);
                            waiting.push(fut);

                            if !requests.contains_key(&(epoch,height)){
                                debug!("Requesting sync for block epoch {}, height {}", epoch,height);
                                let now = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("Failed to measure time")
                                    .as_millis();
                                requests.insert((epoch,height), now);
                                let message = ConsensusMessage::SyncRequestMsg(epoch,height, name);
                                Self::transmit(message, &name, None, &network_filter, &committee).await.unwrap();
                            }
                        }
                    },
                    Some(result) = waiting.next() => match result {
                        Ok((epoch,height)) => {
                            debug!("consensus sync loopback");
                            let _ = pending.remove(&(epoch,height));
                            let _ = requests.remove(&(epoch,height));/////////////////?
                            let message = ConsensusMessage::LoopBackMsg(epoch,height);
                            if let Err(e) = core_channel.send(message).await {
                                panic!("Failed to send message through core channel: {}", e);
                            }
                        },
                        Err(e) => error!("{}", e)
                    },
                    () = &mut timer => {
                        // This implements the 'perfect point to point link' abstraction.
                        for ((epoch,height), timestamp) in &requests {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("Failed to measure time")
                                .as_millis();
                            if timestamp + (sync_retry_delay as u128) < now {
                                debug!("Requesting sync for block epoch {}, height {}", epoch,height);
                                let message = ConsensusMessage::SyncRequestMsg(*epoch,*height, name);///////////////?
                                Self::transmit(message, &name, None, &network_filter, &committee).await.unwrap();
                            }
                        }
                        timer.as_mut().reset(Instant::now() + Duration::from_millis(TIMER_ACCURACY));
                    },
                    else => break,
                }
            }
        });
        Self {
            store,
            inner_channel: tx_inner,
        }
    }

    async fn waiter(
        mut store: Store,
        epoch: SeqNumber,
        height: SeqNumber,
        committee: &Committee,
    ) -> ConsensusResult<(SeqNumber, SeqNumber)> {
        let key = Core::rank(epoch, height, committee);
        let _ = store.notify_read(key.to_le_bytes().into()).await?;
        Ok((epoch, height))
    }

    pub async fn transmit(
        message: ConsensusMessage,
        from: &PublicKey,
        to: Option<&PublicKey>,
        network_filter: &Sender<FilterInput>,
        committee: &Committee,
    ) -> ConsensusResult<()> {
        let addresses = if let Some(to) = to {
            debug!("Sending {:?} to {}", message, to);
            vec![committee.address(to)?]
        } else {
            debug!("Broadcasting {:?}", message);
            committee.broadcast_addresses(from)
        };
        if let Err(e) = network_filter.send((message, addresses)).await {
            panic!("Failed to send block through network channel: {}", e);
        }
        Ok(())
    }

    pub async fn block_request(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
        committee: &Committee,
    ) -> ConsensusResult<Option<Block>> {
        let key = Core::rank(epoch, height, committee);
        return match self.store.read(key.to_le_bytes().into()).await? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => {
                //如果没有 向其他节点发送request
                info!("block request epoch {} height {}", epoch, height);
                if let Err(e) = self.inner_channel.send((epoch, height)).await {
                    panic!("Failed to send request to synchronizer: {}", e);
                }
                Ok(None)
            }
        };
    }
}
