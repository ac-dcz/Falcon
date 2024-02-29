use crate::commiter::MAX_BLOCK_BUFFER;
use crate::config::{Committee, Stake};
use crate::core::SeqNumber;
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::RandomnessShare;
use crypto::PublicKey;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryInto;
use threshold_crypto::PublicKeySet;

#[cfg(test)]
#[path = "tests/aggregator_tests.rs"]
pub mod aggregator_tests;

// In HotStuff, votes/timeouts aggregated by round
// In VABA and async fallback, votes aggregated by round, timeouts/coin_share aggregated by view
pub struct Aggregator {
    committee: Committee,
    sharecoin_aggregators: HashMap<(SeqNumber, SeqNumber, SeqNumber), Box<RandomCoinMaker>>,
}

impl Aggregator {
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            sharecoin_aggregators: HashMap::new(),
        }
    }

    pub fn add_aba_share_coin(
        &mut self,
        share: RandomnessShare,
        pk_set: &PublicKeySet,
    ) -> ConsensusResult<Option<usize>> {
        self.sharecoin_aggregators
            .entry((share.epoch, share.height, share.round))
            .or_insert_with(|| Box::new(RandomCoinMaker::new()))
            .append(share, &self.committee, pk_set)
    }

    pub fn cleanup_aba_share_coin(&mut self, epoch: &SeqNumber, height: &SeqNumber) {
        self.sharecoin_aggregators.retain(|(e, h, _), _| {
            e * (MAX_BLOCK_BUFFER as u64) + h >= epoch * (MAX_BLOCK_BUFFER as u64) + height
        });
    }
}

struct RandomCoinMaker {
    weight: Stake,
    shares: Vec<RandomnessShare>,
    used: HashSet<PublicKey>,
}

impl RandomCoinMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            shares: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(
        &mut self,
        share: RandomnessShare,
        committee: &Committee,
        pk_set: &PublicKeySet,
    ) -> ConsensusResult<Option<usize>> {
        let author = share.author;
        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuseinCoin(author)
        );
        self.shares.push(share.clone());
        self.weight += committee.stake(&author);
        if self.weight == committee.random_coin_threshold() {
            // self.weight = 0; // Ensures QC is only made once.
            let mut sigs = BTreeMap::new();
            // Check the random shares.
            for share in self.shares.clone() {
                sigs.insert(
                    committee.id(share.author.clone()),
                    share.signature_share.clone(),
                );
            }
            if let Ok(sig) = pk_set.combine_signatures(sigs.iter()) {
                let id = usize::from_be_bytes((&sig.to_bytes()[0..8]).try_into().unwrap()) % 2;

                return Ok(Some(id));
            }
        }
        Ok(None)
    }
}
