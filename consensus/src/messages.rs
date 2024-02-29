use crate::commiter::MAX_BLOCK_BUFFER;
use crate::config::Committee;
use crate::core::{Bool, HeightNumber, SeqNumber};
use crate::error::{ConsensusError, ConsensusResult};
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::convert::TryInto;
use std::fmt;
use threshold_crypto::{PublicKeySet, SignatureShare};

#[cfg(test)]
#[path = "tests/messages_tests.rs"]
pub mod messages_tests;

// daniel: Add view, height, fallback in Block, Vote and QC
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Block {
    pub author: PublicKey,
    pub epoch: SeqNumber,  //
    pub height: SeqNumber, // author`s id
    pub payload: Vec<Digest>,
    pub signature: Signature,
}

impl Block {
    pub async fn new(
        author: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        payload: Vec<Digest>,
        mut signature_service: SignatureService,
    ) -> Self {
        let block = Self {
            author,
            epoch,
            height,
            payload,
            signature: Signature::default(),
        };

        let signature = signature_service.request_signature(block.digest()).await;
        Self { signature, ..block }
    }

    pub fn genesis() -> Self {
        Block::default()
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        Ok(())
    }

    // block`s rank
    pub fn rank(&self, committee: &Committee) -> usize {
        let r =
            ((self.epoch as usize) * committee.size() + (self.height as usize)) % MAX_BLOCK_BUFFER;
        r
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B(author {}, view {},  height {}, payload_len {})",
            self.digest(),
            self.author,
            self.epoch,
            self.height,
            self.payload.iter().map(|x| x.size()).sum::<usize>(),
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B(author {}, view {},  height {}, payload_len {})",
            self.digest(),
            self.author,
            self.epoch,
            self.height,
            self.payload.iter().map(|x| x.size()).sum::<usize>(),
        )
    }
}

/************************** RBC Struct ************************************/
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct EchoVote {}
impl fmt::Debug for EchoVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            // "{}: B(author {}, view {},  height {}, payload_len {})",
            // self.digest(),
            // self.author,
            // self.epoch,
            // self.height,
            // self.payload.iter().map(|x| x.size()).sum::<usize>(),
            ""
        )
    }
}
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct ReadyVote {}
impl fmt::Debug for ReadyVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            // "{}: B(author {}, view {},  height {}, payload_len {})",
            // self.digest(),
            // self.author,
            // self.epoch,
            // self.height,
            // self.payload.iter().map(|x| x.size()).sum::<usize>(),
            ""
        )
    }
}
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct RBCProof {}

/************************** RBC Struct ************************************/

/************************** prepare Struct ************************************/
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Prepare {}

impl fmt::Debug for Prepare {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            // "{}: B(author {}, view {},  height {}, payload_len {})",
            // self.digest(),
            // self.author,
            // self.epoch,
            // self.height,
            // self.payload.iter().map(|x| x.size()).sum::<usize>(),
            ""
        )
    }
}
/************************** pre-prepare Struct ************************************/

/************************** ABA Struct ************************************/
#[derive(Clone, Serialize, Deserialize)]
pub struct ABAVal {
    pub author: PublicKey,
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub round: SeqNumber, //ABA 的轮数
    pub phase: u8,        //ABA 的阶段（VAL，AUX）
    pub val: usize,
    pub signature: Signature,
}

impl ABAVal {
    pub async fn new(
        author: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        round: SeqNumber,
        val: usize,
        phase: u8,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut aba_val = Self {
            author,
            epoch,
            height,
            round,
            val,
            phase,
            signature: Signature::default(),
        };
        aba_val.signature = signature_service.request_signature(aba_val.digest()).await;
        return aba_val;
    }

    pub fn verify(&self) -> ConsensusResult<()> {
        self.signature.verify(&self.digest(), &self.author)?;
        Ok(())
    }
}

impl Hash for ABAVal {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for ABAVal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ABAVal(round {},phase {},val {})",
            self.round, self.phase, self.val
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ABAOutput {
    pub author: PublicKey,
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub round: SeqNumber,
    pub val: usize,
    pub signature: Signature,
}

impl ABAOutput {
    pub async fn new(
        author: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        round: SeqNumber,
        val: usize,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut out = Self {
            author,
            epoch,
            height,
            round,
            val,
            signature: Signature::default(),
        };
        out.signature = signature_service.request_signature(out.digest()).await;
        return out;
    }

    pub fn verify(&self) -> ConsensusResult<()> {
        self.signature.verify(&self.digest(), &self.author)?;
        Ok(())
    }
}

impl Hash for ABAOutput {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for ABAOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ABAOutput(author {},height {},round {},val {})",
            self.author, self.height, self.round, self.val
        )
    }
}

/************************** ABA Struct ************************************/

/************************** Share Coin Struct ************************************/
#[derive(Clone, Serialize, Deserialize)]
pub struct RandomnessShare {
    pub height: SeqNumber,
    pub epoch: SeqNumber,
    pub round: SeqNumber,
    pub author: PublicKey,
    pub signature_share: SignatureShare,
}

impl RandomnessShare {
    pub async fn new(
        height: SeqNumber,
        epoch: SeqNumber,
        round: SeqNumber,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(round.to_le_bytes());
        hasher.update(height.to_le_bytes());
        hasher.update(epoch.to_le_bytes());
        let digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());
        let signature_share = signature_service
            .request_tss_signature(digest)
            .await
            .unwrap();
        Self {
            round,
            height,
            epoch,
            author,
            signature_share,
        }
    }

    pub fn verify(&self, committee: &Committee, pk_set: &PublicKeySet) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        let tss_pk = pk_set.public_key_share(committee.id(self.author));
        // Check the signature.
        ensure!(
            tss_pk.verify(&self.signature_share, &self.digest()),
            ConsensusError::InvalidThresholdSignature(self.author)
        );

        Ok(())
    }
}

impl Hash for RandomnessShare {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for RandomnessShare {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "RandomnessShare (author {}, height {},round {})",
            self.author, self.height, self.round,
        )
    }
}
/************************** Share Coin Struct ************************************/
