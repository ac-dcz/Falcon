// use crate::config::Committee;
// use crate::core::{HeightNumber, SeqNumber};
// use crate::mempool::{ConsensusMempoolMessage, PayloadStatus};
// use crate::messages::{Block, EchoVote, ReadyVote};
// use crypto::Hash as _;
// use crypto::{generate_keypair, Digest, PublicKey, SecretKey, Signature};
// use rand::rngs::StdRng;
// use rand::RngCore as _;
// use rand::SeedableRng as _;
// use tokio::sync::mpsc::Receiver;

// // Fixture.
// pub fn keys() -> Vec<(PublicKey, SecretKey)> {
//     let mut rng = StdRng::from_seed([0; 32]);
//     (0..4).map(|_| generate_keypair(&mut rng)).collect()
// }

// // Fixture.
// pub fn committee() -> Committee {
//     Committee::new(
//         keys()
//             .into_iter()
//             .enumerate()
//             .map(|(i, (name, _))| {
//                 let address = format!("127.0.0.1:{}", i).parse().unwrap();
//                 let stake = 1;
//                 (name, 0, stake, address)
//             })
//             .collect(),
//         /* epoch */ 1,
//     )
// }

// impl Committee {
//     pub fn increment_base_port(&mut self, base_port: u16) {
//         for authority in self.authorities.values_mut() {
//             let port = authority.address.port();
//             authority.address.set_port(base_port + port);
//         }
//     }
// }

// impl Block {
//     pub fn new_from_key(
//         author: PublicKey,
//         epoch: SeqNumber,
//         height: SeqNumber,
//         payload: Vec<Digest>,
//         secret: &SecretKey,
//     ) -> Self {
//         let block = Block {
//             author,
//             epoch,
//             height,
//             payload,
//             signature: Signature::default(),
//         };
//         let signature = Signature::new(&block.digest(), secret);
//         Self { signature, ..block }
//     }
// }

// impl PartialEq for Block {
//     fn eq(&self, other: &Self) -> bool {
//         self.digest() == other.digest()
//     }
// }

// impl EchoVote {
//     pub fn new_from_key(
//         digest: Digest,
//         epoch: SeqNumber,
//         height: SeqNumber,
//         author: PublicKey,
//         secret: &SecretKey,
//     ) -> Self {
//         let vote = Self {
//             digest,
//             epoch,
//             height,
//             author,
//             signature: Signature::default(),
//         };
//         let signature = Signature::new(&vote.digest(), &secret);
//         Self { signature, ..vote }
//     }
// }

// impl PartialEq for EchoVote {
//     fn eq(&self, other: &Self) -> bool {
//         self.digest() == other.digest()
//     }
// }

// impl ReadyVote {
//     pub fn new_from_key(
//         digest: Digest,
//         epoch: SeqNumber,
//         height: SeqNumber,
//         author: PublicKey,
//         secret: &SecretKey,
//     ) -> Self {
//         let vote = Self {
//             digest,
//             epoch,
//             height,
//             author,
//             signature: Signature::default(),
//         };
//         let signature = Signature::new(&vote.digest(), &secret);
//         Self { signature, ..vote }
//     }
// }

// impl PartialEq for ReadyVote {
//     fn eq(&self, other: &Self) -> bool {
//         self.digest() == other.digest()
//     }
// }

// // Fixture.
// pub fn block() -> Block {
//     let (public_key, secret_key) = keys().pop().unwrap();
//     Block::new_from_key(public_key, 0, 0, Vec::new(), &secret_key)
// }

// // Fixture.
// pub fn echo_vote() -> EchoVote {
//     let (public_key, secret_key) = keys().pop().unwrap();
//     EchoVote::new_from_key(block().digest(), 0, 0, public_key, &secret_key)
// }

// pub fn ready_vote() -> ReadyVote {
//     let (public_key, secret_key) = keys().pop().unwrap();
//     ReadyVote::new_from_key(block().digest(), 0, 0, public_key, &secret_key)
// }

// // Fixture
// pub struct MockMempool;

// impl MockMempool {
//     pub fn run(mut consensus_mempool_channel: Receiver<ConsensusMempoolMessage>) {
//         tokio::spawn(async move {
//             while let Some(message) = consensus_mempool_channel.recv().await {
//                 match message {
//                     ConsensusMempoolMessage::Get(_max, sender) => {
//                         let mut rng = StdRng::from_seed([0; 32]);
//                         let mut payload = [0u8; 32];
//                         rng.fill_bytes(&mut payload);
//                         sender.send(vec![Digest(payload)]).unwrap();
//                     }
//                     ConsensusMempoolMessage::Verify(_block, sender) => {
//                         sender.send(PayloadStatus::Accept).unwrap()
//                     }
//                     ConsensusMempoolMessage::Cleanup(..) => (),
//                 }
//             }
//         });
//     }
// }
