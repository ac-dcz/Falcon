use crate::Block;
use tokio::sync::mpsc::{Receiver, Sender};

#[cfg(test)]
#[path = "tests/timer_tests.rs"]
pub mod timer_tests;

pub const MAX_BLOCK_BUFFER: usize = 100000;

pub struct Committer {
    cur_indx: usize,
    buffer: Vec<Block>,
}

impl Committer {
    pub fn new(rx_block: Receiver<Block>, tx_commit: Sender<Block>) -> Self {}
}
