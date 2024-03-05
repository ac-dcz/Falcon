use std::usize;

use crate::config::Committee;
use crate::Block;
use tokio::sync::mpsc::{channel, Receiver, Sender};
#[cfg(test)]
#[path = "tests/timer_tests.rs"]
pub mod timer_tests;

pub const MAX_BLOCK_BUFFER: usize = 100000;

fn try_to_commit(
    mut cur_ind: usize,
    buffer: &mut Vec<Option<Block>>,
    filter: &mut Vec<bool>,
    tx_commit: Sender<Block>,
) -> usize {
    let mut data = Vec::new();
    loop {
        if let Some(block) = buffer[cur_ind] {
            data.push(block);
            buffer[cur_ind] = None;
            cur_ind = (cur_ind + 1) % MAX_BLOCK_BUFFER
        } else if filter[cur_ind] {
            filter[cur_ind] = false;
            cur_ind = (cur_ind + 1) % MAX_BLOCK_BUFFER
        } else {
            break;
        }
    }

    for block in data {
        //提交 Block
    }

    cur_ind
}

pub struct Commitor {
    tx_block: Sender<Block>,
    tx_filter: Sender<usize>,
}

impl Commitor {
    pub fn new(tx_commit: Sender<Block>, committee: &Committee) -> Self {
        // cur_indx: usize,
        // buffer: Vec<Option<Block>>,
        // filter: Vec<bool>,
        let (tx_block, rx_block): (_, Receiver<Block>) = channel(10000);
        let (tx_filter, rx_filter): (_, Receiver<usize>) = channel(10000);

        tokio::spawn(async move {
            let mut cur_ind = 0;
            let mut buffer: Vec<Option<Block>> = Vec::with_capacity(MAX_BLOCK_BUFFER);
            let mut filter: Vec<bool> = Vec::with_capacity(MAX_BLOCK_BUFFER);
            for i in 0..MAX_BLOCK_BUFFER {
                buffer.push(None);
                filter.push(false);
            }
            loop {
                tokio::select! {
                    Some(block) = rx_block.recv()=>{
                        let rank = block.rank(committee);
                        if let Some(_) = buffer[rank]{
                            //速率过快 错误处理 增大Buffer
                        }
                        buffer[rank] = Some(block);

                        //try to commit
                        cur_ind = try_to_commit(cur_ind, &mut buffer, &mut filter, tx_commit.clone());
                    }
                    Some(ind) = rx_filter.recv()=>{
                        if filter[ind]{
                            //速率过快 错误处理 增大Buffer
                        }
                        filter[ind]=true;

                        //try to commit
                        cur_ind = try_to_commit(cur_ind, &mut buffer, &mut filter, tx_commit.clone());
                    }
                }
            }
        });

        Self {
            tx_block,
            tx_filter,
        }
    }

    pub async fn buffer_block(&self, block: Block) {
        if let Err(e) = self.tx_block.send(block).await {
            panic!("Failed to send block to commiter core: {}", e);
        }
    }

    pub async fn filter_block(&self, ind: usize) {
        if let Err(e) = self.tx_filter.send(ind).await {
            panic!("Failed to filter block to commiter core: {}", e);
        }
    }
}
