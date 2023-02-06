// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! A basic chat application with logs demonstrating libp2p and the gossipsub protocol
//! combined with mDNS for the discovery of peers to gossip with.
//!
//! Using two terminal windows, start two instances, typing the following in each:
//!
//! ```sh
//! cargo run --example gossipsub-chat --features=full
//! ```
//!
//! Mutual mDNS discovery may take a few seconds. When each peer does discover the other
//! it will print a message like:
//!
//! ```sh
//! mDNS discovered a new peer: {peerId}
//! ```
//!
//! Type a message and hit return: the message is sent and printed in the other terminal.
//! Close with Ctrl-c.
//!
//! You can open more terminal windows and add more peers using the same line above.
//!
//! Once an additional peer is mDNS discovered it can participate in the conversation
//! and all peers will receive messages sent from it.
//!
//! If a participant exits (Control-C or otherwise) the other peers will receive an mDNS expired
//! event and remove the expired peer from the list of known peers.

use async_std::io::{stdin};
use futures::prelude::*;
use futures::{
    prelude::{stream::StreamExt, *},
    select,
};
use libp2p::gossipsub::{
    Gossipsub, GossipsubEvent, GossipsubMessage, IdentTopic as Topic, MessageAuthenticity,
    MessageId, ValidationMode,
};
use libp2p::identify;
use libp2p::ping;
use libp2p::swarm::keep_alive;
use libp2p::{gossipsub, identity, mdns, NetworkBehaviour, PeerId};
use libp2p::{
    swarm::{behaviour, Swarm, SwarmEvent},
    Multiaddr,
};
use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::time::Duration;

mod merkleTree;
mod nodes;
mod request;
mod storage;
use clap::Parser;

//TODO:
//Get Merkle Tree from File System#
// fn(path : string) -> MerkleTree
// Request -> Storage.getContent() -> Send File()
// Storage.get file from hash etc.

//Demo client program
// 1. node.exe - block://1231hasdha1jhd/ashxjasjh/index.html -o /temp/index.html
// 2. get 127.0.0.1:9000/1231hasdha1jhd/ashxjasjh/index.html
//  show content

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    listen_addr: Option<String>,

    /// Number of times to greet
    #[arg(short, long)]
    dial_addr: Option<String>,
}

fn test() -> Result<(), Box<dyn Error>> {
    let testfile = merkleTree::MerkleTreeHash::generate_from_path(Path::new("D:\\dev\\blockchainers\\testrustprogramm\\Node\\testFolder"))?;

    println!("Merkle Tree:");
    merkleTree::print_merkle_tree_hash(&testfile, 0);

    testfile.save(Path::new("D:\\dev\\blockchainers\\testrustprogramm\\Node\\testFolder\\ROOTHASH_Tree.json"))?;

    return Ok(());
}

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    test()?;
    return Ok(());
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(&local_key.public());
    println!("Local peer id: {local_peer_id:?}");

    let identity_config = identify::Config::new("/ipfs/id/1.0.0".to_string(), local_key.public());

    let transport = libp2p::development_transport(local_key).await?;

    let mut swarm = Swarm::new(transport, Behaviour::new(identity_config), local_peer_id);

    let mut listen_addr: String = "/ip4/0.0.0.0/tcp/0".to_string();
    if let Some(addr) = args.listen_addr {
        listen_addr = addr;
    }
    if let Some(addr) = args.dial_addr {
        let remote: Multiaddr = addr.parse()?;
        swarm.dial(remote)?;
        println!("Dialed {addr}");
    }

    swarm.listen_on(listen_addr.parse()?)?;
    //let addr = host.Addrs();

    // Tell the swarm to listen on all interfaces and a random, OS-assigned
    // port.
    //swarm.listen_on("/ip6/2001:9e8:e3f0:9f00:99c9:64e6:8205:d5c6/tcp/44400".parse()?)?;

    //swarm.listen_on("/ip6/2001:9e8:6014:3e81:3a10:d5ff:fe23:c8ce/tcp/44400".parse()?)?;

    // Dial the peer identified by the multi-address given as the second
    // command-line argument, if any.

    loop {
        select! {
            line =  stdin.select_next_some() => swarm
                .behaviour_mut()
                .floodsub
                .publish(floodsub_topic.clone(), line.expect("Stdin not to close").as_bytes()),
            event = swarm.select_next_some() => match event  {
            SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {address:?}"),
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Sent {
                peer_id,
                ..
            })) => {
                println!("Sent identify info to {:?}", peer_id)
            }
            // Prints out the info received via the identify event
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                info,
                ..
            })) => {
                println!("Received {:?}", info)
            }
            SwarmEvent::Behaviour(event) => println!("{event:?}"),
            _ => {}
        }
    }
    }
    Ok(())
}

/// Our network behaviour.
///
/// For illustrative purposes, this includes the [`KeepAlive`](behaviour::KeepAlive) behaviour so a continuous sequence of
/// pings can be observed.
#[derive(NetworkBehaviour)]
struct Behaviour {
    keep_alive: keep_alive::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
}

impl Behaviour {
    fn new(config: identify::Config) -> Behaviour {
        return Behaviour {
            keep_alive: keep_alive::Behaviour::default(),
            ping: ping::Behaviour::default(),
            identify: identify::Behaviour::new(config),
        };
    }
}
