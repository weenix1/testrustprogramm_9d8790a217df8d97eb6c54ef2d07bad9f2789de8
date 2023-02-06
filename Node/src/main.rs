
//#![allow(warnings)]

use indexmap::IndexSet;
use libp2p_core::{ Multiaddr, PeerId };
use nodes::HashVec;
use request::FileRequestBody;
use request::RequestError;
use std::collections::HashSet;

use std::collections::HashMap;
use std::env;
use std::fs;

mod client;
mod merkle_tree;
mod nodes;
mod request;
mod storage;
use clap::Parser;
mod rest_api;

use storage::*;
use nodes::*;
use client::*;
use fs_extra::dir::copy;
use fs_extra::dir::CopyOptions;

//TODO:
// Validation of Merkle Tree
// Domain Ads
//Upload butten

//Demo client program
// 1. node.exe - block://1231hasdha1jhd/ashxjasjh/index.html -o /temp/index.html
// 2. get 127.0.0.1:9000/1231hasdha1jhd/ashxjasjh/index.html
//  show content

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Listen Address
    #[arg(short, long)]
    listen_addr: Option<String>,

    /// Dial Address
    #[arg(short, long)]
    root_addr: Option<String>,

    /// Is this a proivider Node
    #[arg(short, long)]
    provider_node: bool,

    /// Is this a Root Node
    #[arg(short, long)]
    is_root_node: bool,

    /// Is this a DNS Node
    #[arg(short, long)]
    dns_node: bool,

    /// Is this a Client Test Node
    #[arg(short, long)]
    client_node: bool,
}


use thiserror::Error;

#[derive(Error, Debug)]
pub enum NodeError {
    #[error(transparent)]
    StorageError(#[from] StorageError),
    #[error("No Root Reference Found!")]
    NoRootReference,
    #[error("This is not a Root Node!")]
    NoRoot,
    #[error("This is not a DNS Node!")]
    NoDns,
    #[error("This is not a Provider Node!")]
    NoProvider,
    #[error(transparent)]
    RequestError(#[from] RequestError),

    #[error("{body}")]
    ResponseError{status_code : reqwest::StatusCode, body : String},
    #[error("No Provider Is Providing This Group!")]
    NoProviderIsProvidingThisGroup,
    #[error("The Container could not be found!")]
    ContainerCouldNotBeFound,

    //Client:
    #[error("The requested path had the Wrong hash!")]
    WrongHash,
    #[error("The Merkle Tree is Invalid!")]
    MerkleTreeInvalid,

    #[error(transparent)]
    Other(#[from] anyhow::Error),  // source and Display delegate to anyhow::Error

    //#[error(transparent)]
    //InternalRequestError(#[from] reqwest::Error),  // source and Display delegate to anyhow::Error
}

pub struct RootGroup {
    pub hash: HashVec,
    pub services: Vec<Service>,
    pub group_group: IndexSet<User>,
}
pub struct ContainerReference {
    pub container_id_reference: HashMap<HashVec, GroupId>,
    pub groups: HashMap<GroupId, RootGroup>,
}


pub struct PeerDnsReference {
    pub peer_id_reference: HashMap<PeerId, IndexSet<Multiaddr>>,
}

impl ContainerReference {
    fn get_group(&self, hash: &HashVec) -> Option<&RootGroup> {
        if let Some(index) = self.container_id_reference.get(hash) {
            return self.groups.get(index);
        }
        return None;
    }
}

pub struct ProvidingContainer {
    pub container: HashSet<HashVec>,
}

pub struct RootReference {
    pub roots: Vec<Node>,
}

pub struct MainLogic {
    //This User
    pub user : User,
    //Helper for Getting Files
    pub storage: Option<FileStorage>,

    pub container_dns: Option<ContainerReference>,

    pub peer_dns: Option<PeerDnsReference>,

    //Reference to Root Nodes
    pub root_reference: Option<RootReference>,

    //List of Container, this Node is providing
    pub providing_container: Option<ProvidingContainer>

}

async fn test_client(ml : &MainLogic, client : &Client) -> anyhow::Result<()>{
    let mut options = CopyOptions::new(); //Initialize default values for CopyOptions
    options.overwrite = true;
    copy(env::current_dir()?.join("testwebpage/build"), "testFolder", &options)?;
    

    //1. generate merkle Tree!
    let mt1 = merkle_tree::MerkleTreeHash::generate_from_path(&fs::canonicalize(env::current_dir()?.join("../StorageTestFolder/ImageStorage")).unwrap()).await?;
    client.client_publish_container(ml, mt1.hash , fs::canonicalize(env::current_dir()?.join("../StorageTestFolder/ImageStorage"))?).await?;
    //2. test publish data to a provider

    let mt2= merkle_tree::MerkleTreeHash::generate_from_path(&fs::canonicalize(env::current_dir()?.join("../StorageTestFolder/MainStorage"))?).await?;
    client.client_publish_container(ml, mt2.hash , fs::canonicalize(env::current_dir()?.join("../StorageTestFolder/MainStorage"))?).await?;


    //3. test get that data back
    client.client_get_file(ml, &FileRequestBody{ root_hash: mt2.hash, file: Some("website/index.html".to_string()), hashe: None }).await?;
    Ok(())
}

#[actix_web::main]
async fn main() -> Result<(), anyhow::Error> {
    //Parse Command Line:
    let args = Args::parse();
    let client = Client::new();

    let mut listen_addr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse()?;

    let mut ml = MainLogic {
        user : User { public_key: PeerId::random(), private_key: "".to_owned() },
        storage: None,
        container_dns: None,
        root_reference: Some(RootReference { roots: vec![] }),
        providing_container: None,
        peer_dns: None
    };

    let storage = FileStorage::new("D:/testStorage/".to_owned());

    if let Some(addr) = args.listen_addr {
        listen_addr = addr.parse()?;
    }

    if let Some(addr) = args.root_addr {
        let remote: Multiaddr = addr.parse()?;
        ml.root_reference
            .as_mut()
            .expect("expected to have a root reference")
            .roots.push(Node { address: remote, user_info: User { private_key: "".to_owned(), public_key: PeerId::random() } });
        println!("Dialed {addr}");
    }

    if args.provider_node {
        ml.storage = Some(storage);
        //our listen address should be public
        ml.providing_container = Some(ProvidingContainer { container: HashSet::new() });
    
        if let Some(d) = &ml.root_reference {
            println!("informing root:");
            client.peer_inform_root(&d.roots[0].address, 0, &ml.user).await?; //inform root, that we are providing group 0
        }
    }

    if args.is_root_node {
        ml.container_dns = Some(ContainerReference { container_id_reference: HashMap::new(), groups: HashMap::new() });
        if let Some(d) = &mut ml.container_dns {
            d.groups.insert(0, RootGroup { hash: [0; 32].into(), services: vec![], group_group: IndexSet::new()});
        }
        ml.peer_dns = Some(PeerDnsReference { peer_id_reference: HashMap::new() });
    }

    if args.dns_node {
        ml.peer_dns = Some(PeerDnsReference { peer_id_reference: HashMap::new() });
    }


    if args.client_node{
        test_client(&ml, &client).await?;
        //return Ok(());
    }
    let rest_api = rest_api::build_rest_api(ml, &listen_addr,&client, args.provider_node || args.is_root_node, args.provider_node).await?;

    rest_api.await?;
    println!("Ende");

    return Ok(());
}