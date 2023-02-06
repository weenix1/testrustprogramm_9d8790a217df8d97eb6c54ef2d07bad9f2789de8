use libp2p_core::Multiaddr;
use serde::Serialize;
use serde::Deserialize;
use std::marker::PhantomData;

use crate::nodes::HashVec;
use crate::nodes::User;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("Bad Request")]
#[derive(PartialEq)]
pub enum RequestError {
    #[error("The SpecifiedPath is not a File")]
    PathNoFile,
    #[error("No File or hash specified!")]
    FileMissing,
    #[error("Container_Hash has the wrong size!")]
    ContainerWrongFormat,

    #[error("No Connection to the Provider")]
    ConnectionTimeout,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlowJson<Req, Res, Proto> {
    phantom: PhantomData<Req>,
    phantom1: PhantomData<Res>,
    phantom2: PhantomData<Proto>,
}

/* *****HASH REQUEST ****** */

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashRequest {
    pub root_hash: HashVec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashResponse {
    pub hash_tree: String,
}




/* ****** FILE REQUEST********* */

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileRequestBody {
    pub root_hash: HashVec,
    pub file: Option<String>,
    pub hashe: Option<HashVec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct File {
    pub content: Vec<u8>,
    pub hash: HashVec,
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileResponse {
    pub file: Option<File>,
}



/* ****** CONTAINER NODE REQUEST ****** */

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContainerResolveRequest {
    pub root_hash: HashVec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerResolveResponse {
    pub nodes : User,
}



/* ****** Peer DNS NODE REQUEST ****** */

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerResolveRequest {
    pub user: User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerResolveResponse {
    pub address : Vec<Multiaddr> ,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerUpdateRequest {
    pub user: User,
    pub address : Vec<Multiaddr> ,
}









