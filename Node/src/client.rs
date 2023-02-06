use std::{ path::{ PathBuf, Path }, io };

use bytes::Bytes;
use libp2p_core::{ multiaddr::Protocol::*, Multiaddr };
use crate::{ request::*, nodes::*, rest_api::{ PostGroupRequest, PostContainerRequest }, MainLogic, NodeError, storage::StorageError };
use reqwest::{ multipart, Body };
use tokio::fs::File;
use tokio_util::codec::{ BytesCodec, FramedRead };
use pathdiff::diff_paths;
use walkdir::WalkDir;
use serde::de::DeserializeOwned;

pub struct Client {
    client: reqwest::Client,
}

fn multiaddr_to_http(addr: &Multiaddr) -> String {
    let mut result = ("".to_owned(), 0);

    let mut is6 = false;

    for p in addr {
        match p {
            Dns(dns) => {
                result.0 = dns.to_string();
            }
            Dns4(dns) => {
                result.0 = dns.to_string();
            }
            Dns6(dns) => {
                result.0 = dns.to_string();
            }
            Dnsaddr(dns) => {
                result.0 = dns.to_string();
            }
            Http => {}
            Https => {}
            Ip4(ip4) => {
                result.0 = ip4.to_string();
            }
            Ip6(ip6) => {
                result.0 = ip6.to_string();
                is6 = true;
            }
            Tcp(tcp) => {
                result.1 = tcp;
            }
            Tls => {}
            _ => {}
        }
    }
    if is6 {
        return format!("http://[{}]:{}", result.0, result.1);
    } else {
        return format!("http://{}:{}", result.0, result.1);
    }
}

impl From<reqwest::Error> for NodeError {
    fn from(e: reqwest::Error) -> Self {
        return NodeError::Other(anyhow::anyhow!(e));
    }
}

impl From<io::Error> for NodeError {
    fn from(e: io::Error) -> Self {
        return NodeError::Other(anyhow::anyhow!(e));
    }
}

impl From<serde_json::Error> for NodeError {
    fn from(e: serde_json::Error) -> Self {
        return NodeError::Other(anyhow::anyhow!(e));
    }
}

async fn handle_reqwest_ok(resp: reqwest::Response) -> Result<(), NodeError> {
    if resp.status().is_success() {
        return Ok(());
    } else {
        return Err(NodeError::ResponseError { status_code: resp.status(), body: resp.text().await? });
    }
}

async fn handle_reqwest_json<T : DeserializeOwned>(resp: reqwest::Response) -> Result<T, NodeError> {
    if resp.status().is_success() {
        return Ok(resp.json::<T>().await?);
    } else {
        return Err(NodeError::ResponseError { status_code: resp.status(), body: resp.text().await? });
    }
}

impl Client {
    pub fn new() -> Client {
        return Client { client: reqwest::Client::new() };
    }

    pub async fn peer_inform_dns(&self, dns: &Multiaddr, user: &User, addr: Vec<Multiaddr>) -> Result<(), NodeError> {
        let dns_addr = multiaddr_to_http(&dns);

        let body = PeerUpdateRequest { user: user.clone(), address: addr.clone() };

        let resp = self.client
            .post(dns_addr + "/dns/updatePeer")
            .json(&body)
            .send().await?;

        println!("{:#?}", resp);

        return handle_reqwest_ok(resp).await;
    }

    pub async fn peer_inform_root(&self, root: &Multiaddr, group_id: GroupId, user: &User) -> Result<(), NodeError> {
        let dns_addr = multiaddr_to_http(&root);

        let body = PostGroupRequest { group_id, user: user.clone() };

        let resp = self.client
            .post(dns_addr + "/root/provider_add")
            .json(&body)
            .send().await?;
        println!("{:#?}", resp);
        return handle_reqwest_ok(resp).await;
    }

    pub async fn client_get_container(&self, root: &Multiaddr, root_hash: HashVec) -> Result<ContainerResolveResponse, NodeError> {
        let dns_addr = multiaddr_to_http(&root);

        //1. ask root node for a provider, who hosts this content
        let body = ContainerResolveRequest { root_hash };
        let resp = self.client
            .post(dns_addr.clone() + "/root/getContainer")
            .json(&body)
            .send().await?;

        return handle_reqwest_json(resp).await;
    }

    pub async fn client_get_peer_addr(&self, root: &Multiaddr, user: User) -> Result<PeerResolveResponse, NodeError> {
        let dns_addr = multiaddr_to_http(&root);

        //2. make a dns
        let body = PeerResolveRequest { user };
        let resp = self.client
            .post(dns_addr + "/dns/getPeer")
            .json(&body)
            .send().await?;

        return handle_reqwest_json(resp).await;
    }

    pub async fn client_get_file_to_peer(&self, peer: &Multiaddr, request: &FileRequestBody) -> Result<Bytes, NodeError> {
        let dns_addr = multiaddr_to_http(&peer);

        println!("client_get_file Peer:{:?}", peer);

        //now we have the ip-adress of the providing node
        //3. make a get content request:
        let body = request;
        let resp = self.client
            .post(dns_addr + "/provider/getFile")
            .json(body)
            .send().await?;

        if resp.status().is_success() {
            let result = resp.bytes().await?;
            //println!("{:#?}", result);
            return Ok(result);
        } else {
            return Err(NodeError::ResponseError { status_code: resp.status(), body: resp.text().await? });
        }
    }

    pub async fn client_get_merkle_tree_from_peer(&self, peer: &Multiaddr, request: &FileRequestBody) -> Result<String, NodeError> {
        let dns_addr = multiaddr_to_http(&peer);

        println!("client_get_merkle_tree from Peer:{:?}", peer);

        //now we have the ip-adress of the providing node
        //3. make a get content request:
        let body = HashRequest {root_hash : request.root_hash.clone()};
        let resp = self.client
            .post(dns_addr + "/provider/getMerkleTree")
            .json(&body)
            .send().await?;

        if resp.status().is_success() {
            let result = resp.text().await?;
            //println!("{:#?}", result);
            return Ok(result);
        } else {
            return Err(NodeError::ResponseError { status_code: resp.status(), body: resp.text().await? });
        }
    }

    pub async fn client_container_to_peer_addr(&self, root: &Multiaddr, root_hash: &HashVec) -> Result<Vec<Multiaddr>, NodeError> {
        let container = self.client_get_container(root, root_hash.clone()).await?;
        let peer = self.client_get_peer_addr(root, container.nodes).await?;
        return Ok(peer.address);
    }

    pub async fn client_get_file(&self, ml: &MainLogic, request: &FileRequestBody) -> Result<Bytes, NodeError> {
        println!("client_get_file:");
        if let Some(d) = &ml.root_reference {
            let root = &d.roots.first().ok_or(NodeError::NoRootReference)?;

            let peers = self.client_container_to_peer_addr(&root.address, &request.root_hash).await?;

            let mut last_err: NodeError = RequestError::ConnectionTimeout.into();
            for peer in peers {
                let data2 = self.client_get_file_to_peer(&peer, request).await;
                match data2 {
                    Ok(d) => {
                        return Ok(d);
                    }
                    Err(NodeError::StorageError(StorageError::FileNotFound(e))) => {
                        last_err = StorageError::FileNotFound(e).into();
                    }
                    Err(NodeError::StorageError(StorageError::RequestError(r))) => {
                        if r != RequestError::ConnectionTimeout {
                            last_err = StorageError::RequestError(r).into();
                        }
                        else{
                            println!("Error was: {:?}", r);
                        }
                      
                    }
                    Err(e) => {
                        if let  NodeError::Other(_) = e{     
                            //Possibly connection error
                        }
                        else{
                            println!("Error was: {}", e);
                            last_err = e;
                        }
                    }
                }
            }

            return Err(last_err);
        }
        return Err(NodeError::NoRootReference);
    }

    pub async fn client_get_merkle_tree(&self, ml: &MainLogic, request: &FileRequestBody) -> Result<String, NodeError> {
        println!("client_get_merkle_tree:");
        if let Some(d) = &ml.root_reference {
            let root = &d.roots.first().ok_or(NodeError::NoRootReference)?;

            let peers = self.client_container_to_peer_addr(&root.address, &request.root_hash).await?;

            let mut last_err: NodeError = RequestError::ConnectionTimeout.into();
            for peer in peers {
                let data2 = self.client_get_merkle_tree_from_peer(&peer, request).await;
                match data2 {
                    Ok(d) => {
                        return Ok(d);
                    }
                    Err(NodeError::StorageError(StorageError::FileNotFound(e))) => {
                        last_err = StorageError::FileNotFound(e).into();
                    }
                    Err(NodeError::StorageError(StorageError::RequestError(r))) => {
                        if r != RequestError::ConnectionTimeout {
                            last_err = StorageError::RequestError(r).into();
                        }
                        else{
                            println!("Error was: {:?}", r);
                        }
                      
                    }
                    Err(e) => {
                        if let  NodeError::Other(_) = e{     
                            //Possibly connection error
                        }
                        else{
                            println!("Error was: {}", e);
                            last_err = e;
                        }
                    }
                }
            }

            return Err(last_err);
        }
        return Err(NodeError::NoRootReference);
    }


    pub async fn client_publish_file_to_peer(&self, peer: &Multiaddr, request: &FileRequestBody, path: &Path) -> Result<(), NodeError> {
        let dns_addr = multiaddr_to_http(&peer);
        println!("client_publish_file_to peer:{}", dns_addr);
        // read file body stream
        let file = File::open(path).await?;
        let stream = FramedRead::new(file, BytesCodec::new());
        let file_body = Body::wrap_stream(stream);

        //make form part of file
        let some_file = multipart::Part::stream(file_body).file_name("").mime_str("text/plain")?;

        //create the multipart form
        let form = multipart::Form::new().text("command", serde_json::to_string(&request)?).part("file", some_file);

        //send request
        let resp = self.client
            .post(dns_addr.clone() + "/provider/publishFile")
            .multipart(form)
            .send().await?;
        return handle_reqwest_ok(resp).await;
    }

    pub async fn client_publish_container_to_peer(&self, peer: &Multiaddr, root_hash: HashVec, path: PathBuf) -> Result<(), NodeError> {
        //let paths = fs::read_dir(path).unwrap();

        for entry in WalkDir::new(&path) {
            //path.read_dir().expect("read_dir call failed") {
            if let Ok(entry) = entry {
                let entry = entry.path();
                if entry.is_file() {
                    let relative = diff_paths(&entry, &path).expect("Expected path to be relative to each other");
                    self.client_publish_file_to_peer(peer, &(FileRequestBody { root_hash : root_hash.clone(), file: Some(relative.to_str().unwrap().to_owned()), hashe: None }), entry).await?;
                }
            }
        }
        return Ok(());
    }

    pub async fn client_publish_container(&self, ml: &MainLogic, root_hash: HashVec, path: PathBuf) -> Result<(), NodeError> {
        if let Some(d) = &ml.root_reference {
            let root = &d.roots[0].address;
            let root_addr = multiaddr_to_http(&root);

            //1. add container to Root
            let body = PostContainerRequest { user: ml.user.clone(), root_hash: root_hash.clone() };
            let resp = self.client
                .post(root_addr + "/root/container_add")
                .json(&body)
                .send().await?;

            if let Err(e) = handle_reqwest_ok(resp).await{
                return Err(e);
            }

            //2. publish data to provider:
            //a. get provider:
            let peers = self.client_container_to_peer_addr(root, &root_hash).await?;
            println!("Publish to Peer:{:?}", peers);

            let mut last_err: NodeError = RequestError::ConnectionTimeout.into();
            for peer in peers {
                let data2 = self.client_publish_container_to_peer(&peer, root_hash.clone(), path.clone()).await;
                match data2 {
                    Ok(d) => {
                        return Ok(d);
                    }
                    Err(NodeError::StorageError(StorageError::FileNotFound(e))) => {
                        last_err = StorageError::FileNotFound(e).into();
                    }
                    Err(NodeError::StorageError(StorageError::RequestError(r))) => {
                        if r != RequestError::ConnectionTimeout {
                            last_err = StorageError::RequestError(r).into();
                        }
                    }
                    Err(_) => {}
                }
            }

            return Err(last_err);
        }
        return Err(NodeError::NoRootReference);
    }
}