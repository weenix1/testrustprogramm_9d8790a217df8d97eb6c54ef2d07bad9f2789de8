use actix_web::{ web, App, HttpServer, Responder, dev::Server, post, HttpResponse, http::{self, header::ContentType, StatusCode}};
use actix_multipart::Multipart;
use actix_cors::Cors;
use async_std::io::WriteExt;
use indexmap::IndexSet;
use libp2p_core::{ Multiaddr, multiaddr::Protocol::{ *, self } };
use serde::{ Deserialize, Serialize };
use std::{ sync::Mutex, net::{ Ipv4Addr, IpAddr, Ipv6Addr }, path::PathBuf };
use futures_util::TryStreamExt as _;
use crate::{ nodes::{ GroupId, User, HashVec }, request::*, MainLogic, client::Client, NodeError, storage::StorageError, merkle_tree::{self, MerkleTreeError, MerkleTreeHash}};
use bytes::Bytes;
use regex::Regex;
use anyhow::Result;


struct RestApiState {
    caller: Mutex<MainLogic>,
}

pub const fn is_shared4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000) == 0b0100_0000
}

pub const fn is_benchmarking4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 198 && (ip.octets()[1] & 0xfe) == 18
}
pub const fn is_reserved4(ip: Ipv4Addr) -> bool {
    (ip.octets()[0] & 240) == 240 && !ip.is_broadcast()
}
pub const fn is_global4(ip: Ipv4Addr) -> bool {
    !(
        ip.octets()[0] == 0 || // "This network"
        ip.is_private() ||
        is_shared4(ip) ||
        ip.is_loopback() ||
        ip.is_link_local() ||
        // addresses reserved for future protocols (`192.0.0.0/24`)
        (ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0) ||
        ip.is_documentation() ||
        is_benchmarking4(ip) ||
        is_reserved4(ip) ||
        ip.is_broadcast()
    )
}

pub const fn is_documentation6(ip: Ipv6Addr) -> bool {
    ip.segments()[0] == 0x2001 && ip.segments()[1] == 0xdb8
}
pub const fn is_unique_local6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}
pub const fn is_unicast_link_local6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}
pub const fn is_global6(ip: Ipv6Addr) -> bool {
    !(
        ip.is_unspecified() ||
        ip.is_loopback() ||
        // IPv4-mapped Address (`::ffff:0:0/96`)
        matches!(ip.segments(), [0, 0, 0, 0, 0, 0xffff, _, _]) ||
        // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
        matches!(ip.segments(), [0x64, 0xff9b, 1, _, _, _, _, _]) ||
        // Discard-Only Address Block (`100::/64`)
        matches!(ip.segments(), [0x100, 0, 0, 0, _, _, _, _]) ||
        // IETF Protocol Assignments (`2001::/23`)
        (matches!(ip.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200) &&
            !(
                // Port Control Protocol Anycast (`2001:1::1`)

                    u128::from_be_bytes(ip.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001 ||
                    // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                    u128::from_be_bytes(ip.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002 ||
                    // AMT (`2001:3::/32`)
                    matches!(ip.segments(), [0x2001, 3, _, _, _, _, _, _]) ||
                    // AS112-v6 (`2001:4:112::/48`)
                    matches!(ip.segments(), [0x2001, 4, 0x112, _, _, _, _, _]) ||
                    // ORCHIDv2 (`2001:20::/28`)
                    matches!(ip.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x2F)

            )) ||
        is_documentation6(ip) ||
        is_unique_local6(ip) ||
        is_unicast_link_local6(ip)
    )
}

pub const fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_global4(ip),
        IpAddr::V6(ip) => is_global6(ip),
    }
}

pub async fn build_rest_api(ml: MainLogic, listen: &Multiaddr, client: &Client, add_listen: bool, inform_root : bool) -> Result<Server, anyhow::Error> {
    let state = web::Data::new(RestApiState { caller: Mutex::new(ml) });
    let state2 = state.clone();

    let server = HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost")
            // .allowed_origin_fn(|origin, _req_head| {
            //     origin.as_bytes().ends_with(b".rust-lang.org")
            // })
            .allowed_methods(vec!["GET", "POST"])
            //.allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
            .allowed_header(http::header::CONTENT_TYPE)
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(state2.clone())
            .service(client_get_file_request)
            .service(get_file_request)
            .service(publish_file_request)
            .service(get_container)
            .service(post_group)
            .service(post_container)
            .service(get_peer)
            .service(update_peer)
            .service(get_merkle_tree_request)
            .service(client_publish_file_request)
            .service(client_get_file_request_link)
    });

    //let mut addr = ("".to_owned(), 0);
    let mut addr = (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

    for p in listen {
        match p {
            // Dns(dns) =>  addr.0 = dns.to_string(),
            // Dns4(dns) => addr.0 = dns.to_string(),
            // Dns6(dns) =>   addr.0 = dns.to_string(),
            // Dnsaddr(dns) =>   addr.0 = dns.to_string(),
            Http => {}
            Https => {}
            Ip4(ip4) => {
                addr.0 = IpAddr::V4(ip4);
            }
            Ip6(ip6) => {
                addr.0 = IpAddr::V6(ip6);
            }
            Tcp(tcp) => {
                addr.1 = tcp;
            }
            Tls => {}
            _ => {}
        }
    }
    println!("RestAPi Listen:{:?}", addr);

    let mut server = server.bind(addr)?;
    let sockets = server.addrs();
    let port = sockets.first().expect("could not bind to a interface!").port();

    if add_listen {
        let mut addrs = vec![];
        // List all of the machine's network interfaces
        for iface in get_if_addrs::get_if_addrs().unwrap() {
            let mut addr: Multiaddr = Multiaddr::empty();
            let ip = iface.ip();
            println!("{:#?}", ip);
            if is_global(ip) {
                match ip {
                    IpAddr::V4(ip4) => addr.push(Protocol::Ip4(ip4)),
                    IpAddr::V6(ip6) => addr.push(Protocol::Ip6(ip6)),
                }
                addr.push(Protocol::Tcp(port));
                addrs.push(addr);
                server = server.bind((ip, port))?;
            }
        }
    }

    let sockets = server.addrs();

    if inform_root {
        let c = state.caller.lock().unwrap();
        if let Some(d) = &c.root_reference {
            println!("informing dns:");

            let mut addrs = vec![];

            for socket in sockets {
                println!("socket{}", socket);
                let mut addr: Multiaddr = Multiaddr::empty();
                //if is_global(ip) {
                match socket.ip() {
                    IpAddr::V4(ip4) => addr.push(Protocol::Ip4(ip4)),
                    IpAddr::V6(ip6) => addr.push(Protocol::Ip6(ip6)),
                }
                addr.push(Protocol::Tcp(socket.port()));
                addrs.push(addr);
                //}
            }
            client.peer_inform_dns(&d.roots[0].address, &c.user, addrs).await?; //add our Ip-Address to the dns
        }
    }

    let rest_api = server.run(); //.fuse().into_stream();
    return Ok(rest_api);
}

fn report<'a, E>(err: &'a E) -> String
where
    E: std::error::Error,
    //E: Send + Sync,
{
    
    let mut str = format!("[ERROR] {}\n", err);
    if let Some(cause) = err.source() {
        str = str + "\nCaused by:\n";
        for (i, e) in std::iter::successors(Some(cause), |e| e.source()).enumerate() {
            str += &format!("   {}: {}", i, e);
        }
    }
    return str;
}

impl actix_web::error::ResponseError for NodeError {
    fn status_code(&self) -> http::StatusCode {
        match self {
            NodeError::StorageError(e) => e.status_code(),
            NodeError::NoRootReference => StatusCode::INTERNAL_SERVER_ERROR,
            NodeError::RequestError(e) => e.status_code(),
            NodeError::ResponseError { status_code, body: _ } => status_code.clone(),
            NodeError::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
            NodeError::NoRoot => StatusCode::SERVICE_UNAVAILABLE,
            NodeError::NoDns => StatusCode::SERVICE_UNAVAILABLE,
            NodeError::NoProvider => StatusCode::SERVICE_UNAVAILABLE,
            NodeError::NoProviderIsProvidingThisGroup => StatusCode::NOT_FOUND ,
            NodeError::ContainerCouldNotBeFound => StatusCode::NOT_FOUND,
            NodeError::WrongHash => StatusCode::NOT_FOUND,
            NodeError::MerkleTreeInvalid => StatusCode::NOT_FOUND,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        HttpResponse::build(self.status_code())
        .insert_header(ContentType::html())
        .body(report(&self))
    }
}

impl actix_web::error::ResponseError for StorageError {
    fn status_code(&self) -> http::StatusCode {
        match self {
            StorageError::FileNotFound(_) => StatusCode::NOT_FOUND,
            StorageError::RequestError(e) => e.status_code(),
            StorageError::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
            StorageError::MerkleTreeError(m) =>  m.status_code(),
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        HttpResponse::build(self.status_code())
        .insert_header(ContentType::html())
        .body(report(&self))
    }
}

impl actix_web::error::ResponseError for RequestError {
    fn status_code(&self) -> http::StatusCode {
        match self {
            RequestError::PathNoFile => StatusCode::BAD_REQUEST,
            RequestError::FileMissing => StatusCode::BAD_REQUEST,
            RequestError::ContainerWrongFormat => StatusCode::BAD_REQUEST,
            RequestError::ConnectionTimeout => StatusCode::BAD_GATEWAY,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        HttpResponse::build(self.status_code())
        .insert_header(ContentType::html())
        .body(report(&self))
    }
}

impl actix_web::error::ResponseError for MerkleTreeError {
    fn status_code(&self) -> http::StatusCode {
        match self {
            MerkleTreeError::IoError(e) => return e.status_code(),
            MerkleTreeError::PathNotFound(_) => StatusCode::NOT_FOUND,
            MerkleTreeError::CouldNotOpenMerkleTree(_) => StatusCode::NOT_FOUND,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        HttpResponse::build(self.status_code())
        .insert_header(ContentType::html())
        .body(report(&self))
    }
}



/* *** Client Node ***  */

async fn client_get_file_request_helper<'a>(info: &FileRequestBody, c : std::sync::MutexGuard<'a, MainLogic>) -> actix_web::Result<impl Responder> {
    let re2 = Regex::new(r".*\.(.+)").unwrap();
    let client = Client::new();

    println!("/client/getFile: {:?}", info);

    let mt = client.client_get_merkle_tree(&c,info).await?;
    let mt = MerkleTreeHash::from_json(&mt)?;
    if mt.hash != info.root_hash || !mt.verify_merkle_tree(){
        return Err(NodeError::MerkleTreeInvalid.into());
    }
    let result = client.client_get_file(&c, &info).await;
    
    let data = result?;


   
    let mut mime = actix_files::file_extension_to_mime(".txt");
    if let Some(file) = &info.file {
        if mt.verify(data.as_ref(), file)? == false{
            return Err(NodeError::WrongHash.into());
        }

        if let Some(m2) = re2.captures(&file) {
            mime = actix_files::file_extension_to_mime(m2.get(1).unwrap().as_str());
        }
    }

    return Ok(HttpResponse::Ok().content_type(mime).body(data));
}

#[post("/client/getFile")]
async fn client_get_file_request(info: web::Json<FileRequestBody>, data: web::Data<RestApiState>) -> impl Responder {
    let c = data.caller.lock().unwrap();
    return client_get_file_request_helper(&info.0, c).await;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetFileLinkRequest {
    pub url: String,
}

/* *** Client Node ***  */
#[post("/client/getFileLink")]
async fn client_get_file_request_link(info: web::Json<GetFileLinkRequest>, data: web::Data<RestApiState>) -> actix_web::Result<impl Responder> {
    let c = data.caller.lock().unwrap();

   
    println!("/client/getFileLink: {:?}", info.0);

    fn get_rooth_hash(root_hash : &str, path : &str) -> actix_web::Result<HashVec> {
        let root_hash = hex::decode(root_hash).map_err(|_| RequestError::ContainerWrongFormat)?;
        let root_hash: HashVec = root_hash.try_into(). map_err(|_| RequestError::ContainerWrongFormat)?;
        return Ok(root_hash);
    }

    let re = Regex::new(r"block://(.*?)/(.*)").unwrap();
    if let Some(m) = re.captures(&info.url) {
        let root_hash = m.get(1).unwrap().as_str();
        let path = m.get(2).unwrap().as_str();

        if let Ok(root_hash) = get_rooth_hash(root_hash, path){
            return client_get_file_request_helper(&FileRequestBody { root_hash: root_hash, file: Some(path.to_owned()), hashe: None }, c).await;
        }
        else{
            //return client_get_file_request_helper(&FileRequestBody { root_hash: root_hash, file: Some(path.to_owned()), hashe: None }, c).await;
        }
    
    }
    return Err(RequestError::ContainerWrongFormat.into());
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PublishRequest {
    pub folder: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PublishResponse {
    pub hash: String,
}


#[post("/client/publish")]
async fn client_publish_file_request(info: web::Json<PublishRequest>, data: web::Data<RestApiState>) -> actix_web::Result<impl Responder> {
    let c = data.caller.lock().unwrap();

    let client = Client::new();
    println!("/client/publish: {:?}", info.0);

    //1. generate merkle Tree!
    let mt = merkle_tree::MerkleTreeHash::generate_from_path(&PathBuf::from(&info.folder)).await?;

    //2. publish
    client.client_publish_container(&c, mt.hash, PathBuf::from(&info.folder)).await?;
    return Ok(HttpResponse::Ok().json(PublishResponse{hash : hex::encode(mt.hash.0)}));
}

/* *** Provider Node **** */

#[post("/provider/getFile")]
async fn get_file_request(info: web::Json<FileRequestBody>, data: web::Data<RestApiState>) -> actix_web::Result<impl Responder> {
    let mut c = data.caller.lock().unwrap();

    println!("/provider/getFile: {:?}", info.0);

    if let Some(d) = &mut c.storage {
        let result = d.handle_request_data(&info.0).await?;
        return Ok(HttpResponse::Ok().body(result));
    }
    return Err(NodeError::NoProvider.into());
}

#[post("/provider/getMerkleTree")]
async fn get_merkle_tree_request(info: web::Json<HashRequest>, data: web::Data<RestApiState>) -> actix_web::Result<impl Responder> {
    let mut c = data.caller.lock().unwrap();

    println!("/provider/getMerkleTree: {:?}", info.0);

    if let Some(d) = &mut c.storage {
        let result = d.get_merkle_tree(info.root_hash.clone()).await?;
        return Ok(HttpResponse::Ok().body(result));
    }
    return Err(NodeError::NoProvider.into());
}

#[post("/provider/publishFile")]
async fn publish_file_request(mut payload: Multipart, data: web::Data<RestApiState>) -> actix_web::Result<impl Responder> {
    let mut c = data.caller.lock().unwrap();

    println!("/provider/publishFile:");

    if let Some(d) = &mut c.storage {
        let mut is_first = true;

        let mut request: FileRequestBody = FileRequestBody { root_hash: [0; 32].into(), file: None, hashe: None };

        // iterate over multipart stream
        while let Some(mut field) = payload.try_next().await? {
            // A multipart/form-data stream has to contain `content_disposition`
            //let content_disposition = field.content_disposition();

            if is_first {
                //The first Entry will be a Post Command, after that are files

                let result: Vec<Bytes> = field.try_collect().await?; //wait for all content
                let result = result.concat(); // join Bytes together
                request = serde_json::from_slice(&result)?;

                println!("/publishFile:{:?}", request);
            } else {
                //let filename = content_disposition.get_filename();
                let mut file = d.post_content(&request.root_hash, &request.file.as_mut().ok_or(RequestError::FileMissing)?).await?;

                println!("got File Path:{:?}", file);

                // Field in turn is stream of *Bytes* object
                while let Some(chunk) = field.try_next().await? {
                    file.write_all(&chunk).await?;
                }
            }

            is_first = false;
        }
        return Ok(HttpResponse::Ok().finish());
    }
    return Err(NodeError::NoProvider.into());
}

/* ***  Root Node  *** */
#[post("/root/getContainer")]
async fn get_container(info: web::Json<ContainerResolveRequest>, data: web::Data<RestApiState>) -> actix_web::Result<impl Responder> {
    let ml = data.caller.lock().unwrap();

    println!("root/getContainer: {:?}", info.0);

    if let Some(d) = &ml.container_dns {
        if let Some(group) = d.get_group(&info.root_hash) {
            let group = group.group_group.first().ok_or(NodeError::NoProviderIsProvidingThisGroup)?;
            return Ok(HttpResponse::Ok().json(ContainerResolveResponse { nodes: group.clone() }));
        }
        return Err(NodeError::ContainerCouldNotBeFound.into());
    }
    return Err(NodeError::NoRoot.into());
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PostGroupRequest {
    pub user: User,
    pub group_id: GroupId,
}

///a Provider wants to be added to a group
/// //TODO: flush to Root Network!, check authentification
#[post("/root/provider_add")]
async fn post_group(info: web::Json<PostGroupRequest>, data: web::Data<RestApiState>) -> actix_web::Result<impl Responder> {
    let mut ml = data.caller.lock().unwrap();

    println!("root/provider_add: {:?}", info.0);

    if let Some(d) = &mut ml.container_dns {
        if let Some(group) = d.groups.get_mut(&info.group_id) {
            group.group_group.insert(info.user.clone());
            return Ok(HttpResponse::Ok().finish());
        }
    }
    return Err(NodeError::NoRoot.into());
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PostContainerRequest {
    pub user: User,
    pub root_hash: HashVec,
}

///a Host wants to add a container
/// //TODO: flush to Root Network!, check authentification
#[post("/root/container_add")]
async fn post_container(info: web::Json<PostContainerRequest>, data: web::Data<RestApiState>) -> actix_web::Result<impl Responder> {
    let mut ml = data.caller.lock().unwrap();

    println!("root/container_add: {:?}", info.0);

    if let Some(d) = &mut ml.container_dns {
        //for now everything goes into group 0:
        d.container_id_reference.insert(info.root_hash.clone(), 0);
        return Ok(HttpResponse::Ok().finish());
    }
    return Err(NodeError::NoRoot.into());
}

/* ***  Dns Node  *** */
#[post("/dns/getPeer")]
async fn get_peer(info: web::Json<PeerResolveRequest>, data: web::Data<RestApiState>) -> actix_web::Result<impl Responder>  {
    let ml = data.caller.lock().unwrap();

    println!("dns/getPeer: {:?}", info.0);

    if let Some(d) = &ml.peer_dns {
        if let Some(peer) = d.peer_id_reference.get(&info.user.public_key) {
            return Ok(HttpResponse::Ok().json(PeerResolveResponse { address: peer.iter().cloned().collect() }));
        }
    }
    return Err(NodeError::NoDns.into());
}

#[post("/dns/updatePeer")]
async fn update_peer(info: web::Json<PeerUpdateRequest>, data: web::Data<RestApiState>) -> actix_web::Result<impl Responder> {
    let mut ml = data.caller.lock().unwrap();

    println!("dns/updatePeer: {:?}", info.0);

    if let Some(d) = &mut ml.peer_dns {
        for addr in &info.address {
            let v = d.peer_id_reference.entry(info.user.public_key.clone()).or_insert(IndexSet::new());
            v.insert(addr.clone());
            //d.peer_id_reference.insert(info.user.public_key.clone(), addr.clone());
        }
        //TODO: flush to DNS Network!, check authentification

        return Ok(HttpResponse::Ok().finish());
    }
    return Err(NodeError::NoDns.into());
}