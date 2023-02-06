use libp2p_core::{Multiaddr, PeerId};
use serde::{Serialize, Deserialize, ser,de};
use std::{hash::Hash, fmt};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct User {
    pub public_key: PeerId,
    pub private_key: String,
}

pub struct Node {
    pub user_info: User,
    pub address: Multiaddr,
}



///Represents a Group of n Nodes
pub struct NodeGroup{
    pub others : Vec<Node>,
}

#[derive(Clone,Copy, PartialEq,derive_more::From,derive_more::Into,derive_more::Index,derive_more::AsRef, derive_more::AsMut, derive_more::Deref, derive_more::DerefMut)]
pub struct HashVec(pub [u8; 32]);

impl ser::Serialize for HashVec
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: ser::Serializer,
    {
        let str = hex::encode(self.0);
        serializer.serialize_str(&str)
    }
}

struct IHashVecVisitor;
impl<'de> de::Visitor<'de> for IHashVecVisitor {
    type Value = HashVec;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an integer between -2^31 and 2^31")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: de::Error,
     {
        
        let g = hex::decode(v);
        match g{
            Ok(vu8) => 
            {
                let d : HashVec = vu8.try_into().map_err(|_| E::custom(format!("hash is not 32 bytes long: {}", v)))?;
                return Ok(d);
            },            
            Err(_) => return Err(E::custom(format!("hash is not hex: {}", v))),
        }
    }
}

impl<'de> Deserialize<'de> for  HashVec {
    fn deserialize<D>(deserializer: D) -> Result<HashVec, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_str(IHashVecVisitor)
    }
}

impl AsRef<[u8]> for HashVec{
    fn as_ref(&self) -> &[u8] {
        return self.0.as_ref();
    }
}


impl TryFrom<Vec<u8>> for HashVec{
    type Error = Vec<u8>;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let r : [u8;32] = value.try_into()?;
        return Ok(r.into());
    }
}

impl std::cmp::Eq for HashVec{
    fn assert_receiver_is_total_eq(&self) {return self.0.assert_receiver_is_total_eq();}
}

impl Hash for HashVec{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for HashVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}


pub type GroupId = u64;
pub struct Group {
    pub hash: HashVec,
    pub services: Vec<Service>,
    pub group_group: NodeGroup,
}

pub struct Service {
    pub hash: HashVec,
}