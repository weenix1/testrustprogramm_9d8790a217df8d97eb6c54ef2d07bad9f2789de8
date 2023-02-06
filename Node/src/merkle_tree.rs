use std::path::Path;
use std::path::PathBuf;
use crate::nodes::HashVec;
use async_recursion::async_recursion;
use sha2::{ Sha256, Digest };
use std::fs;
use std::io;
use serde::{ Serialize, Deserialize };
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MerkleTreeError {
    #[error("Could not generate MerkleTree")]
    IoError(#[from] std::io::Error),
    #[error("Could not find '{0}' in MerkleTree")]
    PathNotFound(String),
    #[error("Could not open Merkle Tree")]
    CouldNotOpenMerkleTree(#[from] serde_json::Error)
}


#[derive(Serialize, Deserialize, Debug)]
pub enum HashMapType {
    Folder,
    File,
    Link,
    None,
}

fn get_hash_of_file(path: &Path) -> Result<HashVec, MerkleTreeError> {
    let mut hasher: sha2::Sha256 = Sha256::new();
    let mut file = fs::File::open(&path)?;

    io::copy(&mut file, &mut hasher)?;
    //let hash  = hasher.finalize().as_slice().clone();

    let mut buf2 = [0u8; 32];
    buf2.copy_from_slice(hasher.finalize().as_slice());
    return Ok(buf2.into());
}

fn get_hash_of_data(data: &[u8]) -> Result<HashVec, MerkleTreeError> {
    let mut hasher: sha2::Sha256 = Sha256::new();
    hasher.update(data);

    let mut buf2 = [0u8; 32];
    buf2.copy_from_slice(hasher.finalize().as_slice());
    return Ok(buf2.into());
}


//[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct MerkleTreeHash {
    pub name: String,
    pub hash_type: HashMapType,
    //#[serde_as(as = "BytesOrString")]
    pub hash: HashVec,
    pub children: Vec<MerkleTreeHash>,
}

fn generate_folder_hash(elements: &Vec<MerkleTreeHash>) -> HashVec {
    let mut hasher: sha2::Sha256 = Sha256::new();
    for element in elements {
        //this may be a security issue!
        if element.hash.as_slice() != [0; 32]{
            hasher.update(element.hash.clone());
        }
    }
    let mut buf2 = [0u8; 32];
    buf2.copy_from_slice(hasher.finalize().as_slice());
    return buf2.into();
}

impl MerkleTreeHash {
    ///
    /// This Function will generate a MerkleTree from a folder structure returns a Merkle Tree
   #[async_recursion]
    pub async fn generate_from_path(path: &Path) -> Result<MerkleTreeHash, MerkleTreeError> {
        println!("Generate From Path: {}", path.display());
        if !path.is_dir() {
            panic!("File should be a Directory!");
        }

        let paths = fs::read_dir(path)?;

        let mut hash = MerkleTreeHash { name: path.file_name().unwrap().to_str().unwrap().to_owned(), hash_type: HashMapType::Folder, hash: [0; 32].into(), children: vec![] };

        for path in paths {
        
            if let Ok(path) = path {
             
                let path = path.path();
               
                if path.is_dir() {
                    println!("MerkleTreePathDir: {}", path.display());
                    let child = MerkleTreeHash::generate_from_path(&path).await?;
                    hash.children.push(child);
                } else {
                    println!("MerkleTreePathFile: {}", path.display());
                    println!("MerkleTreePathFileName: {}", path.file_name().unwrap().to_str().unwrap());
                    let file = MerkleTreeHash { name: path.file_name().unwrap().to_str().unwrap().to_owned(), hash_type: HashMapType::File, hash: get_hash_of_file(&path)?, children: vec![] };
                    hash.children.push(file);
                }
            }
        }

        if hash.children.len() > 0{
            hash.hash = generate_folder_hash(&hash.children);
        }

        return Ok(hash);
        //get the directory path
        //get the file path and open it and hash
        //return the hashed value
    }

    // [0: FILE1 -> hash, 1 : File2 -> hash , 2 : File3 -> hash]
    //
    //

    //index.html : 42

    /* {
   '001': {
         '0010':'hshgddhhzedueied',
         '0011':'asfds4sjh5dohjs'
         '002': {
            'ttegddghjdkdkdkdkkd'
        }
         },
}
 */

    pub fn to_json(&self) -> String {
        return serde_json::to_string(&self).unwrap();
    }

    pub fn from_json(json: &str) -> Result<MerkleTreeHash, MerkleTreeError> {
        let m: MerkleTreeHash = serde_json::from_str(&json)?;
        return Ok(m);
    }

    //return this Merkle Tree to the specified location
    pub fn save(&self, path: &Path) -> Result<(), anyhow::Error> {
        //probably serilize as json and save to path
        fs::write(path, self.to_json())?;
        return Ok(());
    }

    pub fn get_child(&self, path : &str) -> Option<&MerkleTreeHash> {
        return self.children.iter().find(|c| c.name == path);
    }

    pub fn get_hash_of_path(&self, path : &Path) -> Result<HashVec, MerkleTreeError>{
      
        let paths: Vec<&std::ffi::OsStr> = path.iter().collect();
        let mut current = self;
        
        for path in paths{
            if let Some(c) = current.get_child(path.to_str().unwrap()){
                current = c;
            }
            else{

                if let Some(c) = current.get_child("REFERENCE.json"){
                    return Ok([0;32].into());
                }
                return Err(MerkleTreeError::PathNotFound(path.to_str().unwrap().to_string()));
            }
        }
        return Ok(current.hash.clone());
        
    }

    pub fn verify(&self, data : &[u8], path : &str) ->  Result<bool, MerkleTreeError>{
        
        let hash = get_hash_of_data(data)?;
        let mt_hash = self.get_hash_of_path(&PathBuf::from(path))?;
        if mt_hash.as_slice() == [0; 32]{ //special Case, folder is reference to other storage
            return Ok(true);
        }
        return Ok(hash == mt_hash);
    }

    pub fn verify_merkle_tree(&self) ->  bool{
        if let HashMapType::Folder = self.hash_type{
            let hash = generate_folder_hash(&self.children);
            if self.hash != hash{
                return false
            };
          
            for child in &self.children{
                if !child.verify_merkle_tree()
                {
                    return false;
                }
            }
        }
        return true;
    }

}