use std::{ collections:: HashMap , fs, ops::Range, path::{ Component, Path, PathBuf }, num::NonZeroUsize };

use crate::{ merkle_tree::*, request::{FileRequestBody, RequestError}};
use crate::nodes::HashVec;
use async_std::fs::File;
use chrono::{ DateTime, Utc };
use futures::AsyncReadExt;
use serde::{ Deserialize, Serialize };
use async_recursion::async_recursion;
use thiserror::Error;

struct FileMetaData {
    signatur: Vec<u8>,
    time_stamp: DateTime<Utc>,
}

struct ContainerMetaData {
    owner: Option<Vec<u8>>,
    time_stamp: DateTime<Utc>,
    hash: HashVec,
}

mod my_date_format {
    use chrono::{ DateTime, TimeZone, Utc };
    use serde::{ self, Deserialize, Deserializer, Serializer };

    const FORMAT: &'static str = "%Y-%m-%d %H:%M:%S";

    // The signature of a serialize_with function must follow the pattern:
    //
    //    fn serialize<S>(&T, S) -> Result<S::Ok, S::Error> where S: Serializer
    //
    // although it may also be generic over the input types T.
    pub fn serialize<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let s = format!("{}", date.format(FORMAT));
        serializer.serialize_str(&s)
    }

    // The signature of a deserialize_with function must follow the pattern:
    //
    //    fn deserialize<D>(D) -> Result<T, D::Error> where D: Deserializer
    //
    // although it may also be generic over the output types T.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error> where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        Utc.datetime_from_str(&s, FORMAT).map_err(serde::de::Error::custom)
    }
}

//#[derive(Clone)]
pub struct FileStorage {
    hash_map: lru::LruCache<HashVec, HashMap<HashVec, String>>,
    merkle_tree: lru::LruCache<HashVec, String>,
    meta_data: lru::LruCache<HashVec, HashMap<String, FileMetaData>>,
    root_path: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Reference {
    reference: HashVec,
    owner: Vec<u8>,
    #[serde(with = "my_date_format")]
    time_stamp: DateTime<Utc>,
}



#[derive(Error, Debug)]
pub enum StorageError {
    #[error("A Ressource could not be Found!")]
    FileNotFound(#[from] FileNotFound),
    #[error(transparent)]
    RequestError(#[from] RequestError),
    #[error(transparent)]
    MerkleTreeError(#[from] MerkleTreeError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),  // source and Display delegate to anyhow::Error
}

// #[derive(Debug)]
// pub enum StorageError {
//     FileNotFound(FileNotFound),
//     Other(anyhow::Error),
// }

// impl From<FileNotFound> for StorageError {
//     fn from(e: FileNotFound) -> Self {
//         return StorageError::FileNotFound(e);
//     }
// }

// impl From<anyhow::Error> for StorageError {
//     fn from(e: anyhow::Error) -> Self {
//         return StorageError::Other(e);
//     }
// }

// impl From<NodeError> for StorageError {
//     fn from(e: NodeError) -> Self {
//         return StorageError::Other(e.into());
//     }
// }

// impl fmt::Display for StorageError {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         match self {
//             StorageError::FileNotFound(obj) => write!(f, "{}", obj),
//             StorageError::Other(obj) => write!(f, "{}", obj),
//         }
//     }
// }

// impl Error for StorageError {}

#[derive(Error, Debug, Clone)]
pub enum FileNotFound {
    #[error("The File `{file}` could not be found on Container `{container:?}`")]
    File{container :  HashVec, file  : String},
    #[error("The File-Hash `{hash:?}` could not be found on Container `{container:?}`")]
    Hash{container :  HashVec, hash  : HashVec},
    #[error("The Container `{container:?}` could not be found")]
    Container{container :  HashVec},
}




// #[derive(Debug, Clone)]
// pub struct FileNotFound {
//     pub container: HashVec,
//     pub file: FileOrHash,
// }
// impl Error for FileNotFound {}
// impl FileNotFound {
//     fn new(str: HashVec, file_or_hash: FileOrHash) -> FileNotFound {
//         return FileNotFound { container: str, file: file_or_hash };
//     }
// }
// impl fmt::Display for FileNotFound {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         match &self.file {
//             FileOrHash::File(file) =>  write!(f, "File Not Found: {:?} in Container {:?}",file, self.container),
//             FileOrHash::Hash(hash) =>  write!(f, "Hash Not Found: {:?} in Container {:?}",hash, self.container),
//             FileOrHash::Container =>  write!(f, "Container Not Found: {:?}", self.container),
//         }
       
//     }
// }

impl FileStorage {
    pub fn new(root_path: String) -> FileStorage {
        return FileStorage { root_path, merkle_tree: lru::LruCache::new(NonZeroUsize::new(10).unwrap()), hash_map: lru::LruCache::new(NonZeroUsize::new(10).unwrap()), meta_data: lru::LruCache::new(NonZeroUsize::new(10).unwrap()) };
    }

    pub async fn handle_request(&mut self, req: &FileRequestBody) -> Result<File, StorageError> {
        if let Some(hash) = &req.hashe {
            return self.get_content_hash(req.root_hash.clone(), hash.clone()).await;
        } else if let Some(path) = &req.file {
            return self.get_content(req.root_hash.clone(), &path).await;
        } else {
            return Err(RequestError::FileMissing.into());
        }
    }

    pub async fn handle_request_data(&mut self, req: &FileRequestBody) -> Result<Vec<u8>, StorageError> {
        let mut result = self.handle_request(req).await?;

        let mut buf = Vec::new();
        result.read_to_end(&mut buf).await.map_err(|e| { StorageError::Other(e.into()) })?;
        return Ok(buf);
    }

    pub fn container_path(&mut self, container: &str) -> PathBuf {
        return Path::new(&format!("{}{}", self.root_path, container)).into();
    }

    #[async_recursion]
    async fn get_content(&mut self, container: HashVec, path: &str) -> Result<File, StorageError> {
        //Check Container
        let container_name = hex::encode(&container);
        println!("Try Access: {}", container_name);
        let container_path = self.container_path(&container_name);


        if !container_path.exists() {
            println!("Container does \"{}\" not exist", &container_name);
            return Err(FileNotFound::File{container : container.clone(), file: path.to_string()}.into());
        }

        //check Path exist, return if exist
        let path = Path::new(path);
        let path_to_test = container_path.join(path);
        if path_to_test.exists() && path_to_test.is_file() {
            let f = File::open(&path_to_test).await;

            //let mut f = web::block(|| std::fs::File::create(&path_to_test)).await??;
            return Ok(f.map_err(|e| StorageError::Other(e.into()))?);
        }

        println!("path does \"{}\" not exist", path.display());

        fn get_path_element(start: &Path, elements: &Vec<Component>, range: Range<usize>) -> PathBuf {
            let mut concatenate = PathBuf::from(start);
            for n in range {
                let ele = elements[n];
                concatenate.push(ele);
            }
            return concatenate;
        }

        //Find highest folder existing
        let elements: Vec<Component> = path.components().collect();
        let mut i: usize = 0;
        for n in 0..elements.len() {
            
            let path_to_test = get_path_element(&container_path, &elements, 0..n);
            println!("pathToTest:  \"{}\", i:{}",path_to_test.display(), n);
            if path_to_test.exists() && path_to_test.is_dir() {
                i = n;
            } else {
                break;
            }
        }
        println!("i:  \"{}\"", i);

        if i == 0 {
            return Err(FileNotFound::File{container, file: path.display().to_string()}.into());
        }

        let dynamic_path = get_path_element(&PathBuf::new(), &elements, 0..i);
        let relativ_sub_path = get_path_element(&PathBuf::new(), &elements, i..elements.len());

        println!("dynamic_path:  \"{}\"", dynamic_path.display());
        println!("relativ_sub_path:  \"{}\"",relativ_sub_path.display());
        let last_existing_path = container_path.join(dynamic_path);

        //Check highest Folder is Referencing Folder(Contains Only 1 File named Reference.json)
        let subitems = last_existing_path.read_dir().map_err(|e| StorageError::Other(e.into()))?;

   

        let reference = single(subitems)
            .map_err(|_| {
                return FileNotFound::File{container : container.clone(), file: path.display().to_string()};
                //return Box::new(StorageError::new(format!("Path {} not found in Container {}! Dynamic Link Folder not found as well", path.display(), container_name)));
            })?
            .map_err(|e| StorageError::Other(e.into()))?;
        println!("Only 1 File!");
        if !reference.path().is_file() || reference.file_name() != "REFERENCE.json" {
            return Err( FileNotFound::File{container : container, file: path.display().to_string()}.into());
            //return Err(StorageError::new(format!("Path {} not found in Container {}! Dynamic Link Folder not found as well", path.display(), container_name)).into());
        }
        println!("File is REFERENCE.json");
        //Open Content from Reference Folder!
        let reference = fs::read_to_string(&reference.path()).map_err(|e| StorageError::Other(e.into()))?;
        let reference: Reference = serde_json::from_str(&reference).unwrap();
        return self.get_content(reference.reference, relativ_sub_path.to_str().unwrap()).await;
    }

    pub async fn post_content(&mut self, container: &HashVec, path: &str) -> Result<File, StorageError> {
        //Check Container
        let container_name = hex::encode(container);
        println!("Try Access: {}", container_name);
        let container_path = self.container_path(&container_name);

        // if !container_path.exists() {
        //     println!("create container directory: {}", &container_path);
        //     async_std::fs::create_dir_all(&container_path).await.map_err(|e| StorageError::Other(e.into()))?;
        // }

        //check Path exist, return if exist
        let path = Path::new(path);
        let path_to_test = container_path.join(path);

        let folder = path_to_test.parent().ok_or(RequestError::PathNoFile)?;

        if !folder.exists() {
            println!("create \"{}\" directory!", &path_to_test.display());
            async_std::fs::create_dir_all(&folder).await.map_err(|e| StorageError::Other(e.into()))?;
        }

        let f = File::create(&path_to_test).await;
        return Ok(f.map_err(|e| StorageError::Other(e.into()))?);
    }

    async fn get_content_hash(&mut self, container: HashVec, hash: HashVec) -> Result<File, StorageError> {
        let container_name = hex::encode(&container);
        let container_path = self.container_path(&container_name);

        if !container_path.exists() {
            return Err(FileNotFound::Container{container: container.clone()}.into());
        }

        let result = self.hash_map.get(&container);

        if let None = result {
            let map = load_hash_map();

            let path = map.get(&hash);

            if let None = path {
                return Err(FileNotFound::Container{container}.into());
            }
            let path = path.unwrap().clone();

            self.hash_map.push(container.clone(), map);
            return self.get_content(container, &path).await;
        } else {
            let map = result.unwrap();

            let path = map.get(&hash);

            if let None = path {
                return Err(FileNotFound::Container{container}.into());
            }

            let path = path.unwrap().clone();
            return self.get_content(container, &path).await;
        }
    }

    pub async fn get_merkle_tree(&mut self, container: HashVec) -> Result<String, StorageError> {
        let container_name = hex::encode(&container);
        let container_path = self.container_path(&container_name);

        if !container_path.exists() {
            return Err(FileNotFound::Container{container : container.clone()}.into());
        }

        //let result = self.merkle_tree.get(&container);
        //if let Some(merkle_tree) = result {
        //    return Ok(merkle_tree.clone());
        //}
     
        let merkle_tree_path = container_path.join(container_name.clone() + "_Tree.json");
        println!("mt path:{}", &merkle_tree_path.display());
        if !merkle_tree_path.exists() {
            println!("Generating Merkle Tree from Path:");
            let merkle_tree = MerkleTreeHash::generate_from_path(&container_path).await?;
            merkle_tree.save(&merkle_tree_path)?;
        }
        println!("Reading Merkle Tree from Path:");
        let result = fs::read_to_string(&merkle_tree_path).map_err(|e| StorageError::Other(e.into()))?;
        println!("Readed Merkle Tree from Path:");
        //self.merkle_tree.push(container, result.clone());
        return Ok(result);
    }

    fn get_metadata(&mut self, container: HashVec, path: &str) -> Result<FileMetaData, StorageError> {
        todo!()
    }

    fn get_container_metadata(&self, container: HashVec, path: &str) -> Result<ContainerMetaData, StorageError> {
        todo!()
    }
}

fn single<T, I>(mut iter: T) -> Result<I, anyhow::Error> where T: Iterator<Item = I> {
    match iter.next() {
        None => Err(anyhow::anyhow!("No Item Found")),
        Some(element) => {
            if iter.next().is_none() { Ok(element) } else { Err(anyhow::anyhow!("No Item Found")) }
        }
    }
}

fn load_hash_map() -> HashMap<HashVec, String> {
    todo!()
}