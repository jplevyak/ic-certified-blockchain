use candid::{CandidType, Deserialize, Encode, Principal};
use ic_cdk::export::candid::candid_method;
use ic_certified_map::{AsHashTree, Hash, RbTree};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{log::Log, DefaultMemoryImpl, StableBTreeMap, Storable};
use serde::Serialize;
use sha2::Digest;
use std::fmt::Debug;
use std::{borrow::Cow, cell::RefCell};

type Memory = VirtualMemory<DefaultMemoryImpl>;
type Blob = Vec<u8>;
type Data = Vec<Blob>;
type BlockTree = RbTree<Blob, Hash>;

const MAX_KEY_SIZE: u32 = 32;
const MAX_VALUE_SIZE: u32 = 8;

#[derive(Clone, Debug, CandidType, Deserialize)]
struct BlobHash(Hash);

#[derive(Clone, Debug, CandidType, Deserialize)]
struct Block {
    certificate: Blob,
    tree: Blob,
    data: Vec<Blob>,
    previous_hash: Hash,
}

impl Storable for BlobHash {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.0.to_vec())
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        BlobHash(bytes.try_into().unwrap())
    }
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static LOG: RefCell<Log<Memory, Memory>> = RefCell::new(
        Log::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
        ).unwrap()
    );
    static MAP: RefCell<StableBTreeMap<Memory, BlobHash, u64>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
            MAX_KEY_SIZE,
            MAX_VALUE_SIZE
        )
    );
    static AUTH: RefCell<StableBTreeMap<Memory, Blob, u8>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))),
            MAX_KEY_SIZE,
            1
        )
    );
    static DATA: RefCell<Data> = RefCell::new(Data::default());
    static TREE: RefCell<BlockTree> = RefCell::new(BlockTree::default());
}

#[ic_cdk_macros::update(guard = "is_authorized")]
#[candid_method]
fn prepare(data: Data) -> Blob {
    if DATA.with(|d| d.borrow().len()) > 0 {
        ic_cdk::trap("Block already prepared");
    }
    let mut tree = BlockTree::new();
    for (i, d) in data.iter().enumerate() {
        let hash: [u8; 32] = sha2::Sha256::digest(d).into();
        let i = i as u32;
        tree.insert(i.to_be_bytes().to_vec(), hash); // For lexigraphic order.
    }
    DATA.with(|d| {
        *d.borrow_mut() = data.to_vec();
    });
    let root_hash = tree.root_hash();
    TREE.with(|d| {
        *d.borrow_mut() = tree;
    });
    let certified_data = &ic_certified_map::labeled_hash(b"certified_blocks", &root_hash);
    ic_cdk::api::set_certified_data(certified_data);
    certified_data.to_vec()
}

#[ic_cdk_macros::query]
#[candid_method]
fn get_certificate() -> Option<Blob> {
    ic_cdk::api::data_certificate()
}

#[ic_cdk_macros::update(guard = "is_authorized")]
#[candid_method]
fn unprepare() -> Data {
    TREE.with(|t| t.take());
    DATA.with(|d| d.take())
}

#[ic_cdk_macros::update(guard = "is_authorized")]
#[candid_method]
fn append(certificate: Blob) -> Option<u64> {
    let data = DATA.with(|d| d.take());
    if data.len() == 0 {
        return None;
    }
    let index = LOG.with(|l| l.borrow().len());
    let tree = TREE.with(|t| t.take());
    MAP.with(|m| {
        let mut m = m.borrow_mut();
        for (_, h) in tree.iter() {
            m.insert(BlobHash(*h), index as u64).unwrap();
        }
        let hash = sha2::Sha256::digest(Encode!(&data).unwrap()).into();
        m.insert(BlobHash(hash), index as u64).unwrap();
    });
    LOG.with(|l| {
        let l = l.borrow_mut();
        let mut previous_hash = <[u8; 32]>::default();
        if l.len() > 0 {
            previous_hash =
                sha2::Sha256::digest(Encode!(&l.get(l.len() - 1).unwrap()).unwrap()).into();
        }
        let hash_tree = ic_certified_map::labeled(b"certified_blocks", tree.as_hash_tree());
        let mut serializer = serde_cbor::ser::Serializer::new(vec![]);
        serializer.self_describe().unwrap();
        hash_tree.serialize(&mut serializer).unwrap();
        let block = Block {
            certificate,
            tree: serializer.into_inner(),
            data,
            previous_hash,
        };
        let encoded_block = Encode!(&block).unwrap();
        l.append(&encoded_block).unwrap();
        Some(l.len() as u64 - 1)
    })
}

#[ic_cdk_macros::query]
#[candid_method]
fn get_block(index: u64) -> Block {
    LOG.with(|m| candid::decode_one(&m.borrow().get(index as usize).unwrap()).unwrap())
}

#[ic_cdk_macros::query]
#[candid_method]
fn find(hash: Hash) -> Option<u64> {
    MAP.with(|m| m.borrow().get(&BlobHash(hash)))
}

#[ic_cdk_macros::query]
#[candid_method]
fn length() -> u64 {
    LOG.with(|l| l.borrow().len() as u64)
}

#[ic_cdk_macros::init]
fn init() {
    authorize_principal(&ic_cdk::caller());
}

#[ic_cdk_macros::query]
#[candid_method]
fn get_authorized() -> Vec<Principal> {
    let mut authorized = Vec::<Principal>::new();
    AUTH.with(|a| {
        for (k, _) in a.borrow().iter() {
            authorized.push(Principal::from_slice(&k));
        }
    });
    authorized
}

#[ic_cdk_macros::update(guard = "is_authorized")]
#[candid_method]
fn authorize(principal: Principal) {
    authorize_principal(&principal);
}

#[ic_cdk_macros::update(guard = "is_authorized")]
#[candid_method]
fn deauthorize(principal: Principal) {
    AUTH.with(|a| {
        a.borrow_mut()
            .remove(&principal.as_slice().to_vec())
            .unwrap();
    });
}

fn authorize_principal(principal: &Principal) {
    AUTH.with(|a| {
        a.borrow_mut()
            .insert(principal.as_slice().to_vec(), 1)
            .unwrap();
    });
}

fn is_authorized() -> Result<(), String> {
    AUTH.with(|a| {
        if a.borrow()
            .contains_key(&ic_cdk::caller().as_slice().to_vec())
        {
            Ok(())
        } else {
            Err("You are not authorized".to_string())
        }
    })
}

ic_cdk::export::candid::export_service!();

#[ic_cdk_macros::query(name = "__get_candid_interface_tmp_hack")]
fn export_candid() -> String {
    __export_service()
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    println!("{}", export_candid());
}

#[cfg(target_arch = "wasm32")]
fn main() {}
