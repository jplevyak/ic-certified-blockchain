use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_cdk::export::candid::candid_method;
use ic_certified_map::{AsHashTree, Hash, RbTree};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{log::Log, DefaultMemoryImpl, StableBTreeMap, Storable};
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
    data: Vec<Blob>,
    previous_hash: Hash,
}

impl Storable for BlobHash {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        Decode!(&bytes, Self).unwrap()
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
    static AUTH: RefCell<StableBTreeMap<Memory, Blob, u64>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))),
            MAX_KEY_SIZE,
            MAX_VALUE_SIZE
        )
    );
    static LAST_HASH: Hash = Hash::default();
    static TREE: RefCell<BlockTree> = RefCell::new(BlockTree::new());
    static DATA: RefCell<Data> = RefCell::new(Data::new());
}

#[ic_cdk_macros::update(guard = "is_authorized")]
#[candid_method]
async fn append(data: Data) {
    construct_certification_tree(&data);
    // Wait till the next block so that we have the certified data.
    let _: (Vec<u8>,) = ic_cdk::call(Principal::management_canister(), "raw_rand", ())
        .await
        .unwrap();
    append_certified_blocks_to_log();
}

fn construct_certification_tree(data: &Data) {
    TREE.with(|t| {
        let mut t = t.borrow_mut();
        *t = RbTree::new();
        for (i, d) in data.iter().enumerate() {
            t.insert(i.to_be_bytes().to_vec(), sha2::Sha256::digest(d).into()); // For lexigraphic order.
        }
        ic_cdk::api::set_certified_data(&ic_certified_map::labeled_hash(
            b"certified_blocks",
            &t.root_hash(),
        ));
    });
    DATA.with(|d| {
        *d.borrow_mut() = data.to_vec();
    });
}

fn append_certified_blocks_to_log() {
    let block = Block {
        certificate: ic_cdk::api::data_certificate().unwrap(),
        data: DATA.with(|d| d.take()),
        previous_hash: LAST_HASH.with(|h| *h),
    };
    LOG.with(|l| l.borrow_mut().append(&Encode!(&block).unwrap()).unwrap());
}

#[ic_cdk_macros::update(guard = "is_authorized")]
#[candid_method]
fn append_unique(_data: Data) {}

#[ic_cdk_macros::query]
#[candid_method]
fn get_block(index: u64) -> Block {
    LOG.with(|m| candid::decode_one(&m.borrow().get(index as usize).unwrap()).unwrap())
}

#[ic_cdk_macros::query]
#[candid_method]
fn find_data(hash: Hash) -> Option<u64> {
    MAP.with(|m| m.borrow().get(&BlobHash(hash)))
}

#[ic_cdk_macros::query]
#[candid_method]
fn last() -> u64 {
    LOG.with(|l| l.borrow().len() as u64)
}

#[ic_cdk_macros::init]
fn init() {
    authorize_caller();
}

#[ic_cdk_macros::post_upgrade]
fn post_upgrade() {
    authorize_caller();
}

fn authorize_caller() {
    AUTH.with(|a| {
        a.borrow_mut()
            .insert(ic_cdk::caller().as_slice().to_vec(), 1)
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
