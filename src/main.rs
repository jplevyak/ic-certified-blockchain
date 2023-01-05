use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use hash_tree::{HashTree, LookupResult};
use ic_cdk::export::candid::candid_method;
use ic_certified_map::{AsHashTree, Hash, RbTree};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{
    cell::Cell as StableCell, log::Log, DefaultMemoryImpl, StableBTreeMap, Storable,
};
use num::FromPrimitive;
use serde::Serialize;
use sha2::Digest;
use std::convert::TryInto;
use std::fmt::Debug;
use std::{borrow::Cow, cell::RefCell};
#[macro_use]
extern crate num_derive;

mod hash_tree;

type Memory = VirtualMemory<DefaultMemoryImpl>;
type Blob = Vec<u8>;
type Data = Vec<Blob>;
type BlockTree = RbTree<Blob, Hash>;
type Callers = Vec<Principal>;

const MAX_KEY_SIZE: u32 = 32;
const MAX_VALUE_SIZE: u32 = 8;

#[derive(Clone, Debug, CandidType, Deserialize, FromPrimitive)]
enum Auth {
    User,
    Admin,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct Authorization {
    id: Principal,
    auth: Auth,
}

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
struct BlobHash(Hash);

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
struct Pending {
    data: Data,
    callers: Callers,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct Block {
    certificate: Blob,
    tree: Blob,
    data: Data,
    callers: Callers,
    previous_hash: Hash,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct ReplicaCertificate {
    tree: HashTree<'static>,
    signature: serde_bytes::ByteBuf,
}

impl Storable for BlobHash {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.0.to_vec())
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        let hash: [u8; 32] = bytes.try_into().unwrap();
        BlobHash(hash)
    }
}

impl Storable for Pending {
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
        StableBTreeMap::init_with_sizes(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
            MAX_KEY_SIZE,
            MAX_VALUE_SIZE
        )
    );
    static AUTH: RefCell<StableBTreeMap<Memory, Blob, u32>> = RefCell::new(
        StableBTreeMap::init_with_sizes(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))),
            MAX_KEY_SIZE,
            4
        )
    );
    static PENDING: RefCell<StableCell<Pending, Memory>> = RefCell::new(StableCell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4))),
            Pending::default()).unwrap());
    static PREVIOUS_HASH: RefCell<StableCell<BlobHash, Memory>> = RefCell::new(StableCell::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5))),
        <BlobHash>::default()).unwrap());
}

#[ic_cdk_macros::update(guard = "is_authorized_user")]
#[candid_method]
fn prepare(data: Data) -> Blob {
    if PENDING.with(|p| p.borrow().get().data.len()) > 0 {
        ic_cdk::trap("Block already prepared");
    }
    prepare_some(data)
}

fn hash_pending(pending: &Pending, i: usize) -> [u8; 32] {
    let caller_hash: [u8; 32] = sha2::Sha256::digest(pending.callers[i]).into();
    let data_hash: [u8; 32] = sha2::Sha256::digest(pending.data[i].clone()).into();
    let mut hasher = sha2::Sha256::new();
    hasher.update(caller_hash);
    hasher.update(data_hash);
    let hash: [u8; 32] = hasher.finalize().into();
    ic_cdk::println!(
        "{} {} {}",
        hex::encode(caller_hash),
        hex::encode(data_hash),
        hex::encode(hash)
    );
    hash
}

fn build_tree(pending: &Pending, previous_hash: &Hash) -> BlockTree {
    let mut tree = BlockTree::default();
    for (i, _) in pending.data.iter().enumerate() {
        tree.insert(i.to_be_bytes().to_vec(), hash_pending(&pending, i));
    }
    tree.insert("previous_hash".as_bytes().to_vec(), *previous_hash); // For lexigraphic order.
    tree
}

fn take_cell<T>(c: &mut StableCell<T, Memory>) -> T
where
    T: Clone + Default + Storable,
{
    let v = c.get().clone();
    c.set(T::default()).unwrap();
    v
}

#[ic_cdk_macros::update(guard = "is_authorized_user")]
#[candid_method]
fn prepare_some(new_data: Data) -> Blob {
    let mut pending = PENDING.with(|d| take_cell(&mut d.borrow_mut()));
    for d in new_data.iter() {
        pending.data.push(d.to_vec());
        pending.callers.push(ic_cdk::caller());
    }
    let previous_hash = get_previous_hash();
    let tree = build_tree(&pending, &previous_hash);
    PENDING.with(|p| {
        p.borrow_mut().set(pending).unwrap();
    });
    set_certificate(&tree.root_hash())
}

fn set_certificate(root_hash: &Hash) -> Blob {
    let certified_data = &ic_certified_map::labeled_hash(b"certified_blocks", &root_hash);
    ic_cdk::api::set_certified_data(certified_data);
    certified_data.to_vec()
}

#[ic_cdk_macros::query]
#[candid_method]
fn get_certificate() -> Option<Blob> {
    if PENDING.with(|p| p.borrow().get().data.len()) == 0 {
        None
    } else {
        ic_cdk::api::data_certificate()
    }
}

fn get_previous_hash() -> Hash {
    let mut previous_hash = PREVIOUS_HASH.with(|h| h.borrow().get().0.clone());
    LOG.with(|l| {
        let l = l.borrow();
        if l.len() > 0 {
            previous_hash =
                sha2::Sha256::digest(Encode!(&l.get(l.len() - 1).unwrap()).unwrap()).into();
        }
    });
    previous_hash
}

#[ic_cdk_macros::update(guard = "is_authorized_user")]
#[candid_method]
fn commit(certificate: Blob) -> Option<u64> {
    let pending = PENDING.with(|p| take_cell(&mut p.borrow_mut()));
    if pending.data.len() == 0 {
        return None;
    }
    let previous_hash = get_previous_hash();
    let tree = build_tree(&pending, &previous_hash);
    // Check that the certificate corresponds to our tree.  Note: we are
    // not fully verifying the certificate, just checking for races.
    let root_hash = tree.root_hash();
    let certified_data = &ic_certified_map::labeled_hash(b"certified_blocks", &root_hash);
    let cert: ReplicaCertificate = serde_cbor::from_slice(&certificate[..]).unwrap();
    let canister_id = ic_cdk::api::id();
    let canister_id = canister_id.as_slice();
    if let LookupResult::Found(certified_data_bytes) = cert.tree.lookup_path(&[
        "canister".into(),
        canister_id.into(),
        "certified_data".into(),
    ]) {
        assert!(certified_data == certified_data_bytes);
    } else {
        ic_cdk::trap("certificate mismatch");
    }
    let index = LOG.with(|l| l.borrow().len());
    MAP.with(|m| {
        let mut m = m.borrow_mut();
        for (_, h) in tree.iter() {
            m.insert(BlobHash(*h), index as u64).unwrap();
        }
        for d in pending.data.iter() {
            let hash = sha2::Sha256::digest(d).into();
            m.insert(BlobHash(hash), index as u64).unwrap();
        }
    });
    LOG.with(|l| {
        let l = l.borrow_mut();
        let hash_tree = ic_certified_map::labeled(b"certified_blocks", tree.as_hash_tree());
        let mut serializer = serde_cbor::ser::Serializer::new(vec![]);
        serializer.self_describe().unwrap();
        hash_tree.serialize(&mut serializer).unwrap();
        let block = Block {
            certificate,
            tree: serializer.into_inner(),
            data: pending.data,
            callers: pending.callers,
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

#[ic_cdk_macros::query]
#[candid_method]
fn last_hash() -> String {
    LOG.with(|l| {
        let l = l.borrow();
        if l.len() == 0 {
            return "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        }
        let previous_hash: [u8; 32] =
            sha2::Sha256::digest(Encode!(&l.get(l.len() - 1).unwrap()).unwrap()).into();
        hex::encode(previous_hash)
    })
}

#[ic_cdk_macros::init]
fn canister_init(previous_hash: Option<String>) {
    authorize_principal(&ic_cdk::caller(), Auth::Admin);
    if let Some(previous_hash) = previous_hash {
        let _x = hex::decode(&previous_hash).unwrap();
        if let Ok(previous_hash) = hex::decode(&previous_hash) {
            if previous_hash.len() == 32 {
                PREVIOUS_HASH.with(|h| {
                    h.borrow_mut()
                        .set(BlobHash(previous_hash.try_into().unwrap()))
                        .unwrap();
                });
                return;
            }
        }
        ic_cdk::trap("previous must be a 64 hex string");
    }
}

#[ic_cdk_macros::query]
#[candid_method]
fn get_authorized() -> Vec<Authorization> {
    let mut authorized = Vec::<Authorization>::new();
    AUTH.with(|a| {
        for (k, v) in a.borrow().iter() {
            if let Some(auth) = Auth::from_i32(v as i32) {
                authorized.push(Authorization {
                    id: Principal::from_slice(&k),
                    auth,
                });
            }
        }
    });
    authorized
}

#[ic_cdk_macros::update(guard = "is_authorized_admin")]
#[candid_method]
fn authorize(principal: Principal, value: Auth) {
    authorize_principal(&principal, value);
}

#[ic_cdk_macros::update(guard = "is_authorized_admin")]
#[candid_method]
fn deauthorize(principal: Principal) {
    AUTH.with(|a| {
        a.borrow_mut()
            .remove(&principal.as_slice().to_vec())
            .unwrap();
    });
}

fn authorize_principal(principal: &Principal, value: Auth) {
    AUTH.with(|a| {
        a.borrow_mut()
            .insert(principal.as_slice().to_vec(), value as u32)
            .unwrap();
    });
}

fn is_authorized_user() -> Result<(), String> {
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

fn is_authorized_admin() -> Result<(), String> {
    AUTH.with(|a| {
        if let Some(value) = a.borrow().get(&ic_cdk::caller().as_slice().to_vec()) {
            if value >= Auth::Admin as u32 {
                Ok(())
            } else {
                Err("You are not authorized as Admin".to_string())
            }
        } else {
            Err("You are not authorized".to_string())
        }
    })
}

#[ic_cdk_macros::post_upgrade]
fn post_upgrade() {
    let previous_hash = get_previous_hash();
    let tree = PENDING.with(|p| build_tree(&p.borrow().get(), &previous_hash));
    set_certificate(&tree.root_hash());
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
