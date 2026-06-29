use alloy_primitives::{Address, U256};
use std::marker::PhantomData;

use crate::error::{PrecompileError, Result};
use crate::storage::types::{
    BinaryHeap as StorageBinaryHeap, Mapping, Slot, Storable, StorageCircularBuffer, StorageDeque,
    StorageKey, StorageSet, StorageVec,
};
use crate::storage::StorageHandle;

pub type Value<'storage, T> = Slot<'storage, T>;
pub type List<'storage, T> = StorageVec<'storage, T>;
pub type Set<'storage, T> = StorageSet<'storage, T>;
pub type BinaryHeap<'storage, T> = StorageBinaryHeap<'storage, T>;
pub type Deque<'storage, T> = StorageDeque<'storage, T>;
pub type CircularBuffer<'storage, T> = StorageCircularBuffer<'storage, T>;
pub type Optional<T> = Option<T>;
pub type Deprecated<T> = T;

pub trait StorageRecord: Sized {
    type Key: StorageKey + Clone;

    const SLOTS: u64;

    fn key(&self) -> Self::Key;

    fn exists(entry: &RecordEntry<'_, Self::Key, Self>) -> Result<bool>;
    fn load(entry: &RecordEntry<'_, Self::Key, Self>) -> Result<Option<Self>>;
    fn create(entry: &RecordEntry<'_, Self::Key, Self>, value: &Self) -> Result<()>;
    fn update(entry: &RecordEntry<'_, Self::Key, Self>, value: &Self) -> Result<()>;
    fn delete(entry: &RecordEntry<'_, Self::Key, Self>) -> Result<()>;
}

pub struct Map<'storage, K, V> {
    base_slot: U256,
    address: Address,
    storage: StorageHandle<'storage>,
    _key: PhantomData<K>,
    _value: PhantomData<V>,
}

impl<'storage, K, V> Clone for Map<'storage, K, V> {
    fn clone(&self) -> Self {
        Self {
            base_slot: self.base_slot,
            address: self.address,
            storage: self.storage.clone(),
            _key: PhantomData,
            _value: PhantomData,
        }
    }
}

impl<'storage, K, V> Map<'storage, K, V> {
    pub fn new(base_slot: U256, address: Address, storage: StorageHandle<'storage>) -> Self {
        Self {
            base_slot,
            address,
            storage,
            _key: PhantomData,
            _value: PhantomData,
        }
    }

    pub fn base_slot(&self) -> U256 {
        self.base_slot
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn storage(&self) -> StorageHandle<'storage> {
        self.storage.clone()
    }
}

impl<'storage, K: StorageKey, V: Storable> Map<'storage, K, V> {
    pub fn slot(&self, key: &K) -> Slot<'storage, V> {
        Mapping::new(self.base_slot, self.address, self.storage.clone()).get(key)
    }

    pub fn read(&self, key: &K) -> Result<V> {
        self.slot(key).read()
    }

    pub fn write(&self, key: &K, value: V) -> Result<()> {
        self.slot(key).write(value)
    }

    pub fn clear(&self, key: &K) -> Result<()> {
        self.slot(key).delete()
    }
}

impl<'storage, K: StorageKey, T: Storable> Map<'storage, K, StorageVec<'storage, T>> {
    pub fn list(&self, key: &K) -> StorageVec<'storage, T> {
        StorageVec::new(
            key.mapping_slot(self.base_slot),
            self.address,
            self.storage.clone(),
        )
    }
}

impl<'storage, K, V> Map<'storage, K, V>
where
    K: StorageKey + Clone,
    V: StorageRecord<Key = K>,
{
    pub fn exists(&self, key: K) -> Result<bool> {
        self.entry(key).exists()
    }

    pub fn get(&self, key: K) -> Result<Option<V>> {
        self.entry(key).load()
    }

    pub fn create(&self, value: &V) -> Result<()> {
        self.entry(value.key()).create(value)
    }

    pub fn update(&self, value: &V) -> Result<()> {
        self.entry(value.key()).update(value)
    }

    pub fn delete(&self, key: K) -> Result<()> {
        self.entry(key).delete()
    }

    pub fn entry(&self, key: K) -> RecordEntry<'storage, K, V> {
        RecordEntry::new(self.base_slot, self.address, self.storage.clone(), key)
    }
}

pub struct RecordEntry<'storage, K, V> {
    base_slot: U256,
    address: Address,
    storage: StorageHandle<'storage>,
    key: K,
    _value: PhantomData<V>,
}

impl<'storage, K: Clone, V> Clone for RecordEntry<'storage, K, V> {
    fn clone(&self) -> Self {
        Self {
            base_slot: self.base_slot,
            address: self.address,
            storage: self.storage.clone(),
            key: self.key.clone(),
            _value: PhantomData,
        }
    }
}

impl<'storage, K, V> RecordEntry<'storage, K, V> {
    pub fn new(
        base_slot: U256,
        address: Address,
        storage: StorageHandle<'storage>,
        key: K,
    ) -> Self {
        Self {
            base_slot,
            address,
            storage,
            key,
            _value: PhantomData,
        }
    }

    pub fn base_slot(&self) -> U256 {
        self.base_slot
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn storage(&self) -> StorageHandle<'storage> {
        self.storage.clone()
    }

    pub fn key_ref(&self) -> &K {
        &self.key
    }
}

impl<'storage, K, V> RecordEntry<'storage, K, V>
where
    K: StorageKey + Clone,
    V: StorageRecord<Key = K>,
{
    pub fn key(&self) -> K {
        self.key.clone()
    }

    pub fn exists(&self) -> Result<bool> {
        V::exists(self)
    }

    pub fn load(&self) -> Result<Option<V>> {
        V::load(self)
    }

    pub fn create(&self, value: &V) -> Result<()> {
        V::create(self, value)
    }

    pub fn update(&self, value: &V) -> Result<()> {
        V::update(self, value)
    }

    pub fn delete(&self) -> Result<()> {
        V::delete(self)
    }
}

pub struct OptionalField<'storage, K, T> {
    present: Mapping<'storage, K, bool>,
    value: Mapping<'storage, K, T>,
    key: K,
}

impl<'storage, K, T> OptionalField<'storage, K, T>
where
    K: StorageKey + Clone,
    T: Storable,
{
    pub fn new(
        base_slot: U256,
        address: Address,
        storage: StorageHandle<'storage>,
        key: K,
    ) -> Self {
        Self {
            present: Mapping::new(base_slot, address, storage.clone()),
            value: Mapping::new(base_slot + U256::from(1u64), address, storage),
            key,
        }
    }

    pub fn read(&self) -> Result<Option<T>> {
        if !self.present.read(&self.key)? {
            return Ok(None);
        }
        Ok(Some(self.value.read(&self.key)?))
    }

    pub fn write(&self, value: Option<T>) -> Result<()> {
        match value {
            Some(value) => {
                self.present.write(&self.key, true)?;
                self.value.write(&self.key, value)
            }
            None => self.delete(),
        }
    }

    pub fn delete(&self) -> Result<()> {
        self.present.write(&self.key, false)?;
        self.value.write(&self.key, T::from_word(U256::ZERO))
    }
}

pub fn missing_record_err(name: &str) -> PrecompileError {
    PrecompileError::Revert(format!("{name} not found"))
}

pub fn existing_record_err(name: &str) -> PrecompileError {
    PrecompileError::Revert(format!("{name} already exists"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::hashmap::HashMapStorageProvider;
    use alloy_primitives::address;

    #[test]
    fn optional_field_roundtrip() {
        let mut provider = HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        let field: OptionalField<u32, u64> = OptionalField::new(
            U256::from(5u64),
            address!("0x0000000000000000000000000000000000001003"),
            storage,
            7u32,
        );

        assert_eq!(field.read().unwrap(), None);
        field.write(Some(42)).unwrap();
        assert_eq!(field.read().unwrap(), Some(42));
        field.delete().unwrap();
        assert_eq!(field.read().unwrap(), None);
    }

    #[test]
    fn map_list_accesses_independent_lists() {
        let mut provider = HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        let map: Map<'_, U256, StorageVec<'_, u64>> = Map::new(
            U256::from(7u64),
            address!("0x0000000000000000000000000000000000001003"),
            storage,
        );

        let first = map.list(&U256::from(1u64));
        let second = map.list(&U256::from(2u64));

        first.push(10).unwrap();
        first.push(20).unwrap();
        second.push(30).unwrap();

        assert_eq!(first.read_all().unwrap(), vec![10, 20]);
        assert_eq!(second.read_all().unwrap(), vec![30]);
    }
}
