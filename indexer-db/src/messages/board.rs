use crate::SharedImmutable;
use anyhow::Result;
use fjall::{PartitionCreateOptions, ReadTransaction, WriteTransaction};
use zerocopy::big_endian::U64;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[repr(C)]
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Immutable, FromBytes, IntoBytes, Unaligned, KnownLayout,
)]
pub struct BoardPostByCreatedAtKey {
    pub created_at_ms: U64,
    pub post_uuid: [u8; 16],
}

#[derive(Clone)]
pub struct BoardPostByIdPartition(fjall::TxPartition);

impl BoardPostByIdPartition {
    pub fn new(keyspace: &fjall::TxKeyspace) -> Result<Self> {
        Ok(Self(keyspace.open_partition(
            "board_post_by_id",
            PartitionCreateOptions::default(),
        )?))
    }

    pub fn insert_wtx(&self, wtx: &mut WriteTransaction, post_id: &str, json_bytes: &[u8]) {
        wtx.insert(&self.0, post_id.as_bytes(), json_bytes);
    }

    pub fn get_rtx(
        &self,
        rtx: &ReadTransaction,
        post_id: &str,
    ) -> Result<Option<SharedImmutable<[u8]>>> {
        rtx.get(&self.0, post_id.as_bytes())
            .map(|value| value.map(SharedImmutable::new))
            .map_err(anyhow::Error::from)
    }
}

#[derive(Clone)]
pub struct BoardPostByCreatedAtPartition(fjall::TxPartition);

impl BoardPostByCreatedAtPartition {
    pub fn new(keyspace: &fjall::TxKeyspace) -> Result<Self> {
        Ok(Self(keyspace.open_partition(
            "board_post_by_created_at",
            PartitionCreateOptions::default(),
        )?))
    }

    pub fn insert_wtx(
        &self,
        wtx: &mut WriteTransaction,
        key: &BoardPostByCreatedAtKey,
        json_bytes: &[u8],
    ) {
        wtx.insert(&self.0, key.as_bytes(), json_bytes);
    }

    pub fn iter_all(
        &self,
        rtx: &ReadTransaction,
    ) -> impl DoubleEndedIterator<
        Item = Result<(SharedImmutable<BoardPostByCreatedAtKey>, SharedImmutable<[u8]>)>,
    > + '_ {
        rtx.iter(&self.0).map(|item| {
            let (key, value) = item?;
            Ok((SharedImmutable::new(key), SharedImmutable::new(value)))
        })
    }
}

#[derive(Clone)]
pub struct BoardClientGeneratedIdToPostIdPartition(fjall::TxPartition);

impl BoardClientGeneratedIdToPostIdPartition {
    pub fn new(keyspace: &fjall::TxKeyspace) -> Result<Self> {
        Ok(Self(keyspace.open_partition(
            "board_client_generated_id_to_post_id",
            PartitionCreateOptions::default(),
        )?))
    }

    pub fn insert_wtx(
        &self,
        wtx: &mut WriteTransaction,
        client_generated_id: &str,
        post_id: &str,
    ) {
        wtx.insert(&self.0, client_generated_id.as_bytes(), post_id.as_bytes());
    }

    pub fn get_rtx(
        &self,
        rtx: &ReadTransaction,
        client_generated_id: &str,
    ) -> Result<Option<SharedImmutable<[u8]>>> {
        rtx.get(&self.0, client_generated_id.as_bytes())
            .map(|value| value.map(SharedImmutable::new))
            .map_err(anyhow::Error::from)
    }
}
