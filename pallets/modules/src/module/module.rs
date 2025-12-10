use crate::{AccountIdOf, BalanceOf, Block, StorageReference};
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{
    sp_runtime::{BoundedVec, Percent},
    DebugNoBound, EqNoBound, PartialEqNoBound,
};
use scale_info::TypeInfo;

pub type ModuleTitle<T> = BoundedVec<u8, <T as crate::Config>::MaxModuleTitleLength>;

#[derive(
    DebugNoBound,
    Encode,
    Decode,
    DecodeWithMemTracking,
    MaxEncodedLen,
    TypeInfo,
    PartialEqNoBound,
    EqNoBound,
)]
#[scale_info(skip_type_params(T))]
pub struct Module<T: crate::Config> {
    pub owner: AccountIdOf<T>,
    pub id: u64,
    pub title: ModuleTitle<T>,
    pub data: StorageReference<T>,
    pub collateral: BalanceOf<T>,
    pub take: Percent,
    pub created_at: Block,
    pub last_updated: Block,
}
