use frame_support::traits::Currency;

pub(super) type BalanceOf<T> =
  <<T as crate::Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

pub(super) type AccountIdOf<T> = <T as frame_system::Config>::AccountId;

pub(super) type Block = u64;

pub(super) type StorageReference<T> =
  Option<frame_support::sp_runtime::BoundedVec<u8, <T as crate::Config>::MaxStorageReferenceLength>>;