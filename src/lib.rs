#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_arithmetic::traits::BaseArithmetic;
use sp_core::{bounded::BoundedVec, Get, Pair, RuntimeDebug};
use std::fmt::Debug;

// RedStone packages oracle data off-chain into a specific encoded format, allowing an end-user to
// then submit data on-chain where it is unpacked and verified to provide access to oracle prices.
// This crate is intended to be used by Substrate pallets to easily unpack and verify that data.
// The current implementation uses ECDSA signing, so the below has been designed to allow for this
// base implementation, but also to allow for a more Substrate-optimised approach via config: e.g. a
// 'SubstrateSigner' could be incorporated into the RedStone oracle itself, potentially providing
// more efficient encoding of data using SCALE.

// More info at https://github.com/redstone-finance/redstone-oracles-monorepo/tree/main/packages/evm-connector#data-packing-off-chain-data-encoding

// NOTE: there is a reference implementation in the `near` directory which uses near_sdk::env::ecrecover
// to determine the signer of a package.

mod specifications;

// The config used to decode signed off-chain data packages to on-chain oracle data.
pub trait Config {
    // The type of data package specification.
    type DataPackageSpecification: DataPackageSpecification;
    // A converter for converting between a data point value and a result.
    // todo: can this be improved?
    type ValueConverter: TryConvert<
        <<Self as Config>::DataPackageSpecification as DataPackageSpecification>::Value,
        Self::Result,
    >;
    // The type of oracle result.
    type Result: BaseArithmetic + Copy + Debug;
    // The maximum number of data packages per payload, configured by the runtime.
    type MaxDataPackagesPerPayload: Get<u32>;
    // The maximum length of unsigned metadata, configured by the runtime.
    type MaxUnsignedMetadataLen: Get<u32>;
}

// A specification of a data package.
pub trait DataPackageSpecification {
    // The type of unique identifier of the data feed.
    type FeedId: Debug + PartialEq;
    // The type of data point value.
    type Value: Copy + Debug;
    // The type of timestamp.
    type Timestamp: Debug;
    // The type of signature scheme used to sign the data.
    type Signature: Pair;
    // The maximum data points per data package.
    type MaxDataPointsPerPackage: Get<u32> + Debug;

    // Verifies a data package by checking its signature against the provided authorised signers.
    fn verify<'a>(
        data_package: &DataPackage<
            DataPoint<Self::FeedId, Self::Value>,
            Self::MaxDataPointsPerPackage,
            Self::Timestamp,
            <Self::Signature as Pair>::Signature,
        >,
        authorised_signers: &'a [<Self::Signature as Pair>::Public],
    ) -> Option<&'a <Self::Signature as Pair>::Public>;
}

pub trait TryConvert<A, B> {
    type Error;
    fn try_convert(a: A) -> Result<B, Self::Error>;
}

#[derive(Decode, Encode, MaxEncodedLen, RuntimeDebug, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct Payload<
    DataPackage,
    MaxDataPackagesPerPayload: Get<u32>,
    MaxUnsignedMetadataLen: Get<u32>,
> {
    data: BoundedVec<DataPackage, MaxDataPackagesPerPayload>,
    unsigned_metadata: BoundedVec<u8, MaxUnsignedMetadataLen>,
}

impl<DataPackage, MaxDataPackagesPerPayload: Get<u32>, MaxUnsignedMetadataLen: Get<u32>>
    Payload<DataPackage, MaxDataPackagesPerPayload, MaxUnsignedMetadataLen>
{
    pub fn new(
        data: BoundedVec<DataPackage, MaxDataPackagesPerPayload>,
        unsigned_metadata: BoundedVec<u8, MaxUnsignedMetadataLen>,
    ) -> Payload<DataPackage, MaxDataPackagesPerPayload, MaxUnsignedMetadataLen> {
        Payload {
            data,
            unsigned_metadata,
        }
    }
}

#[derive(Encode, Decode, MaxEncodedLen, RuntimeDebug, TypeInfo)]
#[scale_info(skip_type_params(DataPoint, MaxDataPointsPerPackage, Timestamp, Signature))]
pub struct DataPackage<DataPoint, MaxDataPointsPerPackage: Get<u32>, Timestamp, Signature> {
    data_points: BoundedVec<DataPoint, MaxDataPointsPerPackage>,
    timestamp: Timestamp,
    signature: Signature,
}

impl<DataPoint, MaxDataPointsPerPackage: Get<u32>, Timestamp, Signature>
    DataPackage<DataPoint, MaxDataPointsPerPackage, Timestamp, Signature>
{
    pub fn new(
        data_points: BoundedVec<DataPoint, MaxDataPointsPerPackage>,
        timestamp: Timestamp,
        signature: Signature,
    ) -> DataPackage<DataPoint, MaxDataPointsPerPackage, Timestamp, Signature> {
        DataPackage {
            data_points,
            timestamp,
            signature,
        }
    }
}

#[derive(Encode, Decode, MaxEncodedLen, RuntimeDebug, TypeInfo)]
#[scale_info(skip_type_params(FeedId, Value))]
pub struct DataPoint<FeedId, Value> {
    feed_id: FeedId,
    value: Value,
}

#[derive(Debug)]
pub enum Error {
    CannotTakeMedianOfEmptyArray,
    ValueConversionError,
}

// Used internally within a pallet extrinsic to extract oracle values from submitted extrinsic parameter (of type `PayloadOf<T>`)
pub fn get_oracle_value<T: Config>(
    feed_id: &FeedIdOf<T>,
    unique_signers_threshold: u8,
    authorised_signers: &[SignerOf<T>],
    current_timestamp_milliseconds: u128,
    payload: &PayloadOf<T>,
) -> Result<T::Result, Error> {
    // todo: complete implementation
    let mut values: Vec<T::Result> = vec![];
    for package in &payload.data {
        if let Some(signer) =
            <<T as Config>::DataPackageSpecification as DataPackageSpecification>::verify(
                &package,
                authorised_signers,
            )
        {
            if !authorised_signers.contains(&signer) {
                continue;
            }

            for point in &package.data_points {
                if &point.feed_id == feed_id {
                    match T::ValueConverter::try_convert(point.value) {
                        Ok(value) => values.push(value),
                        Err(_) => return Err(Error::ValueConversionError),
                    }
                }
            }
        }
    }
    aggregate_values::<T>(&mut values)
}

// Taken as-is from reference implementation.
fn aggregate_values<T: Config>(values: &mut Vec<T::Result>) -> Result<T::Result, Error> {
    if values.len() == 0 {
        //panic!("Can not take median of an empty array");
        return Err(Error::CannotTakeMedianOfEmptyArray);
    }
    values.sort();
    // todo: use checked
    let mid = values.len() / 2;
    Ok(if values.len() % 2 == 0 {
        (values[mid - 1] + values[mid]) / 2.into()
    } else {
        values[mid]
    })
}

// Type helpers
pub type BoundedDataPointsOf<T> = BoundedVec<
    DataPointOf<T>,
    <<T as Config>::DataPackageSpecification as DataPackageSpecification>::MaxDataPointsPerPackage,
>;
pub type BoundedUnsignedMetadataOf<T> = BoundedVec<u8, <T as Config>::MaxUnsignedMetadataLen>;
pub type DataPointOf<T> = DataPoint<
    <<T as Config>::DataPackageSpecification as DataPackageSpecification>::FeedId,
    <<T as Config>::DataPackageSpecification as DataPackageSpecification>::Value,
>;
pub type DataPackageOf<T> = DataPackage<
    DataPointOf<T>,
    <<T as Config>::DataPackageSpecification as DataPackageSpecification>::MaxDataPointsPerPackage,
    <<T as Config>::DataPackageSpecification as DataPackageSpecification>::Timestamp,
    <<<T as Config>::DataPackageSpecification as DataPackageSpecification>::Signature as Pair>::Signature,
>;
pub type FeedIdOf<T> =
    <<T as Config>::DataPackageSpecification as DataPackageSpecification>::FeedId;
pub type PayloadOf<T> = Payload<
    DataPackageOf<T>,
    <T as Config>::MaxDataPackagesPerPayload,
    <T as Config>::MaxUnsignedMetadataLen,
>;
pub type SignerOf<T> =
    <<<T as Config>::DataPackageSpecification as DataPackageSpecification>::Signature as Pair>::Public;
pub type SignatureOf<T> =
    <<<T as Config>::DataPackageSpecification as DataPackageSpecification>::Signature as Pair>::Signature;
pub type TimestampOf<T> =
    <<T as Config>::DataPackageSpecification as DataPackageSpecification>::Timestamp;
pub type ValueOf<T> = <<T as Config>::DataPackageSpecification as DataPackageSpecification>::Value;

#[cfg(test)]
mod tests {
    use codec::{Decode, Encode};
    use sp_core::bounded::BoundedVec;
    use sp_core::ConstU32;

    #[test]
    fn bounded_vec_encodes_as_vec() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let bound_data: BoundedVec<u8, ConstU32<10>> = data.clone().try_into().unwrap();
        assert_eq!(data.encode(), bound_data.encode());
    }

    #[test]
    fn vec_exceeding_bounds_cannot_decode() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].encode();
        if let Err(error) = BoundedVec::<u8, ConstU32<10>>::decode(&mut &data[..]) {
            assert_eq!("BoundedVec exceeds its limit", error.to_string())
        } else {
            panic!()
        }
    }
}
