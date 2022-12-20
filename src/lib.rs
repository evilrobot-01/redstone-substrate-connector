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
// base implementation, but also to perhaps allow for a more Substrate-optimised approach via config:
// e.g. a 'SubstrateSigner' could be incorporated into the RedStone oracle itself (using ECDSA or
// SR25519), potentially providing more efficient encoding of data using the SCALE codec.

// More info at https://github.com/redstone-finance/redstone-oracles-monorepo/tree/main/packages/evm-connector#data-packing-off-chain-data-encoding

// NOTE: there is a reference implementation in the `near` directory attached which uses
// near_sdk::env::ecrecover to determine the signer of a package.

// Implementation options of the data package specifications in separate module.
mod specifications;

// The config used to decode signed off-chain data packages to on-chain oracle data.
// This trait could allow a Substrate runtime to configure the data-types used.
pub trait Config {
    // The type of data package specification.
    type DataPackageSpecification: DataPackageSpecification;
    // A converter for converting between a data point value and a result.
    // todo: improve
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

// A specification of a data package, effectively lifting the structure of a data package into a type
// and making it configurable. The specifications module contains two sample implementations.
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

// Main entry point: used internally within a pallet function (extrinsic/transaction) to extract
// oracle values from submitted extrinsic parameter (of type `PayloadOf<T>`).
// Note: This function has a generic type parameter which is used to inject the actual configuration,
// much the same way as pallet config works. This *could* allow runtimes to use slightly different
// implementations as required, provided there was sufficient benefit. A default config could be provided for most cases.
pub fn get_oracle_value<T: Config>(
    feed_id: &FeedIdOf<T>, // A type alias, specifying the FeedId type defined in supplied config.
    _unique_signers_threshold: u8,
    authorised_signers: &[SignerOf<T>], // A type alias, specifying the Signer type defined in supplied config.
    _current_timestamp_milliseconds: u128,
    payload: &PayloadOf<T>, // A type alias, specifying the payload type defined in supplied config.
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

// Simple trait for converting from data package value type (e.g. bytes) to a rust primitive type (e.g. u128).
pub trait TryConvert<A, B> {
    type Error;
    fn try_convert(a: A) -> Result<B, Self::Error>;
}

// An oracle payload, submitted on-chain as an extrinsic (transaction) parameter.
#[derive(Decode, Encode, MaxEncodedLen, RuntimeDebug, TypeInfo)] // Derive macros which implement SCALE encoding of the type.
#[scale_info(skip_type_params(DataPackage, MaxDataPackagesPerPayload, MaxUnsignedMetadataLen))] // Ignores generics on scale encoding
pub struct Payload<
    DataPackage, // Generic parameters, as the actual types are based on config.
    MaxDataPackagesPerPayload: Get<u32>,
    MaxUnsignedMetadataLen: Get<u32>,
> {
    // The data packages within the payload.
    data: BoundedVec<DataPackage, MaxDataPackagesPerPayload>, // BoundedVec constrains vector capacity to some max size (defined in config)
    // Any unsigned metadata.
    unsigned_metadata: BoundedVec<u8, MaxUnsignedMetadataLen>,
}

impl<DataPackage, MaxDataPackagesPerPayload: Get<u32>, MaxUnsignedMetadataLen: Get<u32>>
    Payload<DataPackage, MaxDataPackagesPerPayload, MaxUnsignedMetadataLen>
{
    // Simple helper function
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

// A data package within a payload.
#[derive(Encode, Decode, MaxEncodedLen, RuntimeDebug, TypeInfo)]
#[scale_info(skip_type_params(DataPoint, MaxDataPointsPerPackage, Timestamp, Signature))]
pub struct DataPackage<DataPoint, MaxDataPointsPerPackage: Get<u32>, Timestamp, Signature> {
    // The data points within the payload.
    data_points: BoundedVec<DataPoint, MaxDataPointsPerPackage>,
    // The corresponding timestamp.
    timestamp: Timestamp,
    // A signature of the data package (data-points and timestamp).
    signature: Signature,
}

impl<DataPoint, MaxDataPointsPerPackage: Get<u32>, Timestamp, Signature>
    DataPackage<DataPoint, MaxDataPointsPerPackage, Timestamp, Signature>
{
    // Simple helper function
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

// A data point within a data package.
#[derive(Encode, Decode, MaxEncodedLen, RuntimeDebug, TypeInfo)]
#[scale_info(skip_type_params(FeedId, Value))]
pub struct DataPoint<FeedId, Value> {
    // The feed identifier.
    feed_id: FeedId,
    // The data point value.
    value: Value,
}

// Errors potentially produced by the crate: runtime code must not panic!
#[derive(Debug)]
pub enum Error {
    CannotTakeMedianOfEmptyArray,
    ValueConversionError,
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
