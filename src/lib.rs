#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_arithmetic::traits::BaseArithmetic;
use sp_core::ecdsa::Public;
use sp_core::{bounded::BoundedVec, Get, RuntimeDebug};
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
// todo: determine how same can be achieved for Ed/SR25519

// A specification of a data package.
pub trait DataPackageSpecification {
    // The type of unique identifier of the data feed.
    type FeedId: Debug + PartialEq;
    // The type of data point value.
    type Value: Copy + Debug;
    // The type of timestamp.
    type Timestamp: Debug;
    // The type of signature scheme used to sign the data.
    type Signature: SignatureScheme<
        DataPackage = DataPackage<
            DataPoint<Self::FeedId, Self::Value>,
            Self::MaxDataPointsPerPackage,
            Self::Timestamp,
            <Self::Signature as SignatureScheme>::Signature,
        >,
    >;
    // The maximum data points per data package, configured by the runtime.
    // todo: can this be improved?
    type MaxDataPointsPerPackage: Get<u32> + Debug;
}

// The signature scheme used to sign data packages.
// todo: this is currently ecdsa-specific, need a better api to support ed25519 verification - i.e. verify(sig: &Signature, message: M, pubkey: &Public)
pub trait SignatureScheme {
    // The type of data package.
    type DataPackage;
    // The type of signer.
    type Signer: PartialEq;
    // The type of signature.
    type Signature: Debug;
    // todo: make hasher configurable too?

    // Recovers the signer of the data package, for verification against 'trusted' signers.
    fn recover(data_package: &Self::DataPackage) -> Option<Self::Signer>;
}

// The config used to decode signed off-chain data packages to on-chain oracle data.
pub trait Config {
    // The type of data package.
    type DataPackage: DataPackageSpecification;
    // A converter for converting between a data point value and a result.
    // todo: can this be improved?
    type ValueConverter: Convert<
        <<Self as Config>::DataPackage as DataPackageSpecification>::Value,
        Self::Result,
    >;
    // The type of oracle result.
    type Result: BaseArithmetic + Copy + Debug;
    // The maximum number of data packages per payload, configured by the runtime.
    type MaxDataPackagesPerPayload: Get<u32>;
    // The maximum length of unsigned metadata, configured by the runtime.
    type MaxUnsignedMetadataLen: Get<u32>;
}

// todo; change to try convert
pub trait Convert<A, B> {
    /// Make conversion.
    fn convert(a: A) -> B;
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

#[derive(Encode, Decode, MaxEncodedLen, RuntimeDebug, TypeInfo)]
#[scale_info(skip_type_params(DataPoint, MaxDataPointsPerPackage, Timestamp, Signature))]
pub struct DataPackage<DataPoint, MaxDataPointsPerPackage: Get<u32>, Timestamp, Signature> {
    data_points: BoundedVec<DataPoint, MaxDataPointsPerPackage>,
    timestamp: Timestamp,
    signature: Signature,
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
}

type DataPointOf<T> = DataPoint<
    <<T as Config>::DataPackage as DataPackageSpecification>::FeedId,
    <<T as Config>::DataPackage as DataPackageSpecification>::Value,
>;
type DataPackageOf<T> = DataPackage<
    DataPointOf<T>,
    <<T as Config>::DataPackage as DataPackageSpecification>::MaxDataPointsPerPackage,
    <<T as Config>::DataPackage as DataPackageSpecification>::Timestamp,
    <<<T as Config>::DataPackage as DataPackageSpecification>::Signature as SignatureScheme>::Signature,
>;
type PayloadOf<T> = Payload<
    DataPackageOf<T>,
    <T as Config>::MaxDataPackagesPerPayload,
    <T as Config>::MaxUnsignedMetadataLen,
>;

// Used internally within a pallet extrinsic to extract oracle values from submitted extrinsic parameter of type `PayloadOf<T>`
pub fn get_oracle_value<T: Config>(
    feed_id: &<<T as Config>::DataPackage as DataPackageSpecification>::FeedId,
    unique_signers_threshold: u8,
    authorised_signers: &[<<<T as Config>::DataPackage as DataPackageSpecification>::Signature as SignatureScheme>::Signer],
    current_timestamp_milliseconds: u128,
    payload: &PayloadOf<T>,
) -> Result<T::Result, Error> {
    // todo: complete implementation
    let mut values: Vec<T::Result> = vec![];
    for package in &payload.data {
        if let Some(signer) =
            <<T as Config>::DataPackage as DataPackageSpecification>::Signature::recover(&package)
        {
            if !authorised_signers.contains(&signer) {
                continue;
            }

            for point in &package.data_points {
                if &point.feed_id == feed_id {
                    values.push(T::ValueConverter::convert(point.value));
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

mod ecdsa {
    use super::*;
    use sp_core::{ecdsa::Signature, keccak_256};
    use std::marker::PhantomData;

    // Define the types as used by the existing ECDSA implementation
    pub type FeedId = [u8; 32];
    pub type Value = [u8; 32];
    pub type Timestamp = [u8; 6];
    pub type DataPackage<Max> = super::DataPackage<DataPoint, Max, Timestamp, Signature>;
    pub type DataPoint = super::DataPoint<FeedId, Value>;

    // Define data package specification
    // todo: need better way to handle this max generic parameter configured by runtime
    pub struct DataPackageSpecification<MaxDataPointsPerPackage> {
        data: PhantomData<MaxDataPointsPerPackage>,
    }
    impl<MaxDataPointsPerPackage: Get<u32> + Debug> super::DataPackageSpecification
        for DataPackageSpecification<MaxDataPointsPerPackage>
    {
        type FeedId = FeedId;
        type Value = Value;
        type Timestamp = Timestamp;
        type Signature = ECDSA<Self::MaxDataPointsPerPackage>;
        type MaxDataPointsPerPackage = MaxDataPointsPerPackage;
    }

    // Define signature scheme
    pub struct ECDSA<MaxDataPointsPerPackage> {
        data: PhantomData<MaxDataPointsPerPackage>,
    }
    impl<MaxDataPointsPerPackage: Get<u32>> SignatureScheme for ECDSA<MaxDataPointsPerPackage> {
        type DataPackage = DataPackage<MaxDataPointsPerPackage>;
        type Signer = Public;
        type Signature = Signature;

        fn recover(data_package: &Self::DataPackage) -> Option<Self::Signer> {
            // todo: use actual data package data
            let message = Vec::new();
            let message = keccak_256(&message);
            data_package.signature.recover_prehashed(&message)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use frame_support::traits::ConstU32;
        use sp_core::bytes::{from_hex, to_hex};
        use sp_core::{bounded_vec, ecdsa, Pair};

        const BTC_BYTES_32_HEX_STR: &str =
            "4254430000000000000000000000000000000000000000000000000000000000";
        const BTC_VALUE_HEX_STR: &str =
            "000000000000000000000000000000000000000000000000000003d1e3821000";
        const ETH_BYTES_32_HEX_STR: &str =
            "4554480000000000000000000000000000000000000000000000000000000000";
        const ETH_VALUE_HEX_STR: &str =
            "0000000000000000000000000000000000000000000000000000002e90edd000";
        const TIMESTAMP_HEX_STR: &str = "01812f2590c0"; // 1654353400000 in hex

        type Payload = super::PayloadOf<Runtime>;
        type MaxDataPointsPerPackage = ConstU32<10>;

        #[derive(Debug)]
        struct Runtime;
        impl Config for Runtime {
            type DataPackage = DataPackageSpecification<MaxDataPointsPerPackage>;
            type ValueConverter = Self;
            type Result = u128;
            type MaxDataPackagesPerPayload = ConstU32<10>;
            type MaxUnsignedMetadataLen = ConstU32<500>;
        }
        impl Convert<Value, u128> for Runtime {
            fn convert(value: Value) -> u128 {
                u128::from_be_bytes(value[16..].try_into().unwrap())
            }
        }

        #[test]
        fn data_point_value_conversion() {
            const VALUE: u128 = 42000 * 10u128.pow(8);
            let mut value = vec![0; 16];
            value.append(VALUE.to_be_bytes().to_vec().as_mut());
            let value: Value = value.try_into().unwrap();
            let value_hex = to_hex(&value, false);
            assert_eq!(
                "0x000000000000000000000000000000000000000000000000000003d1e3821000",
                value_hex
            );

            let value: [u8; 16] = from_hex(&value_hex).unwrap()[16..].try_into().unwrap();
            assert_eq!(VALUE, u128::from_be_bytes(value))
        }

        #[test]
        fn timestamp_conversion() {
            const TIMESTAMP: u64 = 1654353400000;

            // Timestamp is 6 bytes in RedStone data package specification
            let timestamp: Timestamp = TIMESTAMP.to_be_bytes()[2..].try_into().unwrap();
            let timestamp_hex = to_hex(&timestamp, false);
            assert_eq!("0x01812f2590c0", timestamp_hex);

            let mut timestamp = vec![0; 2];
            timestamp.append(from_hex(&timestamp_hex).unwrap().as_mut());
            let timestamp: [u8; 8] = timestamp.try_into().unwrap();
            assert_eq!(TIMESTAMP, u64::from_be_bytes(timestamp))
        }

        #[test]
        fn initial() {
            let timestamp = from_hex(TIMESTAMP_HEX_STR).unwrap().try_into().unwrap();

            let unsigned_metadata: BoundedVec<u8, <Runtime as Config>::MaxUnsignedMetadataLen> =
                "1.1.2#test-data-feed"
                    .as_bytes()
                    .to_vec()
                    .try_into()
                    .unwrap();

            let package = DataPackage {
                data_points: bounded_vec![
                    DataPoint {
                        feed_id: from_hex(BTC_BYTES_32_HEX_STR).unwrap().try_into().unwrap(),
                        value: from_hex(BTC_VALUE_HEX_STR).unwrap().try_into().unwrap(),
                    },
                    DataPoint {
                        feed_id: from_hex(ETH_BYTES_32_HEX_STR).unwrap().try_into().unwrap(),
                        value: from_hex(ETH_VALUE_HEX_STR).unwrap().try_into().unwrap(),
                    }
                ],
                timestamp,
                signature: Default::default(),
            };
            let payload = Payload {
                data: bounded_vec![package],
                unsigned_metadata,
            };

            let encoded = payload.encode();
            println!("{} {:?}", encoded.len(), encoded);

            let decoded = Payload::decode(&mut &encoded[..]).unwrap();
            println!("{:?}", decoded);

            assert_eq!(payload.unsigned_metadata, decoded.unsigned_metadata)
        }

        #[test]
        fn from_hex_equals_decode_hex() {
            // Copied from redstone-near-connectors/rust/tests/integration_test.rs
            fn decode_hex(s: &str) -> Result<Vec<u8>, core::num::ParseIntError> {
                (0..s.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
                    .collect()
            }

            assert_eq!(
                from_hex(BTC_BYTES_32_HEX_STR).unwrap(),
                decode_hex(BTC_BYTES_32_HEX_STR).unwrap()
            )
        }

        #[test]
        fn gets_oracle_value() {
            let btc = from_hex(BTC_BYTES_32_HEX_STR).unwrap().try_into().unwrap();
            let timestamp = from_hex(TIMESTAMP_HEX_STR).unwrap().try_into().unwrap();

            let unsigned_metadata: BoundedVec<u8, <Runtime as Config>::MaxUnsignedMetadataLen> =
                "1.1.2#test-data-feed"
                    .as_bytes()
                    .to_vec()
                    .try_into()
                    .unwrap();

            let signer_1 = ecdsa::Pair::from_seed(b"12345678901234567890123456789012");
            let data_points: BoundedVec<DataPoint, MaxDataPointsPerPackage> = bounded_vec![
                DataPoint {
                    feed_id: btc,
                    value: from_hex(BTC_VALUE_HEX_STR).unwrap().try_into().unwrap(),
                },
                DataPoint {
                    feed_id: from_hex(ETH_BYTES_32_HEX_STR).unwrap().try_into().unwrap(),
                    value: from_hex(ETH_VALUE_HEX_STR).unwrap().try_into().unwrap(),
                }
            ];
            // todo: use actual data package data
            let message = Vec::new();
            let message_hashed = super::ecdsa::keccak_256(&message);
            let signature = signer_1.sign_prehashed(&message_hashed);
            println!("{:?}", signature);

            let package = DataPackage {
                data_points,
                timestamp,
                signature,
            };
            let payload = Payload {
                data: bounded_vec![package],
                unsigned_metadata,
            };

            let authorised_signers = [signer_1.public()];
            let current_timestamp_milliseconds = 10;

            let value: u128 = get_oracle_value::<Runtime>(
                &btc,
                2,
                &authorised_signers,
                current_timestamp_milliseconds,
                &payload,
            )
            .unwrap();

            assert_eq!(42_000 * 100_000_000, value);
        }
    }
}
