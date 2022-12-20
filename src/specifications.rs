use super::*;
use std::marker::PhantomData;

// An EVM-based implementation of a data package.
pub struct EVM<MaxDataPointsPerPackage> {
    data: PhantomData<MaxDataPointsPerPackage>,
}
// Implementation of the data package specification trait based on existing EVM settings.
impl<MaxDataPointsPerPackage: Get<u32> + Debug> DataPackageSpecification
    for EVM<MaxDataPointsPerPackage>
{
    // Define the standard types as used by the EVMSigner/Connector
    type FeedId = [u8; 32];
    type Value = [u8; 32];
    type Timestamp = [u8; 6];
    type Signature = sp_core::ecdsa::Pair; // 65 bytes
    type MaxDataPointsPerPackage = MaxDataPointsPerPackage;

    fn verify<'a>(
        data_package: &DataPackage<
            DataPoint<Self::FeedId, Self::Value>,
            Self::MaxDataPointsPerPackage,
            Self::Timestamp,
            <Self::Signature as Pair>::Signature,
        >,
        authorised_signers: &'a [<Self::Signature as Pair>::Public],
    ) -> Option<&'a <Self::Signature as Pair>::Public> {
        // Serialise the data package (and hash) to recover the public key for comparison
        // todo: optimise & refactor hashing into separate trait/type
        let message = Self::serialise(&data_package.data_points, &data_package.timestamp);

        // todo: optimise between signature.recover vs verifying until first trusted signer found
        if let Some(signer) = data_package.signature.recover_prehashed(&message) {
            if let Some(position) = authorised_signers.iter().position(|s| s == &signer) {
                return authorised_signers.get(position);
            }
        }
        // for signer in authorised_signers {
        //     if sp_core::ecdsa::Pair::verify_prehashed(&data_package.signature, &message, signer) {
        //         return Some(signer);
        //     }
        // }
        None
    }
}
// Implementation of serialise trait for serialising a data package
impl<MaxDataPointsPerPackage: Debug + Get<u32>> Serialise for EVM<MaxDataPointsPerPackage> {
    type DataPoint = DataPoint<
        <Self as DataPackageSpecification>::FeedId,
        <Self as DataPackageSpecification>::Value,
    >;
    type Timestamp = <Self as DataPackageSpecification>::Timestamp;

    fn serialise(data_points: &[Self::DataPoint], timestamp: &Self::Timestamp) -> [u8; 32] {
        // Data already byte arrays so simply add to a vector and then hash
        // todo: optimise
        let mut message = Vec::new();
        message.extend(data_points.iter().flat_map(|dp| dp.feed_id));
        message.extend(data_points.iter().flat_map(|dp| dp.value));
        message.extend(timestamp);
        sp_core::keccak_256(&message)
    }
}

// A Substrate-based implementation of a data package, using data types more natural to Substrate.
pub struct Substrate<MaxDataPointsPerPackage> {
    data: PhantomData<MaxDataPointsPerPackage>,
}
// Implementation of the data package specification trait using compact number encoding
impl<MaxDataPointsPerPackage: Get<u32> + Debug> DataPackageSpecification
    for Substrate<MaxDataPointsPerPackage>
{
    type FeedId = [u8; 32];
    type Value = codec::Compact<u128>;
    type Timestamp = codec::Compact<u64>;
    type Signature = sp_core::sr25519::Pair; // 64 bytes
    type MaxDataPointsPerPackage = MaxDataPointsPerPackage;

    fn verify<'a>(
        data_package: &DataPackage<
            DataPoint<Self::FeedId, Self::Value>,
            Self::MaxDataPointsPerPackage,
            Self::Timestamp,
            <Self::Signature as Pair>::Signature,
        >,
        authorised_signers: &'a [<Self::Signature as Pair>::Public],
    ) -> Option<&'a <Self::Signature as Pair>::Public> {
        // Serialise the data package (and hash) to generate the message for signature verification
        // todo: optimise
        let message = Self::serialise(&data_package.data_points, &data_package.timestamp);
        for signer in authorised_signers {
            if sp_core::sr25519::Pair::verify(&data_package.signature, message, &signer) {
                return Some(signer);
            }
        }

        None
    }
}
// Implementation of serialise trait for serialising a data package
impl<MaxDataPointsPerPackage: Debug + Get<u32>> Serialise for Substrate<MaxDataPointsPerPackage> {
    type DataPoint = DataPoint<
        <Self as DataPackageSpecification>::FeedId,
        <Self as DataPackageSpecification>::Value,
    >;
    type Timestamp = <Self as DataPackageSpecification>::Timestamp;

    fn serialise(data_points: &[Self::DataPoint], timestamp: &Self::Timestamp) -> [u8; 32] {
        // Some data (value/timestamp) needs converting to bytes before hashing, would be good to
        // benchmark against EVM implementation for performance/size comparison
        // todo: optimise
        let mut message = Vec::new();
        message.extend(data_points.iter().flat_map(|dp| dp.feed_id));
        message.extend(data_points.iter().flat_map(|dp| dp.value.encode()));
        message.extend(timestamp.encode());
        sp_core::blake2_256(&message) // Use blake2 hashing for comparison
    }
}

// A simple trait to allow serialisation of a data package for signature verification.
trait Serialise {
    // Only use these two types to avoid complexity of using DataPackage<..>
    type DataPoint;
    type Timestamp;
    fn serialise(data_points: &[Self::DataPoint], timestamp: &Self::Timestamp) -> [u8; 32];
}

// Various tests which demonstrate usage.
#[cfg(test)]
mod tests {
    use super::*;
    use frame_support::traits::ConstU32;
    use sp_core::bytes::{from_hex, to_hex};
    use sp_core::{bounded_vec, ecdsa, sr25519, Pair};
    use std::array::TryFromSliceError;

    const BTC_BYTES_32_HEX_STR: &str =
        "4254430000000000000000000000000000000000000000000000000000000000";
    const BTC_VALUE_HEX_STR: &str =
        "000000000000000000000000000000000000000000000000000003d1e3821000";
    const ETH_BYTES_32_HEX_STR: &str =
        "4554480000000000000000000000000000000000000000000000000000000000";
    const ETH_VALUE_HEX_STR: &str =
        "0000000000000000000000000000000000000000000000000000002e90edd000";
    const TIMESTAMP_HEX_STR: &str = "01812f2590c0"; // 1654353400000 in hex

    // Simple types to constrain maximum vector values
    type MaxDataPointsPerPackage = ConstU32<10>;
    type MaxDataPackagesPerPayload = ConstU32<10>;
    type MaxUnsignedMetadataLen = ConstU32<100>;

    // Implementation of config using the EVM-based data spec.
    #[derive(Debug)]
    struct EVMConfig;
    impl Config for EVMConfig {
        type DataPackageSpecification = EVM<MaxDataPointsPerPackage>; // EVM data spec
        type ValueConverter = Self; // Converter of byte array to oracle result
        type Result = u128;
        type MaxDataPackagesPerPayload = MaxDataPackagesPerPayload;
        type MaxUnsignedMetadataLen = MaxUnsignedMetadataLen;
    }
    impl TryConvert<ValueOf<EVMConfig>, u128> for EVMConfig {
        type Error = TryFromSliceError;
        fn try_convert(value: ValueOf<EVMConfig>) -> Result<u128, Self::Error> {
            // Convert byte array to u128
            Ok(u128::from_be_bytes(value[16..].try_into()?))
        }
    }

    // Gets oracle value using EVM data spec
    #[test]
    fn gets_oracle_value() {
        let btc = from_hex(BTC_BYTES_32_HEX_STR).unwrap().try_into().unwrap();

        let unsigned_metadata: BoundedUnsignedMetadataOf<EVMConfig> = "1.1.2#test-data-feed"
            .as_bytes()
            .to_vec()
            .try_into()
            .unwrap();

        let signer_1 = ecdsa::Pair::from_seed(b"12345678901234567890123456789012");
        let data_points: BoundedDataPointsOf<EVMConfig> = bounded_vec![
            DataPoint {
                feed_id: btc,
                value: from_hex(BTC_VALUE_HEX_STR).unwrap().try_into().unwrap(),
            },
            DataPoint {
                feed_id: from_hex(ETH_BYTES_32_HEX_STR).unwrap().try_into().unwrap(),
                value: from_hex(ETH_VALUE_HEX_STR).unwrap().try_into().unwrap(),
            }
        ];
        let timestamp = from_hex(TIMESTAMP_HEX_STR).unwrap().try_into().unwrap();
        let message = EVM::<MaxDataPointsPerPackage>::serialise(&data_points, &timestamp);
        let signature = signer_1.sign_prehashed(&message);

        let package = DataPackage::new(data_points, timestamp, signature);
        let payload = Payload {
            data: bounded_vec![package],
            unsigned_metadata,
        };

        let authorised_signers = [signer_1.public()];
        let current_timestamp_milliseconds = 10;

        let value: u128 = get_oracle_value::<EVMConfig>(
            &btc,
            2,
            &authorised_signers,
            current_timestamp_milliseconds,
            &payload,
        )
        .unwrap();

        assert_eq!(42_000 * 100_000_000, value);
    }

    // Implementation of config using the Substrate-based data spec.
    #[derive(Debug)]
    struct SubstrateConfig;
    impl Config for SubstrateConfig {
        type DataPackageSpecification = Substrate<MaxDataPointsPerPackage>; // Substrate data spec
        type ValueConverter = Self;
        type Result = u128;
        type MaxDataPackagesPerPayload = MaxDataPackagesPerPayload;
        type MaxUnsignedMetadataLen = MaxUnsignedMetadataLen;
    }
    impl TryConvert<ValueOf<SubstrateConfig>, u128> for SubstrateConfig {
        type Error = TryFromSliceError;
        fn try_convert(value: ValueOf<SubstrateConfig>) -> Result<u128, Self::Error> {
            // Value already deserialised based on config, so simply return value
            Ok(value.0)
        }
    }

    // Create EVM/Substrate-based payloads for comparison
    #[test]
    fn compare_data_package_encodings() {
        let btc = from_hex(BTC_BYTES_32_HEX_STR).unwrap().try_into().unwrap();
        let eth = from_hex(ETH_BYTES_32_HEX_STR).unwrap().try_into().unwrap();
        let unsigned_metadata = BoundedVec::default();

        // Create 'EVM' payload
        let ecdsa_signer = ecdsa::Pair::from_seed(b"12345678901234567890123456789012");
        let data_points: BoundedDataPointsOf<EVMConfig> = bounded_vec![
            DataPoint {
                feed_id: btc,
                value: from_hex(BTC_VALUE_HEX_STR).unwrap().try_into().unwrap(),
            },
            DataPoint {
                feed_id: eth,
                value: from_hex(ETH_VALUE_HEX_STR).unwrap().try_into().unwrap(),
            }
        ];
        let timestamp = from_hex(TIMESTAMP_HEX_STR).unwrap().try_into().unwrap();
        let message = EVM::<MaxDataPointsPerPackage>::serialise(&data_points, &timestamp);
        let evm = Payload::new(
            bounded_vec![DataPackageOf::<EVMConfig>::new(
                data_points,
                timestamp,
                ecdsa_signer.sign_prehashed(&message),
            )],
            unsigned_metadata.clone(),
        );

        // Create 'Substrate' payload
        let sr25519_signer = sr25519::Pair::from_seed(b"12345678901234567890123456789012");
        let data_points: BoundedDataPointsOf<SubstrateConfig> = bounded_vec![
            DataPoint {
                feed_id: btc,
                value: (42_000 * 10u128.pow(8)).into(),
            },
            DataPoint {
                feed_id: eth,
                value: (2_000 * 10u128.pow(8)).into(),
            }
        ];
        let timestamp = 1654353400000.into();
        let message = Substrate::<MaxDataPointsPerPackage>::serialise(&data_points, &timestamp);
        let substrate: PayloadOf<SubstrateConfig> = Payload::new(
            bounded_vec![DataPackageOf::<SubstrateConfig>::new(
                data_points,
                timestamp,
                sr25519_signer.sign(&message),
            )],
            unsigned_metadata,
        );

        // Compare resulting prices from both data packages
        assert_eq!(
            get_oracle_value::<EVMConfig>(&btc, 2, &vec![ecdsa_signer.public()], 0, &evm).unwrap(),
            get_oracle_value::<SubstrateConfig>(
                &btc,
                2,
                &vec![sr25519_signer.public()],
                0,
                &substrate
            )
            .unwrap(),
        );
        assert_eq!(
            get_oracle_value::<EVMConfig>(&eth, 2, &vec![ecdsa_signer.public()], 0, &evm).unwrap(),
            get_oracle_value::<SubstrateConfig>(
                &eth,
                2,
                &vec![sr25519_signer.public()],
                0,
                &substrate
            )
            .unwrap(),
        );

        // SCALE encode data packages, required for on-chain submission
        let evm = evm.encode();
        let substrate = substrate.encode();
        assert!(substrate.len() < evm.len());

        println!("EVM Payload: Length={} Bytes={:?}", evm.len(), evm);
        println!(
            "Substrate Payload: Length={} Bytes={:?}",
            substrate.len(),
            substrate
        );
    }

    // Just checking payload encoding
    #[test]
    fn payload_encoding() {
        let timestamp = from_hex(TIMESTAMP_HEX_STR).unwrap().try_into().unwrap();

        let unsigned_metadata: BoundedUnsignedMetadataOf<EVMConfig> = "1.1.2#test-data-feed"
            .as_bytes()
            .to_vec()
            .try_into()
            .unwrap();

        let package = DataPackage::new(
            bounded_vec![
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
            Default::default(),
        );
        let payload = PayloadOf::<EVMConfig> {
            data: bounded_vec![package],
            unsigned_metadata,
        };

        let encoded = payload.encode();
        println!("{} {:?}", encoded.len(), encoded);

        let decoded = PayloadOf::<EVMConfig>::decode(&mut &encoded[..]).unwrap();
        println!("{:?}", decoded);

        assert_eq!(payload.unsigned_metadata, decoded.unsigned_metadata)
    }

    // Just checking conversions work as expected
    #[test]
    fn data_point_value_conversion() {
        const VALUE: u128 = 42000 * 10u128.pow(8);
        let mut value = vec![0; 16];
        value.append(VALUE.to_be_bytes().to_vec().as_mut());
        let value: ValueOf<EVMConfig> = value.try_into().unwrap();
        let value_hex = to_hex(&value, false);
        assert_eq!(
            "0x000000000000000000000000000000000000000000000000000003d1e3821000",
            value_hex
        );

        let value: [u8; 16] = from_hex(&value_hex).unwrap()[16..].try_into().unwrap();
        assert_eq!(VALUE, u128::from_be_bytes(value))
    }

    // Just checking conversions work as expected
    #[test]
    fn timestamp_conversion() {
        const TIMESTAMP: u64 = 1654353400000;

        // Timestamp is 6 bytes in RedStone data package specification
        let timestamp: TimestampOf<EVMConfig> = TIMESTAMP.to_be_bytes()[2..].try_into().unwrap();
        let timestamp_hex = to_hex(&timestamp, false);
        assert_eq!("0x01812f2590c0", timestamp_hex);

        let mut timestamp = vec![0; 2];
        timestamp.append(from_hex(&timestamp_hex).unwrap().as_mut());
        let timestamp: [u8; 8] = timestamp.try_into().unwrap();
        assert_eq!(TIMESTAMP, u64::from_be_bytes(timestamp))
    }

    // Just checking conversions work as expected
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
}
