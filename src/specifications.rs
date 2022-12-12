use super::*;
use std::marker::PhantomData;

pub struct EVM<MaxDataPointsPerPackage> {
    data: PhantomData<MaxDataPointsPerPackage>,
}
impl<MaxDataPointsPerPackage: Get<u32> + Debug> DataPackageSpecification
    for EVM<MaxDataPointsPerPackage>
{
    type FeedId = [u8; 32];
    type Value = [u8; 32];
    type Timestamp = [u8; 6];
    type Signature = sp_core::ecdsa::Pair;
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
        // todo: use actual data package data
        let message = Vec::new();
        let message = sp_core::keccak_256(&message);
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

pub struct Substrate<MaxDataPointsPerPackage> {
    data: PhantomData<MaxDataPointsPerPackage>,
}
impl<MaxDataPointsPerPackage: Get<u32> + Debug> DataPackageSpecification
    for Substrate<MaxDataPointsPerPackage>
{
    type FeedId = [u8; 32];
    type Value = codec::Compact<u128>;
    type Timestamp = codec::Compact<u64>;
    type Signature = sp_core::ed25519::Pair;
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
        // todo: use actual data package data
        let message = Vec::new();
        let message = sp_core::twox_256(&message);

        for signer in authorised_signers {
            if sp_core::ed25519::Pair::verify(&data_package.signature, message, &signer) {
                return Some(signer);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frame_support::traits::ConstU32;
    use sp_core::bytes::{from_hex, to_hex};
    use sp_core::{bounded_vec, ecdsa, keccak_256, Pair};
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

    type MaxDataPointsPerPackage = ConstU32<10>;
    type MaxDataPackagesPerPayload = ConstU32<10>;
    type MaxUnsignedMetadataLen = ConstU32<100>;

    #[derive(Debug)]
    struct Config;
    impl super::Config for Config {
        type DataPackageSpecification = EVM<MaxDataPointsPerPackage>;
        type ValueConverter = Self;
        type Result = u128;
        type MaxDataPackagesPerPayload = MaxDataPackagesPerPayload;
        type MaxUnsignedMetadataLen = MaxUnsignedMetadataLen;
    }
    impl TryConvert<Value, u128> for Config {
        type Error = TryFromSliceError;
        fn try_convert(value: Value) -> Result<u128, Self::Error> {
            Ok(u128::from_be_bytes(value[16..].try_into()?))
        }
    }

    type DataPackage = DataPackageOf<Config>;
    type Payload = PayloadOf<Config>;
    type DataPoint = DataPointOf<Config>;
    type Value = ValueOf<Config>;
    type Timestamp = TimestampOf<Config>;

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

        let unsigned_metadata: BoundedUnsignedMetadataOf<Config> = "1.1.2#test-data-feed"
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

        let unsigned_metadata: BoundedUnsignedMetadataOf<Config> = "1.1.2#test-data-feed"
            .as_bytes()
            .to_vec()
            .try_into()
            .unwrap();

        let signer_1 = ecdsa::Pair::from_seed(b"12345678901234567890123456789012");
        let data_points: BoundedDataPointsOf<Config> = bounded_vec![
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
        let message_hashed = keccak_256(&message);
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

        let value: u128 = get_oracle_value::<Config>(
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
