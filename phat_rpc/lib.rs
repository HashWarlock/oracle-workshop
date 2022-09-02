#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

use fat_utils::attestation;
use ink_env::AccountId;
use ink_lang as ink;
use ink_prelude::{string::String, vec::Vec};
use pink_extension as pink;

#[ink::trait_definition]
pub trait SubmittableOracle {
    #[ink(message)]
    fn admin(&self) -> AccountId;

    #[ink(message)]
    fn verifier(&self) -> attestation::Verifier;

    #[ink(message)]
    fn get_next_nonce(&self, chain: String) -> Result<attestation::Attestation, Vec<u8>>;

    #[ink(message)]
    fn get_runtime_version(&self, chain: String) -> Result<attestation::Attestation, Vec<u8>>;

    #[ink(message)]
    fn get_genesis_hash(&self, chain: String) -> Result<attestation::Attestation, Vec<u8>>;
}

#[pink::contract(env=PinkEnvironment)]
mod phat_rpc {
    use super::pink;
    use super::SubmittableOracle;
    use pink::logger::{Level, Logger};
    use pink::{http_post, PinkEnvironment};

    use base58::ToBase58;
    use core::fmt::Write;
    use fat_utils::attestation;
    use ink_prelude::{
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
    use ink_storage::traits::SpreadAllocate;
    use ink_storage::Mapping;
    use scale::{Decode, Encode};
    use serde::Deserialize;
    use serde_json_core::from_slice;
    use sp_core::crypto::{Ss58AddressFormat};

    static LOGGER: Logger = Logger::with_max_level(Level::Info);
    pink::register_logger!(&LOGGER);

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct PhatRpc {
        admin: AccountId,
        attestation_verifier: attestation::Verifier,
        attestation_generator: attestation::Generator,
        rpc_nodes: Mapping<String, String>,
        chain_account_id: Mapping<String, String>,
        account_public: Mapping<String, attestation::Verifier>,
        account_private: Mapping<String, attestation::Generator>,
        api_key: String,
        is_api_key_set: bool,
    }

    /// Errors that can occur upon calling this contract.
    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        InvalidBody,
        InvalidUrl,
        InvalidSignature,
        RequestFailed,
        NoPermissions,
        ApiKeyNotSet,
        ChainNotConfigured,
        InvalidAccount,
    }

    /// Type alias for the contract's result type.
    pub type Result<T> = core::result::Result<T, Error>;

    impl PhatRpc {
        #[ink(constructor)]
        pub fn new() -> Self {
            // Create the attestation helpers
            let (generator, verifier) = attestation::create(b"phat-rpc-attestation-key");
            // Save sender as the contract admin
            let admin = Self::env().caller();

            ink_lang::utils::initialize_contract(|this: &mut Self| {
                this.admin = admin;
                this.attestation_generator = generator;
                this.attestation_verifier = verifier;
                this.api_key = Default::default();
                this.is_api_key_set = false;
            })
        }

        /// Set the RPC node for parachain.
        #[ink(message)]
        pub fn set_chain_info(&mut self, chain: String) -> core::result::Result<(), Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            if !self.is_api_key_set {
                return Err(Error::ApiKeyNotSet);
            }

            let http_endpoint = format!(
                "https://{}.api.onfinality.io/rpc?apikey={}",
                chain, self.api_key
            );
            let salt = chain.clone();
            // Create the attestation helpers
            let (generator, verifier) = attestation::create(salt.as_bytes());
            let account_public: &[u8] = &verifier.pubkey;
            //let account_public_ss58 = account_public.to_base58();
            let version = match Ss58AddressFormat::try_from(chain.as_str()) {
                Ok(version) => {
                    version
                },
                Err(_e) => {
                    return Err(Error::InvalidAccount)
                }
            };

            let ident: u16 = u16::from(version) & 0b0011_1111_1111_1111;
            let mut v: Vec<u8> = match ident {
                0..=63 => vec![ident as u8],
                64..=16_383 => {
                    let first = ((ident & 0b0000_0000_1111_1100) as u8) >> 2;
                    let second = ((ident >> 8) as u8) | ((ident & 0b0000_0000_0000_0011) as u8) << 6;
                    vec![first | 0b01000000, second]
                }
                _ => unreachable!("masked out the upper two bits; qed"),
            };

            let account_public: &[u8; 32] = account_public.try_into().expect("works");
            v.extend(account_public);
            let r = ss58hash(&v);
            v.extend(&r.as_bytes()[0..2]);
            let account_public_ss58 = v.to_base58();

            self.rpc_nodes.insert(&chain, &http_endpoint);
            self.chain_account_id.insert(&chain, &account_public_ss58);
            self.account_public.insert(&account_public_ss58, &verifier);
            self.account_private
                .insert(&account_public_ss58, &generator);
            Ok(())
        }

        /// Set the user api key for user account.
        #[ink(message)]
        pub fn set_api_key(&mut self, api_key: String) -> core::result::Result<(), Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            self.api_key = api_key;
            self.is_api_key_set = true;
            Ok(())
        }

        #[ink(message)]
        pub fn get_api_key(&self) -> core::result::Result<String, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            if !self.is_api_key_set {
                return Err(Error::ApiKeyNotSet);
            }
            Ok(self.api_key.clone())
        }

        #[ink(message)]
        pub fn get_rpc_endpoint(&self, chain: String) -> core::result::Result<String, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured),
            };
            Ok(rpc_node)
        }

        #[ink(message)]
        pub fn get_chain_account_id(&self, chain: String) -> core::result::Result<String, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let account_id = match self.chain_account_id.get(&chain) {
                Some(account_id) => account_id,
                None => return Err(Error::ChainNotConfigured),
            };
            Ok(account_id)
        }
    }

    impl SubmittableOracle for PhatRpc {
        // Queries

        #[ink(message)]
        fn admin(&self) -> AccountId {
            self.admin.clone()
        }

        /// The attestation verifier
        #[ink(message)]
        fn verifier(&self) -> attestation::Verifier {
            self.attestation_verifier.clone()
        }

        /// Get account's next nonce on a specific chain.
        #[ink(message)]
        fn get_next_nonce(
            &self,
            chain: String,
        ) -> core::result::Result<attestation::Attestation, Vec<u8>> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions.encode());
            }
            let account_id = match self.chain_account_id.get(&chain) {
                Some(account_id) => account_id,
                None => return Err(Error::ChainNotConfigured.encode()),
            };
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured.encode()),
            };
            let data = format!(
                r#"{{"id":1,"jsonrpc":"2.0","method":"system_accountNextIndex","params":["{}"]}}"#,
                account_id
            )
            .into_bytes();
            let content_length = format!("{}", data.len());
            let headers: Vec<(String, String)> = vec![
                ("Content-Type".into(), "application/json".into()),
                ("Content-Length".into(), content_length),
            ];
            // Get next nonce for the account through HTTP request
            let response = http_post!(rpc_node, data, headers);
            if response.status_code != 200 {
                return Err(Error::RequestFailed.encode());
            }
            let body = response.body;
            let (next_nonce, _): (NextNonce, usize) =
                serde_json_core::from_slice(&body).or(Err(Error::InvalidBody.encode()))?;

            let next_nonce_ok = NextNonceOk {
                next_nonce: next_nonce.result,
            };

            let result = self.attestation_generator.sign(next_nonce_ok);

            Ok(result)
        }

        /// Get the chain's runtime version.
        #[ink(message)]
        fn get_runtime_version(
            &self,
            chain: String,
        ) -> core::result::Result<attestation::Attestation, Vec<u8>> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions.encode());
            }
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured.encode()),
            };
            let data = r#"{"id":1, "jsonrpc":"2.0", "method": "state_getRuntimeVersion"}"#
                .to_string()
                .into_bytes();
            let content_length = format!("{}", data.len());
            let headers: Vec<(String, String)> = vec![
                ("Content-Type".into(), "application/json".into()),
                ("Content-Length".into(), content_length),
            ];
            // Get next nonce for the account through HTTP request
            let response = http_post!(rpc_node, data, headers);
            if response.status_code != 200 {
                return Err(Error::RequestFailed.encode());
            }
            let body = response.body;
            let (runtime_version, _): (RuntimeVersion, usize) =
                serde_json_core::from_slice(&body).or(Err(Error::InvalidBody.encode()))?;
            let runtime_version_result = runtime_version.result;
            let mut api_vec: Vec<(String, u32)> = Vec::new();
            for (api_str, api_u32) in runtime_version_result.apis {
                api_vec.push((api_str.to_string().parse().unwrap(), api_u32));
            }

            let runtime_version_ok = RuntimeVersionOk {
                spec_name: runtime_version_result.specName.to_string().parse().unwrap(),
                impl_name: runtime_version_result.implName.to_string().parse().unwrap(),
                authoring_version: runtime_version_result.authoringVersion,
                spec_version: runtime_version_result.specVersion,
                impl_version: runtime_version_result.implVersion,
                apis: api_vec,
                transaction_version: runtime_version_result.transactionVersion,
                state_version: runtime_version_result.stateVersion,
            };

            let result = self.attestation_generator.sign(runtime_version_ok);

            Ok(result)
        }

        /// Get chain's genesis hash
        #[ink(message)]
        fn get_genesis_hash(
            &self,
            chain: String,
        ) -> core::result::Result<attestation::Attestation, Vec<u8>> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions.encode());
            }
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured.encode()),
            };
            let data =
                r#"{"id":1, "jsonrpc":"2.0", "method": "chain_getBlockHash","params":["0"]}"#
                    .to_string()
                    .into_bytes();
            let content_length = format!("{}", data.len());
            let headers: Vec<(String, String)> = vec![
                ("Content-Type".into(), "application/json".into()),
                ("Content-Length".into(), content_length),
            ];
            // Get next nonce for the account through HTTP request
            let response = http_post!(rpc_node, data, headers);
            if response.status_code != 200 {
                return Err(Error::RequestFailed.encode());
            }
            let body = response.body;
            let (genesis_hash, _): (GenesisHash, usize) =
                serde_json_core::from_slice(&body).or(Err(Error::InvalidBody.encode()))?;

            let genesis_hash_string = GenesisHashOk {
                genesis_hash: genesis_hash.result.to_string().parse().unwrap(),
            };

            let result = self.attestation_generator.sign(genesis_hash_string);

            Ok(result)
        }
    }

    #[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
    pub struct NextNonce<'a> {
        jsonrpc: &'a str,
        result: u32,
        id: u32,
    }

    #[derive(Encode, Decode, Clone, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct NextNonceOk {
        next_nonce: u32,
    }

    #[derive(Deserialize, Debug)]
    pub struct RuntimeVersion<'a> {
        jsonrpc: &'a str,
        #[serde(borrow)]
        result: RuntimeVersionResult<'a>,
        id: u32,
    }

    #[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
    #[serde(bound(deserialize = "ink_prelude::vec::Vec<(&'a str, u32)>: Deserialize<'de>"))]
    pub struct RuntimeVersionResult<'a> {
        specName: &'a str,
        implName: &'a str,
        authoringVersion: u32,
        specVersion: u32,
        implVersion: u32,
        #[serde(borrow)]
        apis: Vec<(&'a str, u32)>,
        transactionVersion: u32,
        stateVersion: u32,
    }

    #[derive(Encode, Decode, Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct RuntimeVersionOk {
        spec_name: String,
        impl_name: String,
        authoring_version: u32,
        spec_version: u32,
        impl_version: u32,
        apis: Vec<(String, u32)>,
        transaction_version: u32,
        state_version: u32,
    }

    #[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
    pub struct GenesisHash<'a> {
        jsonrpc: &'a str,
        result: &'a str,
        id: u32,
    }

    #[derive(Encode, Decode, Clone, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct GenesisHashOk {
        genesis_hash: String,
    }

    pub fn extract_next_nonce(body: &[u8]) -> core::result::Result<u32, Error> {
        let (next_nonce, _): (NextNonce, usize) = serde_json_core::from_slice(body).unwrap();
        let result = next_nonce.result;
        Ok(result)
    }

    pub fn extract_runtime_version(body: &[u8]) -> core::result::Result<RuntimeVersionOk, Error> {
        let (runtime_version, _): (RuntimeVersion, usize) =
            serde_json_core::from_slice(body).unwrap();
        let runtime_version_result = runtime_version.result;
        let mut api_vec: Vec<(String, u32)> = Vec::new();
        for (api_str, api_u32) in runtime_version_result.apis {
            api_vec.push((api_str.to_string().parse().unwrap(), api_u32));
        }

        let runtime_version_ok = RuntimeVersionOk {
            spec_name: runtime_version_result.specName.to_string().parse().unwrap(),
            impl_name: runtime_version_result.implName.to_string().parse().unwrap(),
            authoring_version: runtime_version_result.authoringVersion,
            spec_version: runtime_version_result.specVersion,
            impl_version: runtime_version_result.implVersion,
            apis: api_vec,
            transaction_version: runtime_version_result.transactionVersion,
            state_version: runtime_version_result.stateVersion,
        };
        Ok(runtime_version_ok)
    }

    pub fn extract_genesis_hash(body: &[u8]) -> core::result::Result<String, Error> {
        let (genesis_hash, _): (GenesisHash, usize) = serde_json_core::from_slice(body).unwrap();
        let result = genesis_hash.result.to_string().parse().unwrap();
        Ok(result)
    }

    fn vec_to_hex_string(v: &Vec<u8>) -> String {
        let mut res = "0x".to_string();
        for a in v.iter() {
            write!(res, "{:02x}", a).expect("should create hex string");
        }
        res
    }

    const PREFIX: &[u8] = b"SS58PRE";

    fn ss58hash(data: &[u8]) -> blake2_rfc::blake2b::Blake2bResult {
        let mut context = blake2_rfc::blake2b::Blake2b::new(64);
        context.update(PREFIX);
        context.update(data);
        context.finalize()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;

        fn default_accounts() -> ink_env::test::DefaultAccounts<PinkEnvironment> {
            ink_env::test::default_accounts::<Environment>()
        }

        #[ink::test]
        fn can_set_chain_info() {
            use pink_extension::chain_extension::{mock, HttpResponse};
            fat_utils::test_helper::mock_all();
            let salt = "kusama";
            // Create the attestation helpers
            let (generator, verifier) = attestation::create(salt.as_bytes());
            let account_public: &[u8] = &verifier.pubkey;
            //let account_public_ss58 = account_public.to_base58();
            let version = match Ss58AddressFormat::try_from(salt) {
                Ok(version) => {
                    // println!("{:?}", version);
                    version
                },
                Err(_e) => {
                    Ss58AddressFormat::custom(0u16)
                }
            };
            let ident: u16 = u16::from(version) & 0b0011_1111_1111_1111;
            let mut v: Vec<u8> = match ident {
                0..=63 => vec![ident as u8],
                64..=16_383 => {
                    let first = ((ident & 0b0000_0000_1111_1100) as u8) >> 2;
                    let second = ((ident >> 8) as u8) | ((ident & 0b0000_0000_0000_0011) as u8) << 6;
                    vec![first | 0b01000000, second]
                }
                _ => unreachable!("masked out the upper two bits; qed"),
            };
            v.extend(account_public);
            let r = ss58hash(&v);
            v.extend(&r.as_bytes()[0..2]);
            let account_public_ss58 = v.to_base58();
            // println!("{:?}", v);
            // println!("{}", account_public_ss58);
            assert_eq!("HF39woh1kRBzQNseVHMLccjeay85KsNAHuJh76Ahp5WAXd4", account_public_ss58);
        }

        #[ink::test]
        fn can_parse_next_nonce() {
            let response = r#"{
                "jsonrpc":"2.0","result":238,"id":1
            }"#;
            let result = extract_next_nonce(response.as_bytes());

            assert_eq!(result, Ok(238));
        }

        #[ink::test]
        fn can_parse_runtime_version() {
            let response = r#"{
                "jsonrpc":"2.0","result":{"specName":"kusama","implName":"parity-kusama","authoringVersion":2,"specVersion":9230,"implVersion":0,"apis":[["0xdf6acb689907609b",4],["0x37e397fc7c91f5e4",1],["0x40fe3ad401f8959a",6],["0xd2bc9897eed08f15",3],["0xf78b278be53f454c",2],["0xaf2c0297a23e6d3d",2],["0x49eaaf1b548a0cb0",1],["0x91d5df18b0d2cf58",1],["0xed99c5acb25eedf5",3],["0xcbca25e39f142387",2],["0x687ad44ad37f03c2",1],["0xab3c0572291feb8b",1],["0xbc9d89904f5b923f",1],["0x37c8bb1350a9a2a8",1]],"transactionVersion":11,"stateVersion":0},"id":1
            }"#;
            let result = extract_runtime_version(response.as_bytes());
            let exp_result = RuntimeVersionOk {
                spec_name: "kusama".to_string(),
                impl_name: "parity-kusama".to_string(),
                authoring_version: 2,
                spec_version: 9230,
                impl_version: 0,
                apis: vec![
                    ("0xdf6acb689907609b".to_string(), 4),
                    ("0x37e397fc7c91f5e4".to_string(), 1),
                    ("0x40fe3ad401f8959a".to_string(), 6),
                    ("0xd2bc9897eed08f15".to_string(), 3),
                    ("0xf78b278be53f454c".to_string(), 2),
                    ("0xaf2c0297a23e6d3d".to_string(), 2),
                    ("0x49eaaf1b548a0cb0".to_string(), 1),
                    ("0x91d5df18b0d2cf58".to_string(), 1),
                    ("0xed99c5acb25eedf5".to_string(), 3),
                    ("0xcbca25e39f142387".to_string(), 2),
                    ("0x687ad44ad37f03c2".to_string(), 1),
                    ("0xab3c0572291feb8b".to_string(), 1),
                    ("0xbc9d89904f5b923f".to_string(), 1),
                    ("0x37c8bb1350a9a2a8".to_string(), 1),
                ],
                transaction_version: 11,
                state_version: 0,
            };

            assert_eq!(result, Ok(exp_result));
        }

        #[ink::test]
        fn can_parse_genesis_hash() {
            let response = r#"{
                "jsonrpc":"2.0","result":"0xb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe","id":1
            }"#;
            let result = extract_genesis_hash(response.as_bytes());

            assert_eq!(
                result,
                Ok(
                    "0xb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe"
                        .to_string()
                )
            );
        }
    }
}
