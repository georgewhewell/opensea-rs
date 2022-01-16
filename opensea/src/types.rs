use crate::{
    constants::{self, WETH_ADDRESS_RINKEBY},
    contracts, OrderRequest,
};
use chrono::NaiveDateTime;
use eth_encode_packed::{abi::encode_packed, SolidityDataType, TakeLastXBytes};
use ethers::{
    core::utils::id,
    prelude::{rand::thread_rng, LocalWallet, Signer, SignerMiddleware},
    types::{Address, Bytes, H256, U256},
    utils::{hash_message, keccak256},
};
use serde::{ser::SerializeMap, Deserialize, Serialize, Serializer};
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub enum Network {
    Mainnet,
    Rinkeby,
}

impl Network {
    pub fn url(&self) -> &str {
        match self {
            Network::Mainnet => constants::API_BASE_MAINNET,
            Network::Rinkeby => constants::API_BASE_RINKEBY,
        }
    }

    pub fn orderbook(&self) -> String {
        let url = self.url();
        format!("{}/wyvern/v{}", url, constants::ORDERBOOK_VERSION)
    }

    pub fn orderbook_post(&self) -> String {
        let url = self.url();
        format!("{}/wyvern/v{}", url, constants::ORDERBOOK_VERSION)
    }

    pub fn api(&self) -> String {
        let url = self.url();
        format!("{}/api/v{}", url, constants::ORDERBOOK_VERSION)
    }

    pub fn collection(&self, address: Address) -> String {
        let url = self.url();
        format!("{}/api/v{}/", url, constants::ORDERBOOK_VERSION,)
    }

    pub fn asset(&self, address: Address, token_id: U256) -> String {
        let url = self.url();
        format!("{}/api/v{}/", url, constants::API_VERSION)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Asset {}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// The exact arguments required to provide to the smart contract
pub struct UnsignedOrder {
    // addresses involved
    pub exchange: Address,
    pub maker: Address,
    pub taker: Address,
    pub fee_recipient: Address,
    pub target: Address,
    pub static_target: Address,
    pub payment_token: Address,

    // fees
    pub maker_relayer_fee: U256,
    pub taker_relayer_fee: U256,
    pub maker_protocol_fee: U256,
    pub taker_protocol_fee: U256,

    pub base_price: U256,
    // pub current_price: U256,
    pub extra: U256,
    pub listing_time: U256,
    pub expiration_time: U256,
    pub salt: U256,

    pub fee_method: u8,
    pub side: u8,
    pub sale_kind: u8,
    pub how_to_call: u8,

    pub calldata: Bytes,
    pub replacement_pattern: Bytes,
    pub static_extradata: Bytes,
}

pub fn ser_u256_dec<S>(id: &U256, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&format!("{:.0}", id))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The exact arguments required to provide to the smart contract
///
pub struct MinimalOrder {
    // addresses involved
    pub exchange: Address,
    pub maker: Address,
    pub taker: Address,
    pub fee_recipient: Address,
    pub target: Address,
    pub static_target: Address,
    pub payment_token: Address,

    // fees
    #[serde(serialize_with = "ser_u256_dec")]
    pub maker_relayer_fee: U256,
    #[serde(serialize_with = "ser_u256_dec")]
    pub taker_relayer_fee: U256,
    #[serde(serialize_with = "ser_u256_dec")]
    pub maker_protocol_fee: U256,
    #[serde(serialize_with = "ser_u256_dec")]
    pub taker_protocol_fee: U256,

    #[serde(serialize_with = "ser_u256_dec")]
    pub base_price: U256,
    // pub current_price: U256,
    #[serde(serialize_with = "ser_u256_dec")]
    pub extra: U256,
    #[serde(serialize_with = "ser_u256_dec")]
    pub listing_time: U256,
    #[serde(serialize_with = "ser_u256_dec")]
    pub expiration_time: U256,
    #[serde(serialize_with = "ser_u256_dec")]
    pub salt: U256,

    pub fee_method: u8,
    pub side: u8,
    pub sale_kind: u8,
    pub how_to_call: u8,

    pub calldata: Bytes,

    pub replacement_pattern: Bytes,

    pub static_extradata: Bytes,

    #[serde(serialize_with = "ser_u256_dec")]
    pub quantity: U256,
    pub metadata: Metadata,
    pub hash: H256,
    pub v: u8,
    pub r: H256,
    pub s: H256,
}

impl MinimalOrder {
    pub fn calculate_hash(&self) -> H256 {
        let calldata_bytes = self.calldata.to_vec();
        let replacement_pattern_bytes = self.replacement_pattern.to_vec();
        let static_extradata_bytes = self.static_extradata.to_vec();
        let parts = vec![
            SolidityDataType::Address(self.exchange),
            SolidityDataType::Address(self.maker),
            SolidityDataType::Address(self.taker),
            SolidityDataType::Number(self.maker_relayer_fee),
            SolidityDataType::Number(self.taker_relayer_fee),
            SolidityDataType::Number(self.maker_protocol_fee),
            SolidityDataType::Number(self.taker_protocol_fee),
            SolidityDataType::Address(self.fee_recipient),
            SolidityDataType::NumberWithShift(self.fee_method.into(), TakeLastXBytes(8)),
            SolidityDataType::NumberWithShift(self.side.into(), TakeLastXBytes(8)),
            SolidityDataType::NumberWithShift(self.sale_kind.into(), TakeLastXBytes(8)),
            SolidityDataType::Address(self.target),
            SolidityDataType::NumberWithShift(self.how_to_call.into(), TakeLastXBytes(8)),
            SolidityDataType::Bytes(&calldata_bytes),
            SolidityDataType::Bytes(&replacement_pattern_bytes),
            SolidityDataType::Address(self.static_target),
            SolidityDataType::Bytes(&static_extradata_bytes),
            SolidityDataType::Address(self.payment_token),
            SolidityDataType::Number(self.base_price),
            SolidityDataType::Number(self.extra),
            SolidityDataType::Number(self.listing_time.into()),
            SolidityDataType::Number(self.expiration_time.into()),
            SolidityDataType::Number(self.salt),
        ];
        let (packed, _hex) = encode_packed(&parts);
        keccak256(&packed).into()
    }
}

#[derive(Clone, Debug)]
pub struct BidArgs {
    pub taker: Address,
    pub token: Address,
    pub token_id: U256,
    pub timestamp: Option<u64>,
}

// wtf
fn u256_to_h256(u256: U256) -> H256 {
    // let mut buf = vec![0; 32];
    let mut out = H256::zero();
    u256.to_big_endian(&mut out.0);
    out
    // H256::from_slice(&buf)
}

impl UnsignedOrder {
    pub async fn sign_order(self, signer: impl Signer, metadata: Metadata) -> MinimalOrder {
        let order_hash = self.calculate_hash();
        let sig = signer.sign_message(order_hash.as_bytes()).await.unwrap();
        MinimalOrder {
            quantity: U256::from(1u64),
            exchange: self.exchange,
            maker: self.maker,
            taker: self.taker,
            fee_recipient: self.fee_recipient,
            target: self.target,
            static_target: self.static_target,
            payment_token: self.payment_token,
            maker_relayer_fee: self.maker_relayer_fee,
            taker_relayer_fee: self.taker_relayer_fee,
            maker_protocol_fee: self.maker_protocol_fee,
            taker_protocol_fee: self.taker_protocol_fee,
            base_price: self.base_price,
            extra: self.extra,
            listing_time: self.listing_time,
            expiration_time: self.expiration_time,
            salt: self.salt,
            fee_method: self.fee_method,
            side: self.side,
            sale_kind: self.sale_kind,
            how_to_call: self.how_to_call,
            calldata: self.calldata,
            replacement_pattern: self.replacement_pattern,
            static_extradata: self.static_extradata,
            hash: order_hash,
            metadata: metadata,
            v: sig.v.try_into().unwrap(),
            r: u256_to_h256(sig.r),
            s: u256_to_h256(sig.s),
        }
    }

    fn calculate_hash(&self) -> H256 {
        let calldata_bytes = self.calldata.to_vec();
        let replacement_pattern_bytes = self.replacement_pattern.to_vec();
        let static_extradata_bytes = self.static_extradata.to_vec();
        let parts = vec![
            SolidityDataType::Address(self.exchange),
            SolidityDataType::Address(self.maker),
            SolidityDataType::Address(self.taker),
            SolidityDataType::Number(self.maker_relayer_fee),
            SolidityDataType::Number(self.taker_relayer_fee),
            SolidityDataType::Number(self.maker_protocol_fee),
            SolidityDataType::Number(self.taker_protocol_fee),
            SolidityDataType::Address(self.fee_recipient),
            SolidityDataType::NumberWithShift(self.fee_method.into(), TakeLastXBytes(8)),
            SolidityDataType::NumberWithShift(self.side.into(), TakeLastXBytes(8)),
            SolidityDataType::NumberWithShift(self.sale_kind.into(), TakeLastXBytes(8)),
            SolidityDataType::Address(self.target),
            SolidityDataType::NumberWithShift(self.how_to_call.into(), TakeLastXBytes(8)),
            SolidityDataType::Bytes(&calldata_bytes),
            SolidityDataType::Bytes(&replacement_pattern_bytes),
            SolidityDataType::Address(self.static_target),
            SolidityDataType::Bytes(&static_extradata_bytes),
            SolidityDataType::Address(self.payment_token),
            SolidityDataType::Number(self.base_price),
            SolidityDataType::Number(self.extra),
            SolidityDataType::Number(self.listing_time.into()),
            SolidityDataType::Number(self.expiration_time.into()),
            SolidityDataType::Number(self.salt),
        ];
        let (packed, _hex) = encode_packed(&parts);
        keccak256(&packed).into()
    }

    fn buy_from_metadata(maker: Address, metadata: &Metadata, payment_token: Address) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiry = now + 3600;

        let schema = &metadata.schema;
        let (calldata, pattern) = match schema.as_str() {
            "ERC721" => {
                let abi = ethers::contract::BaseContract::from(contracts::OPENSEA_ABI.clone());
                let sig = id("transferFrom(address,address,uint256)");
                let data = (Address::zero(), maker, metadata.asset.id);
                let replacement_pattern = hex::decode("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().into();
                (
                    abi.encode_with_selector(sig, data).unwrap(),
                    replacement_pattern,
                )
            }
            "ERC1155" => {
                let replacement_pattern = hex::decode("000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().into();

                let abi = ethers::contract::BaseContract::from(contracts::OPENSEA_ABI.clone());
                let sig = id("safeTransferFrom(address,address,uint256,uint256,bytes)");
                let data = (
                    Address::zero(),
                    maker,
                    metadata.asset.id,
                    U256::from(1u32),
                    Vec::<u8>::new(),
                );
                (
                    abi.encode_with_selector(sig, data).unwrap(),
                    replacement_pattern,
                )
            }
            unsupported => {
                panic!("Unsupported schema: {}", unsupported)
            }
        };

        Self {
            exchange: *constants::OPENSEA_ADDRESS_RINKEBY,
            maker: maker,
            taker: Address::zero(),
            // testnests frontend uses mainnet address..
            fee_recipient: *constants::OPENSEA_FEE_RECIPIENT,
            // fee_recipient: *constants::OPENSEA_FEE_RECIPIENT_RINKEBY,
            target: metadata.asset.address,
            payment_token,
            maker_relayer_fee: 0.into(),
            taker_relayer_fee: 2000.into(),
            maker_protocol_fee: 0.into(),
            taker_protocol_fee: 0.into(),
            base_price: U256::from_dec_str("70000000000000000").unwrap(),
            extra: 0.into(),
            listing_time: now.into(),
            expiration_time: expiry.into(),
            salt: ethers::core::rand::random::<u64>().into(),
            fee_method: 1.into(),
            side: 0.into(),
            sale_kind: 0.into(),
            how_to_call: 0.into(),
            calldata: calldata,
            replacement_pattern: pattern,
            static_target: Address::zero(),
            static_extradata: Bytes::default(),
        }
    }

    fn sell_from_metadata(
        maker: Address,
        metadata: &Metadata,
        payment_token: Option<Address>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiry = now + 3600;

        let schema = &metadata.schema;
        let (calldata, pattern) = match schema.as_str() {
            "ERC721" => {
                let abi = ethers::contract::BaseContract::from(contracts::OPENSEA_ABI.clone());
                let sig = id("transferFrom(address,address,uint256)");
                let data = (maker, Address::zero(), metadata.asset.id);

                let replacement_pattern = hex::decode("000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000").unwrap().into();
                (
                    abi.encode_with_selector(sig, data).unwrap(),
                    replacement_pattern,
                )
            }
            "ERC1155" => {
                let replacement_pattern = hex::decode("000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().into();

                let abi = ethers::contract::BaseContract::from(contracts::OPENSEA_ABI.clone());
                let sig = id("safeTransferFrom(address,address,uint256,uint256,bytes)");
                let data = (
                    maker,
                    Address::zero(),
                    metadata.asset.id,
                    U256::from(1u32),
                    Vec::<u8>::new(),
                );
                (
                    abi.encode_with_selector(sig, data).unwrap(),
                    replacement_pattern,
                )
            }
            unsupported => {
                panic!("Unsupported schema: {}", unsupported)
            }
        };

        Self {
            exchange: *constants::OPENSEA_ADDRESS_RINKEBY,
            maker: maker,
            taker: Address::zero(),
            fee_recipient: *constants::OPENSEA_FEE_RECIPIENT_RINKEBY,
            target: metadata.asset.address,
            payment_token: payment_token.unwrap_or_else(|| Address::zero()),
            maker_relayer_fee: 500.into(),
            taker_relayer_fee: 0.into(),
            maker_protocol_fee: 0.into(),
            taker_protocol_fee: 0.into(),
            base_price: U256::from_dec_str("70000000000000000").unwrap(),
            extra: 0.into(),
            listing_time: (now - 3600).into(),
            expiration_time: 0.into(),
            salt: ethers::core::rand::random::<u64>().into(),
            fee_method: 1.into(),
            side: 1.into(),
            sale_kind: 0.into(),
            how_to_call: 0.into(),
            calldata: calldata,
            replacement_pattern: pattern,
            static_target: Address::zero(),
            static_extradata: Bytes::default(),
        }
    }
}

impl From<Order> for MinimalOrder {
    fn from(order: Order) -> Self {
        Self {
            quantity: order.quantity,
            exchange: order.exchange,
            maker: order.maker.address,
            taker: order.taker.address,
            fee_recipient: order.fee_recipient.address,
            target: order.target,
            static_target: order.static_target,
            payment_token: order.payment_token,
            base_price: order.base_price,
            // current_price: order.current_price,
            extra: order.extra,
            listing_time: order.listing_time.into(),
            expiration_time: order.expiration_time.into(),
            salt: order.salt,
            fee_method: order.fee_method,
            how_to_call: order.how_to_call,
            calldata: order.calldata,
            replacement_pattern: order.replacement_pattern,
            static_extradata: order.static_extradata,
            hash: order.order_hash,
            metadata: order.metadata,
            v: order.v as u8,
            r: order.r,
            s: order.s,
            maker_relayer_fee: order.maker_relayer_fee,
            taker_relayer_fee: order.taker_relayer_fee,
            maker_protocol_fee: order.maker_protocol_fee,
            taker_protocol_fee: order.taker_protocol_fee,
            sale_kind: order.sale_kind,
            side: order.side,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum AssetContractType {
    #[serde(rename = "fungible")]
    Fungible,
    #[serde(rename = "non-fungible")]
    NonFungible,
    #[serde(rename = "semi-fungible")]
    SemiFungible,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum SchemaName {
    ERC721,
    ERC1155,
    CRYPTOPUNKS,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AssetContract {
    pub address: Address,
    asset_contract_type: AssetContractType,
    created_date: NaiveDateTime,
    pub name: Option<String>,
    nft_version: Option<String>,
    opensea_version: Option<String>,
    owner: Option<u64>,
    // schema_name: Schema,
    symbol: Option<String>,
    description: Option<String>,
    external_link: Option<String>,
    image_url: Option<String>,
    default_to_fiat: bool,
    dev_buyer_fee_basis_points: u64,
    dev_seller_fee_basis_points: u64,
    only_proxied_transfers: bool,
    opensea_buyer_fee_basis_points: u64,
    opensea_seller_fee_basis_points: u64,
    buyer_fee_basis_points: u64,
    seller_fee_basis_points: u64,
    // payout_address: Option<Address>,
}

/// The response we get from the API
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Order {
    pub id: Option<u64>,
    pub asset: Option<Asset>,
    pub listing_time: u64,
    pub expiration_time: u64,
    pub order_hash: H256,
    pub v: u64,
    #[serde(deserialize_with = "h256_from_str")]
    pub r: H256,
    #[serde(deserialize_with = "h256_from_str")]
    pub s: H256,

    #[serde(deserialize_with = "u256_from_dec_str")]
    pub base_price: U256,

    // #[serde(deserialize_with = "u256_from_dec_str")]
    // pub current_price: U256,
    pub side: u8,
    pub sale_kind: u8,
    pub target: Address,
    pub how_to_call: u8,

    // pub approved_on_chain: Option<bool>,
    // pub cancelled: Option<bool>,
    // pub finalized: Option<bool>,
    // pub marked_invalid: Option<bool>,
    pub fee_recipient: User,
    pub maker: User,

    #[serde(deserialize_with = "u256_from_dec_str")]
    pub salt: U256,

    pub payment_token: Address,
    #[serde(deserialize_with = "u256_from_dec_str")]
    pub extra: U256,

    #[serde(deserialize_with = "u256_from_dec_str")]
    pub maker_protocol_fee: U256,
    #[serde(deserialize_with = "u256_from_dec_str")]
    pub maker_relayer_fee: U256,
    #[serde(deserialize_with = "u256_from_dec_str")]
    pub maker_referrer_fee: U256,

    #[serde(deserialize_with = "u256_from_dec_str")]
    pub taker_protocol_fee: U256,
    #[serde(deserialize_with = "u256_from_dec_str")]
    pub taker_relayer_fee: U256,

    pub calldata: Bytes,
    pub replacement_pattern: Bytes,

    pub static_target: Address,
    pub static_extradata: Bytes,

    pub exchange: Address,
    pub taker: User,

    #[serde(deserialize_with = "u256_from_dec_str")]
    pub quantity: U256,
    pub metadata: Metadata,

    pub fee_method: u8,
}

#[derive(Clone, Debug)]
pub struct BuyArgs {
    pub taker: Address,
    pub recipient: Address,
    pub token: Address,
    pub token_id: U256,
    pub timestamp: Option<u64>,
}

pub struct SellArgs {
    pub taker: Address,
    pub recipient: Address,
    pub timestamp: Option<u64>,
    pub token: Address,
    pub token_id: U256,
}

impl Order {
    pub fn match_sell(&self, args: BuyArgs) -> MinimalOrder {
        let mut order = MinimalOrder::from(self.clone());

        // buy order
        order.side = 0;
        // the order maker is our taker
        order.maker = args.taker;
        order.taker = self.maker.address;
        order.target = args.token;
        order.expiration_time = 0.into();
        order.extra = 0.into();
        order.salt = ethers::core::rand::random::<u64>().into();
        order.fee_recipient = Address::zero(); // *constants::OPENSEA_FEE_RECIPIENT;

        // order.maker_relayer_fee = 0.into();
        // order.taker_relayer_fee = 0.into();
        // order.maker_protocol_fee = 0.into();
        // order.taker_protocol_fee = 0.into();

        let schema = &self.metadata.schema;
        let calldata = if schema == "ERC721" {
            // TODO: abigen should emit this as a typesafe method over a "Typed" BaseContract
            let abi = ethers::contract::BaseContract::from(contracts::OPENSEA_ABI.clone());
            let sig = id("transferFrom(address,address,uint256)");
            let data = (Address::zero(), args.recipient, args.token_id);

            order.replacement_pattern = hex::decode("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().into();
            abi.encode_with_selector(sig, data).unwrap()
        } else if schema == "ERC1155" {
            // safeTransferFrom(address,address,uint256,uint256,bytes), replacement for `from`
            order.replacement_pattern = hex::decode("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().into();

            let abi = ethers::contract::BaseContract::from(contracts::OPENSEA_ABI.clone());
            let sig = id("safeTransferFrom(address,address,uint256,uint256,bytes)");
            let data = (
                Address::zero(),
                args.recipient,
                args.token_id,
                self.quantity,
                Vec::<u8>::new(),
            );
            abi.encode_with_selector(sig, data).unwrap()
        } else {
            panic!("Unsupported schema")
        };
        order.calldata = calldata;

        let listing_time = args
            .timestamp
            .unwrap_or_else(|| chrono::offset::Local::now().timestamp() as u64 - 100);
        order.listing_time = listing_time.into();

        order
    }

    pub fn match_buy(&self, args: SellArgs) -> UnsignedOrder {
        let schema = &self.metadata.schema;
        let (replacement_pattern, calldata) = if schema == "ERC721" {
            // TODO: abigen should emit this as a typesafe method over a "Typed" BaseContract
            let abi = ethers::contract::BaseContract::from(contracts::OPENSEA_ABI.clone());
            let sig = id("transferFrom(address,address,uint256)");
            let data = (args.taker, Address::zero(), args.token_id);

            let replacement_pattern = hex::decode("000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000").unwrap().into();
            (
                replacement_pattern,
                abi.encode_with_selector(sig, data).unwrap(),
            )
        } else if schema == "ERC1155" {
            // safeTransferFrom(address,address,uint256,uint256,bytes), replacement for `from`
            let replacement_pattern = hex::decode("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().into();

            let abi = ethers::contract::BaseContract::from(contracts::OPENSEA_ABI.clone());
            let sig = id("safeTransferFrom(address,address,uint256,uint256,bytes)");
            let data = (
                Address::zero(),
                args.recipient,
                args.token_id,
                self.quantity,
                Vec::<u8>::new(),
            );
            (
                replacement_pattern,
                abi.encode_with_selector(sig, data).unwrap(),
            )
        } else {
            panic!("Unsupported schema")
        };

        let listing_time = args
            .timestamp
            .unwrap_or_else(|| chrono::offset::Local::now().timestamp() as u64 - 100);

        UnsignedOrder {
            exchange: self.exchange,
            maker: args.taker,
            taker: self.maker.address,
            fee_recipient: Address::zero(), // *constants::OPENSEA_FEE_RECIPIENT;
            target: self.target,
            static_target: self.static_target,
            payment_token: self.payment_token,
            maker_relayer_fee: self.maker_relayer_fee,
            taker_relayer_fee: self.taker_relayer_fee,
            maker_protocol_fee: self.maker_protocol_fee,
            taker_protocol_fee: self.taker_protocol_fee,
            base_price: self.base_price,
            extra: self.extra,
            listing_time: listing_time.into(),
            expiration_time: self.expiration_time.into(),
            salt: ethers::core::rand::random::<u64>().into(),
            fee_method: self.fee_method,
            side: 1.into(),
            sale_kind: self.sale_kind,
            how_to_call: self.how_to_call,
            calldata: calldata,
            replacement_pattern: replacement_pattern,
            static_extradata: self.static_extradata.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub asset: AssetId,
    pub schema: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetId {
    #[serde(deserialize_with = "u256_from_dec_str")]
    #[serde(serialize_with = "ser_u256_dec")]
    pub id: U256,
    pub address: Address,
}

use serde::de;
pub fn u256_from_dec_str<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: &str = de::Deserialize::deserialize(deserializer)?;
    U256::from_dec_str(s).map_err(de::Error::custom)
}

use std::{str::FromStr, time::SystemTime};
pub fn h256_from_str<'de, D>(deserializer: D) -> Result<H256, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: &str = de::Deserialize::deserialize(deserializer)?;
    if s.starts_with("0x") {
        H256::from_str(s).map_err(de::Error::custom)
    } else {
        Ok(H256::zero())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub user: Option<Username>,
    pub profile_img_url: Option<String>,
    pub address: Address,
    pub config: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Username {
    username: Option<String>,
}

pub enum OrderSide {
    Buy,
    Sell,
}

pub async fn create_maker_order<S: Signer>(
    maker: &Address,
    metadata: Metadata,
    signer: S,
    is_buy: bool,
    payment_token: Option<Address>,
) -> Order {
    // make buy order
    let unsigned = if is_buy {
        UnsignedOrder::buy_from_metadata(maker.clone(), &metadata, payment_token.unwrap())
    } else {
        UnsignedOrder::sell_from_metadata(maker.clone(), &metadata, payment_token)
    };

    let order_hash = unsigned.calculate_hash();
    println!("order hash is: {:?}", order_hash);
    let signed = unsigned.sign_order(signer, metadata.clone()).await;
    // println!("signed hash: {:?}", signed)
    Order {
        quantity: 1.into(),
        id: None,
        asset: None,
        listing_time: signed.listing_time.try_into().unwrap(),
        expiration_time: signed.expiration_time.try_into().unwrap(),
        order_hash: order_hash,
        v: signed.v.try_into().unwrap(),
        r: signed.r,
        s: signed.s,
        base_price: signed.base_price,
        side: signed.side,
        sale_kind: signed.sale_kind,
        target: signed.target,
        how_to_call: signed.how_to_call,
        // approved_on_chain: Some(false),
        // cancelled: Some(false),
        // finalized: Some(false),
        // marked_invalid: Some(false),
        salt: signed.salt,
        payment_token: signed.payment_token,
        extra: signed.extra,
        maker_protocol_fee: signed.maker_protocol_fee,
        maker_relayer_fee: signed.maker_relayer_fee,
        maker_referrer_fee: 0u64.into(),
        taker_protocol_fee: signed.taker_protocol_fee,
        taker_relayer_fee: signed.taker_relayer_fee,
        calldata: signed.calldata,
        replacement_pattern: signed.replacement_pattern,
        static_target: signed.static_target,
        static_extradata: signed.static_extradata,
        exchange: signed.exchange,
        fee_recipient: User {
            address: signed.fee_recipient,
            user: None,
            profile_img_url: None,
            config: None,
        },
        maker: User {
            address: signed.maker,
            user: None,
            profile_img_url: None,
            config: None,
        },
        taker: User {
            address: signed.taker,
            user: None,
            profile_img_url: None,
            config: None,
        },
        metadata: metadata,
        fee_method: signed.fee_method,
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use std::sync::Arc;

    use ethers::prelude::rand::thread_rng;
    use ethers::prelude::{Middleware, Provider};
    use ethers::signers::Signer;

    use crate::api::OpenSeaApiConfig;
    use crate::Client;

    use super::*;

    // #[tokio::test]
    // async fn test_roundtrip_order() {
    //     let provider = Provider::try_from("http://localhost:18545").unwrap();
    //     let provider = Arc::new(provider);

    //     let accounts = provider.get_accounts().await.unwrap()[0];

    //     let sell = create_maker_order(&wallet);
    //     let sell_minimal = MinimalOrder::from(sell.clone());

    //     let buyArgs = BuyArgs {
    //         taker: wallet.address(),
    //         recipient: wallet.address(),
    //         token: Address::default(),
    //         token_id: 1.into(),
    //         timestamp: 0.into(),
    //     };
    //     let buy = sell.match_sell(buyArgs);

    //     let config = OpenSeaApiConfig::default();

    //     let client = Client::new(provider.clone(), OpenSeaApiConfig::with_api_key(""));

    //     let call = client.atomic_match(buy, sell_minimal).await.unwrap();

    //     let a = call.send().await.unwrap().await.unwrap();
    //             // construct matching sell
    //     // let order = Order::from(buy);
    // }

    #[test]
    fn deser_order() {
        let _order: Order = serde_json::from_str(include_str!("./../../order.json")).unwrap();
    }
}
