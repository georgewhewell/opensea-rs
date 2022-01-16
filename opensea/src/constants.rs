pub const ORDERBOOK_VERSION: u64 = 1;
pub const API_VERSION: u64 = 1;
pub const ORDERBOOK_PATH: &str = "/wyvern/v${ORDERBOOK_VERSION}";
pub const API_PATH: &str = "/api/v${ORDERBOOK_VERSION}";

pub const COLLECTION_PATH: &str = "/api/v${ORDERBOOK_VERSION}/asset_contract/${ADDRESS}";

pub const API_BASE_MAINNET: &str = "https://api.opensea.io";
pub const API_BASE_RINKEBY: &str = "https://rinkeby-api.opensea.io";
pub const SITE_HOST_MAINNET: &str = "https://opensea.io";
pub const SITE_HOST_RINKEBY: &str = "https://rinkeby.opensea.io";

use ethers::types::Address;
use once_cell::sync::Lazy;

pub static OPENSEA_FEE_RECIPIENT: Lazy<Address> = Lazy::new(|| {
    "0x5b3256965e7c3cf26e11fcaf296dfc8807c01073"
        .parse()
        .unwrap()
});

pub static OPENSEA_FEE_RECIPIENT_RINKEBY: Lazy<Address> = Lazy::new(|| {
    "0xa839D4b5A36265795EbA6894651a8aF3d0aE2e68"
        .parse()
        .unwrap()
});

pub static OPENSEA_ADDRESS: Lazy<Address> = Lazy::new(|| {
    "0x7be8076f4ea4a4ad08075c2508e481d6c946d12b"
        .parse()
        .unwrap()
});

pub static OPENSEA_ADDRESS_RINKEBY: Lazy<Address> = Lazy::new(|| {
    "0x5206e78b21Ce315ce284FB24cf05e0585A93B1d9"
        .parse()
        .unwrap()
});

pub static OPENSEA_PROXY_REGISTRY_RINKEBY: Lazy<Address> = Lazy::new(|| {
    "0xf57b2c51ded3a29e6891aba85459d600256cf317"
        .parse()
        .unwrap()
});

pub static WETH_ADDRESS_RINKEBY: Lazy<Address> = Lazy::new(|| {
    "0xc778417e063141139fce010982780140aa0cd5ab"
        .parse()
        .unwrap()
});

pub static OPENSEA_TRANSFER_PROXY_MAINNET: Lazy<Address> = Lazy::new(|| {
    "0xe5c783ee536cf5e63e792988335c4255169be4e1"
        .parse()
        .unwrap()
});

pub static OPENSEA_TRANSFER_PROXY_RINKEBY: Lazy<Address> = Lazy::new(|| {
    "0x82d102457854c985221249f86659c9d6cf12aa72"
        .parse()
        .unwrap()
});
