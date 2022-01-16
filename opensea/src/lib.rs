pub mod constants;

pub mod types;
use api::OpenSeaApiConfig;
use ethers::{
    contract::builders::ContractCall,
    prelude::{Address, U256},
    providers::Middleware,
    utils::parse_units,
};
pub use types::BuyArgs;
use types::Order;

pub mod api;
pub use api::{OpenSeaApi, OpenSeaApiError, OrderRequest};

mod contracts;
pub use contracts::OpenSea;
pub use contracts::OpenseaProxyRegistry;
pub use contracts::ERC20;
pub use contracts::NFT;

use crate::constants::WETH_ADDRESS_RINKEBY;
use std::sync::Arc;
use thiserror::Error;
use types::MinimalOrder;

use crate::types::UnsignedOrder;

pub async fn get_n_cheapest_orders(
    api: &OpenSeaApi,
    contract_address: Address,
    token_id: U256,
    num: usize,
) -> Result<Vec<Order>, ClientError> {
    // get the order
    let req = OrderRequest {
        side: 1,
        token_id: token_id.to_string(),
        contract_address,
        // use max limit
        limit: 50,
    };

    // get the cheapest orders above 1e16 Wei. Used to filter out "noise"
    // bids which exist in OpenSea, presumably a bug?
    let mut orders = api
        .get_orders(req)
        .await?
        .into_iter()
        .filter(|order| order.base_price > parse_units("1", 14).unwrap())
        .collect::<Vec<_>>();
    // orders.sort_by(|o1, o2| o1.current_price.cmp(&o2.current_price));

    // get at most `orders.len()` items
    let len = std::cmp::min(num, orders.len());
    Ok(orders.into_iter().take(len).collect())
}

#[derive(Clone)]
pub struct Client<M> {
    pub api: OpenSeaApi,
    pub contracts: OpenSea<M>,
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error(transparent)]
    OpenSeaApiError(#[from] OpenSeaApiError),
}

impl<M: Middleware> Client<M> {
    pub fn new(provider: Arc<M>, cfg: OpenSeaApiConfig) -> Self {
        let address = match cfg.network {
            types::Network::Mainnet => *constants::OPENSEA_ADDRESS,
            types::Network::Rinkeby => *constants::OPENSEA_ADDRESS_RINKEBY,
        };
        println!("opensea address is {:?}", &address);
        Self {
            api: OpenSeaApi::new(cfg),
            contracts: OpenSea::new(address, provider),
        }
    }

    pub async fn buy(
        &self,
        args: BuyArgs,
        n: usize,
    ) -> Result<Vec<ContractCall<M, ()>>, ClientError> {
        println!(
            "Querying Opensea API for {} orders of token {}",
            n, args.token_id
        );
        let sells = get_n_cheapest_orders(&self.api, args.token, args.token_id, n).await?;
        println!("sells: {:#?}", sells);
        let mut calls = Vec::new();
        for sell in sells {
            println!(
                "[Token Id = {:?}] Maker: {:?}",
                args.token_id, sell.maker.address,
            );
            let real_hash = sell.order_hash;
            // let unsign = UnsignedOrder::from(&sell);
            // make its corresponding buy
            let buy = sell.match_sell(args.clone());
            let sell = MinimalOrder::from(sell);
            let sell_hash = sell.calculate_hash();
            assert_eq!(real_hash, sell_hash);
            println!("HASH IS CORRECT!!");
            let call = self.atomic_match(buy, sell, true).await?;
            calls.push(call);
        }

        Ok(calls)
    }

    pub async fn buy_one(&self, args: BuyArgs) -> Result<ContractCall<M, ()>, ClientError> {
        let sell = get_n_cheapest_orders(&self.api, args.token, args.token_id, 1).await?[0].clone();
        // make its corresponding buy
        let buy = sell.match_sell(args.clone());
        let sell = MinimalOrder::from(sell);
        self.atomic_match(buy, sell, true).await
    }

    pub fn check_order(&self, buy: &MinimalOrder, sell: &MinimalOrder) -> Result<(), ()> {
        // run checks.. https://github.com/ProjectOpenSea/wyvern-js/blob/master/src/wyvern-ethereum/contracts/exchange/ExchangeCore.sol#L630
        /* Must be opposite-side. */
        assert_eq!(buy.side, 0);
        assert_eq!(sell.side, 1);

        /* Must use same fee method. */
        assert_eq!(sell.fee_method, buy.fee_method);

        /* Must use same payment token. */
        assert_eq!(sell.payment_token, buy.payment_token);

        /* Must match maker/taker addresses. */
        assert!(sell.taker == Address::zero() || sell.taker == buy.maker);
        assert!(buy.taker == Address::zero() || buy.taker == sell.maker);

        /* One must be maker and the other must be taker (no bool XOR in Solidity). */
        assert!(
            (sell.fee_recipient == Address::zero() && buy.fee_recipient != Address::zero())
                || (sell.fee_recipient != Address::zero() && buy.fee_recipient == Address::zero())
        );

        /* Must match target. */
        assert_eq!(sell.target, buy.target);

        /* Must match howToCall. */
        assert_eq!(sell.how_to_call, buy.how_to_call);

        /* Buy-side order must be settleable. */
        // SaleKindInterface.canSettleOrder(buy.listingTime, buy.expirationTime) &&

        /* Sell-side order must be settleable. */
        // SaleKindInterface.canSettleOrder(sell.listingTime, sell.expirationTime)

        Ok(())
    }

    pub async fn atomic_match(
        &self,
        buy: MinimalOrder,
        sell: MinimalOrder,
        is_buyer: bool,
    ) -> Result<ContractCall<M, ()>, ClientError> {
        println!("Atomic match");
        println!("BUY: {:#?}", buy);
        println!("SELL: {:#?}", sell);

        // solidity does these things..

        // check buy hash/sig
        // check sell hash/sig

        // require can match
        self.check_order(&buy, &sell).expect("no match");

        // check target exists...
        // i think this checks that `target` is a contract- i.e has code

        /* Must match calldata after replacement, if specified. */
        if !buy.replacement_pattern.0.is_empty() {
            let replaced: Vec<_> = buy
                .calldata
                .clone()
                .0
                .iter()
                .zip(buy.replacement_pattern.clone().0)
                .map(|(x, y)| x ^ y)
                .collect();
            println!(
                r#"
                calldata was: {:?},
                replacement was: {:?},
                result is: {:?}
            "#,
                hex::encode(buy.calldata.clone().0),
                hex::encode(buy.replacement_pattern.clone().0),
                hex::encode(replaced)
            );

            // ArrayUtils.guardedArrayReplace(buy.calldata, sell.calldata, buy.replacementPattern);
        }

        // if (sell.replacementPattern.length > 0) {
        // ArrayUtils.guardedArrayReplace(sell.calldata, buy.calldata, sell.replacementPattern);
        //   }
        //   require(ArrayUtils.arrayEq(buy.calldata, sell.calldata));

        // make the arguments in the format the contracts expect them
        let addrs = [
            buy.exchange,
            buy.maker,
            buy.taker,
            buy.fee_recipient,
            buy.target,
            buy.static_target,
            buy.payment_token,
            sell.exchange,
            sell.maker,
            sell.taker,
            sell.fee_recipient,
            sell.target,
            sell.static_target,
            sell.payment_token,
        ];
        let uints = [
            buy.maker_relayer_fee,
            buy.taker_relayer_fee,
            buy.maker_protocol_fee,
            buy.taker_protocol_fee,
            buy.base_price,
            buy.extra,
            buy.listing_time,
            buy.expiration_time,
            buy.salt,
            sell.maker_relayer_fee,
            sell.taker_relayer_fee,
            sell.maker_protocol_fee,
            sell.taker_protocol_fee,
            sell.base_price,
            sell.extra,
            sell.listing_time,
            sell.expiration_time,
            sell.salt,
        ];

        // passing it u8 returns an InvalidData error due to ethabi interpreting
        // them wrongly, so we need to convert them to u256
        // to work :shrug:
        let methods = [
            U256::from(buy.fee_method),
            buy.side.into(),
            buy.sale_kind.into(),
            buy.how_to_call.into(),
            sell.fee_method.into(),
            sell.side.into(),
            sell.sale_kind.into(),
            sell.how_to_call.into(),
        ];
        let vs: [U256; 2] = [buy.v.into(), sell.v.into()];

        // TODO: This should be [H256; 5] in Abigen
        let rss_metadata = [buy.r.0, buy.s.0, sell.r.0, sell.s.0, [0; 32]];

        // get the call
        let call = self
            .contracts
            // Abigen error, doesn't generate a correct signature for function with underscore
            // in its name
            .method(
                "atomicMatch_",
                (
                    addrs,
                    uints,
                    methods,
                    buy.calldata,
                    sell.calldata,
                    buy.replacement_pattern,
                    sell.replacement_pattern,
                    buy.static_extradata,
                    sell.static_extradata,
                    vs,
                    rss_metadata,
                ),
            )
            .unwrap()
            .legacy();

        // set the value
        let value = if is_buyer && buy.payment_token.is_zero() {
            buy.base_price
        } else {
            0.into()
        };

        let call = call.value(value);

        // set the gas
        // let gas = call.estimate_gas().await.expect("could not estimate gas");

        // TODO: Why does gas estimation not work?
        let call = call.gas(500_000);

        Ok(call)
    }

    // fn encode_buy(schema: WyvernSchema)
}

#[cfg(test)]
mod tests {
    use std::{
        convert::{TryFrom, TryInto},
        sync::Arc,
        time::Duration,
    };

    use ethers::{
        prelude::{BlockNumber, Http, Lazy, LocalWallet, Signer, SignerMiddleware},
        providers::Provider,
        types::Address,
        utils::parse_units,
    };

    use super::*;
    use crate::{
        api::OpenSeaApiConfig,
        constants::{
            OPENSEA_ADDRESS, OPENSEA_ADDRESS_RINKEBY, OPENSEA_FEE_RECIPIENT_RINKEBY,
            OPENSEA_PROXY_REGISTRY_RINKEBY, OPENSEA_TRANSFER_PROXY_MAINNET,
            OPENSEA_TRANSFER_PROXY_RINKEBY, WETH_ADDRESS_RINKEBY,
        },
        types::{create_maker_order, AssetId, Metadata, SellArgs},
    };

    const RPC_ENDPOINT: &str = "http://localhost:8575";

    pub static COLLECTION_ADDRESS: Lazy<Address> = Lazy::new(|| {
        "0x8e04b806a89550332b9ee8f28cdffb72e60ef606"
            .parse()
            .unwrap()
    });

    pub static WALLET_A: Lazy<LocalWallet> = Lazy::new(|| {
        "57b2de6d5ec9062543df654091f0165b947fefb39e18b206f9ca4d4b6c502fe5"
            .parse()
            .unwrap()
    });

    pub static WALLET_B: Lazy<LocalWallet> = Lazy::new(|| {
        "dc1235467601950f136c9ebde5478dde864851fd058ceed04cea93fae9e9b555"
            .parse()
            .unwrap()
    });

    fn get_provider<S: Signer>(wallet: S) -> Arc<SignerMiddleware<Provider<Http>, S>> {
        let provider = Provider::try_from(RPC_ENDPOINT).unwrap();
        let provider = provider.interval(Duration::from_millis(100));
        let provider = SignerMiddleware::new(provider, wallet);
        Arc::new(provider)
    }

    async fn ensure_approval<M: Middleware>(
        token: &ERC20<M>,
        from: Address,
        to: Address,
        amount: U256,
    ) {
        let approved: U256 = token.allowance(from, to).call().await.unwrap();
        if approved < amount {
            token
                .approve(to, amount - approved)
                .send()
                .await
                .unwrap()
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn can_buy_from_opensea() {
        let taker_wallet = WALLET_A.clone().with_chain_id(4u32);
        let taker_address = taker_wallet.address();
        let taker_provider = get_provider(taker_wallet.clone());

        let id = 7.into();

        let block = taker_provider
            .get_block(BlockNumber::Latest)
            .await
            .unwrap()
            .unwrap();
        let timestamp = block.timestamp.as_u64();

        // set up the args
        let args = BuyArgs {
            token_id: id,
            taker: taker_address,
            token: *COLLECTION_ADDRESS,
            recipient: taker_address,
            timestamp: Some(timestamp - 100),
        };

        // instantiate the client
        let client = Client::new(taker_provider.clone(), OpenSeaApiConfig::with_api_key(""));

        // execute the call
        let call = client.buy(args, 1).await.unwrap()[0].clone();
        let call = call.gas(500_000).gas_price(parse_units(500, 9).unwrap());
        let call = call.from(taker_address.clone());
        call.send().await.unwrap().await.unwrap();

        let nft = NFT::new(*COLLECTION_ADDRESS, taker_provider.clone());
        let owner = nft.owner_of(id).call().await.unwrap();
        assert_eq!(owner, taker_address);
    }

    #[tokio::test]
    async fn can_sell_nft() {
        let wallet_a = WALLET_A.clone().with_chain_id(4u32);
        let provider_a = get_provider(wallet_a.clone());

        let wallet_b = WALLET_B.clone().with_chain_id(4u32);
        let provider_b = get_provider(wallet_b.clone());

        let token_id = U256::from(6u64);
        let nft = NFT::new(*COLLECTION_ADDRESS, provider_a.clone());
        let nft_owner: Address = nft.owner_of(token_id).call().await.unwrap();
        println!("Owner is: {:?}", nft_owner);

        let (maker_wallet, maker_provider, taker_wallet, taker_provider) = match nft_owner {
            a if a == wallet_a.address() => (wallet_a, provider_a, wallet_b, provider_b),
            a if a == wallet_b.address() => (wallet_b, provider_b, wallet_a, provider_a),
            other => {
                panic!("nft owned by {:?}", other)
            }
        };

        let maker_address = maker_wallet.address();
        let taker_address = taker_wallet.address();
        println!("maker is {maker_address:?}, taker is {taker_address:?}");

        // Make sure we have a proxy account..
        let prx =
            OpenseaProxyRegistry::new(*OPENSEA_PROXY_REGISTRY_RINKEBY, maker_provider.clone());
        let mut proxy_address: Address = prx.proxies(maker_address).call().await.unwrap();
        if proxy_address.is_zero() {
            // need to create proxy..
            prx.register_proxy().send().await.unwrap().await.unwrap();
            proxy_address = prx.proxies(maker_address).call().await.unwrap();
            println!("created new proxy");
        };
        println!("proxy address: {:?}", proxy_address);

        // approve transfer to opensea
        let nft = NFT::new(*COLLECTION_ADDRESS, maker_provider.clone());
        let approval: Address = nft.get_approved(token_id).call().await.unwrap();
        println!("currently approved: {:?}", approval);
        if approval != proxy_address {
            nft.approve(proxy_address, token_id)
                .from(maker_address)
                .send()
                .await
                .unwrap()
                .await
                .unwrap();
        };

        println!("seller is {:?}", &maker_address);

        // make a sell order for it...
        let metadata = Metadata {
            asset: AssetId {
                id: token_id.into(),
                address: *COLLECTION_ADDRESS,
            },
            schema: "ERC721".into(),
        };

        let sell = create_maker_order(&maker_address, metadata, maker_wallet, false, None).await;

        let client = Client::new(taker_provider.clone(), OpenSeaApiConfig::with_api_key(""));

        let block = taker_provider
            .get_block(BlockNumber::Latest)
            .await
            .unwrap()
            .unwrap();
        let timestamp = block.timestamp.as_u64();
        let args = BuyArgs {
            taker: taker_address,
            recipient: taker_address,
            token: *COLLECTION_ADDRESS,
            token_id: token_id,
            timestamp: Some(timestamp - 100),
        };
        let buy = sell.match_sell(args);
        let sell = MinimalOrder::from(sell);
        let call = client.atomic_match(buy, sell, true).await.unwrap();
        let call = call.gas_price(parse_units(500, 9).unwrap());
        call.from(taker_address)
            .gas(500_000)
            .send()
            .await
            .unwrap()
            .await
            .unwrap();

        let owner: Address = nft.owner_of(token_id).call().await.unwrap();
        assert_eq!(owner, taker_address);
    }

    #[tokio::test]
    async fn can_sell_nft_for_weth() {
        let wallet_a = WALLET_A.clone().with_chain_id(4u32);
        let provider_a = get_provider(wallet_a.clone());

        let wallet_b = WALLET_B.clone().with_chain_id(4u32);
        let provider_b = get_provider(wallet_b.clone());

        let token_id = U256::from(6u64);
        let nft = NFT::new(*COLLECTION_ADDRESS, provider_a.clone());
        let nft_owner: Address = nft.owner_of(token_id).call().await.unwrap();
        println!("Owner is: {:?}", nft_owner);

        let (maker_wallet, maker_provider, taker_wallet, taker_provider) = match nft_owner {
            a if a == wallet_a.address() => (wallet_a, provider_a, wallet_b, provider_b),
            a if a == wallet_b.address() => (wallet_b, provider_b, wallet_a, provider_a),
            other => {
                panic!("nft owned by {:?}", other)
            }
        };

        let maker_address = maker_wallet.address();
        let taker_address = taker_wallet.address();
        println!("maker is {maker_address:?}, taker is {taker_address:?}");

        // Make sure we have a proxy account..
        let prx =
            OpenseaProxyRegistry::new(*OPENSEA_PROXY_REGISTRY_RINKEBY, maker_provider.clone());
        let mut proxy_address: Address = prx.proxies(maker_address).call().await.unwrap();
        if proxy_address.is_zero() {
            // need to create proxy..
            prx.register_proxy().send().await.unwrap().await.unwrap();
            proxy_address = prx.proxies(maker_address).call().await.unwrap();
            println!("created new proxy");
        };
        println!("proxy address: {:?}", proxy_address);

        // approve transfer to opensea
        let nft = NFT::new(*COLLECTION_ADDRESS, maker_provider.clone());
        let approval: Address = nft.get_approved(token_id).call().await.unwrap();
        println!("currently approved: {:?}", approval);
        if approval != proxy_address {
            nft.approve(proxy_address, token_id)
                .from(maker_address)
                .send()
                .await
                .unwrap()
                .await
                .unwrap();
        };

        println!("seller is {:?}", &maker_address);

        // make a sell order for it...
        let metadata = Metadata {
            asset: AssetId {
                id: token_id.into(),
                address: *COLLECTION_ADDRESS,
            },
            schema: "ERC721".into(),
        };

        let sell = create_maker_order(
            &maker_address,
            metadata,
            maker_wallet,
            false,
            Some(*WETH_ADDRESS_RINKEBY),
        )
        .await;

        let client = Client::new(taker_provider.clone(), OpenSeaApiConfig::with_api_key(""));

        // Make sure we have a proxy account..
        let prx =
            OpenseaProxyRegistry::new(*OPENSEA_PROXY_REGISTRY_RINKEBY, taker_provider.clone());
        let mut proxy_address: Address = prx.proxies(taker_address).call().await.unwrap();
        if proxy_address.is_zero() {
            // need to create proxy..
            prx.register_proxy().send().await.unwrap().await.unwrap();
            proxy_address = prx.proxies(taker_address).call().await.unwrap();
            println!("created new proxy");
        };
        println!("proxy address: {:?}", proxy_address);

        let weth = ERC20::new(*WETH_ADDRESS_RINKEBY, taker_provider.clone());
        ensure_approval(
            &weth,
            taker_address,
            sell.fee_recipient.address,
            sell.base_price,
        )
        .await;
        ensure_approval(&weth, taker_address, proxy_address, sell.base_price).await;

        let block = taker_provider
            .get_block(BlockNumber::Latest)
            .await
            .unwrap()
            .unwrap();
        let timestamp = block.timestamp.as_u64();
        let args = BuyArgs {
            taker: taker_address,
            recipient: taker_address,
            token: *COLLECTION_ADDRESS,
            token_id: token_id,
            timestamp: Some(timestamp - 100),
        };
        let buy = sell.match_sell(args);
        let sell = MinimalOrder::from(sell);
        let call = client.atomic_match(buy, sell, true).await.unwrap();
        let call = call.gas_price(parse_units(500, 9).unwrap());
        let receipt = call
            .from(taker_address)
            .gas(500_000)
            .send()
            .await
            .unwrap()
            .await
            .unwrap();

        println!("tx receipt: {:#?}", receipt);

        let owner: Address = nft.owner_of(token_id).call().await.unwrap();
        assert_eq!(owner, taker_address);
    }

    #[tokio::test]
    async fn can_bid_on_erc721_and_accept_via_api() {
        let wallet_a = WALLET_A.clone().with_chain_id(4u32);
        let provider_a = get_provider(wallet_a.clone());

        let wallet_b = WALLET_B.clone().with_chain_id(4u32);
        let provider_b = get_provider(wallet_b.clone());

        let token_id = U256::from(6u64);
        let nft = NFT::new(*COLLECTION_ADDRESS, provider_a.clone());
        let nft_owner: Address = nft.owner_of(token_id).call().await.unwrap();
        println!("Owner is: {:?}", nft_owner);

        let (maker_wallet, maker_provider, taker_wallet, taker_provider) = match nft_owner {
            a if a == wallet_b.address() => (wallet_a, provider_a, wallet_b, provider_b),
            a if a == wallet_a.address() => (wallet_b, provider_b, wallet_a, provider_a),
            other => {
                panic!("nft owned by {:?}", other)
            }
        };

        let maker_address = maker_wallet.address();
        let taker_address = taker_wallet.address();
        println!("maker is {maker_address:?}, taker is {taker_address:?}");

        let metadata = Metadata {
            asset: AssetId {
                id: token_id,
                address: *COLLECTION_ADDRESS,
            },
            schema: "ERC721".into(),
        };

        let buy = create_maker_order(
            &maker_address,
            metadata,
            maker_wallet,
            true,
            Some(*WETH_ADDRESS_RINKEBY),
        )
        .await;

        // Make sure we have a proxy account..
        let prx =
            OpenseaProxyRegistry::new(*OPENSEA_PROXY_REGISTRY_RINKEBY, maker_provider.clone());
        let mut proxy_address: Address = prx.proxies(maker_address).call().await.unwrap();
        if proxy_address.is_zero() {
            // need to create proxy..
            prx.register_proxy().send().await.unwrap().await.unwrap();
            proxy_address = prx.proxies(maker_address).call().await.unwrap();
            println!("created new proxy");
        };
        println!("proxy address: {:?}", proxy_address);

        // deposit erc20
        let weth = ERC20::new(*WETH_ADDRESS_RINKEBY, maker_provider.clone());
        let balance: U256 = weth.balance_of(maker_address).call().await.unwrap();
        if balance < buy.base_price {
            println!("need to deposit additional weth");
            weth.deposit()
                .value(buy.base_price - balance)
                .send()
                .await
                .unwrap()
                .await
                .unwrap();
        }

        // approve transfer to opensea
        ensure_approval(
            &weth,
            maker_address,
            *OPENSEA_TRANSFER_PROXY_RINKEBY,
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .parse()
                .unwrap(),
        )
        .await;

        // should be able to post to opensea here..
        // println!("buy order: {:#?}", &buy);
        let minimal = MinimalOrder::from(buy.clone());
        let client = Client::new(maker_provider.clone(), OpenSeaApiConfig::with_api_key(""));
        client.api.post_order(minimal).await.unwrap();

        // all done from account A
        let client = Client::new(taker_provider.clone(), OpenSeaApiConfig::with_api_key(""));

        // set up the args
        let req = OrderRequest {
            side: 0,
            token_id: token_id.to_string(),
            contract_address: *COLLECTION_ADDRESS,
            limit: 1,
        };
        let order = client.api.get_order(req).await.unwrap();

        let args = SellArgs {
            taker: taker_address,
            recipient: order.maker.address,
            timestamp: None,
            token: *COLLECTION_ADDRESS,
            token_id: token_id,
        };
        let unsigned_sell = order.match_buy(args);
        let sell = unsigned_sell
            .sign_order(taker_wallet, order.metadata.clone())
            .await;
        let buy = MinimalOrder::from(order.clone());
        let call = client.atomic_match(buy, sell, false).await.unwrap();
        let call = call.gas(500_000).gas_price(parse_units(500, 9).unwrap());
        let call = call.from(taker_address.clone());
        call.send().await.unwrap().await.unwrap();

        // // approve token for sale
        let nft = NFT::new(*COLLECTION_ADDRESS, taker_provider.clone());
        let owner = nft.owner_of(token_id).call().await.unwrap();
        assert_eq!(owner, maker_address);
    }

    #[tokio::test]
    async fn can_accept_bid() {
        let taker_wallet = WALLET_A.clone().with_chain_id(4u32);
        let taker_address = taker_wallet.address();
        let taker_provider = get_provider(taker_wallet.clone());

        let prx =
            OpenseaProxyRegistry::new(*OPENSEA_PROXY_REGISTRY_RINKEBY, taker_provider.clone());
        let mut proxy_address: Address = prx.proxies(taker_address).call().await.unwrap();
        if proxy_address.is_zero() {
            // need to create proxy..
            prx.register_proxy().send().await.unwrap().await.unwrap();
            proxy_address = prx.proxies(taker_address).call().await.unwrap();
            println!("created new proxy");
        };
        println!("taker proxy address: {:?}", proxy_address);

        let id: U256 = 6u64.into();

        let address = "0x8e04b806a89550332b9ee8f28cdffb72e60ef606"
            .parse::<Address>()
            .unwrap();
        let nft = NFT::new(address, taker_provider.clone());

        let client = Client::new(taker_provider.clone(), OpenSeaApiConfig::with_api_key(""));

        let req = OrderRequest {
            side: 0,
            token_id: id.to_string(),
            contract_address: address,
            limit: 1,
        };
        let order = client.api.get_order(req).await.unwrap();
        println!("order: {:#?}", &order);

        let mut proxy_address: Address = prx.proxies(order.maker.address).call().await.unwrap();
        println!("maker proxy address: {:?}", proxy_address);

        // probably we need to pay fees. approve the fee recipient to take fees.. from our proxy
        let weth = ERC20::new(order.payment_token, taker_provider.clone());
        println!("fee recipient: {:?}", order.fee_recipient.address);

        // wtf? what is this address?
        let approval_address: Address = "0x82d102457854c985221249f86659C9d6cf12aA72"
            .parse()
            .unwrap();
        let allowance: U256 = weth
            .allowance(taker_address, approval_address)
            .call()
            .await
            .unwrap();
        if allowance.is_zero() {
            println!("approving..");
            weth.approve(approval_address, order.base_price)
                .send()
                .await
                .unwrap()
                .await
                .unwrap();
        }

        let args = SellArgs {
            taker: taker_address,
            recipient: order.maker.address,
            timestamp: None,
            token: address,
            token_id: id,
        };
        let unsigned_sell = order.match_buy(args);
        let sell = unsigned_sell
            .sign_order(taker_wallet, order.metadata.clone())
            .await;
        let buy = MinimalOrder::from(order.clone());
        let call = client.atomic_match(buy, sell, false).await.unwrap();
        let call = call.gas_price(parse_units(500, 9).unwrap());
        let result = call
            .from(taker_address)
            .gas(300_000)
            .send()
            .await
            .unwrap()
            .await
            .unwrap();

        println!("result: {:#?}", result);
        let owner = nft.owner_of(id).call().await.unwrap();
        assert_eq!(owner, order.maker.address);
        panic!("doine");
        // println!("buy order: {:#?}", &buy);
        // client.api.post_order(buy.clone()).await.unwrap();

        // Make sure we have a proxy account..
        // let prx = OpenseaProxyRegistry::new(*OPENSEA_PROXY_REGISTRY_RINKEBY, provider.clone());
        // let mut proxy_address: Address = prx.proxies(maker).call().await.unwrap();
        // if proxy_address.is_zero() {
        //     // need to create proxy..
        //     prx.register_proxy().send().await.unwrap().await.unwrap();
        //     proxy_address = prx.proxies(maker).call().await.unwrap();
        //     println!("created new proxy");
        // };
        // println!("proxy address: {:?}", proxy_address);

        // // need to use erc20 for bids
        // let weth = ERC20::new(*WETH_ADDRESS_RINKEBY, provider.clone());

        // // deposit erc20
        // let balance: U256 = weth.balance_of(maker).call().await.unwrap();
        // if balance < buy.base_price {
        //     println!("need to deposit additional weth");
        //     weth.deposit()
        //         .value(buy.base_price - balance)
        //         .send()
        //         .await
        //         .unwrap()
        //         .await
        //         .unwrap();
        // }

        // // approve erc20
        // let approved: U256 = weth.allowance(maker, proxy_address).call().await.unwrap();
        // if approved < buy.base_price {
        //     println!("need additional approval");
        //     weth.approve(proxy_address, buy.base_price - approved)
        //         .send()
        //         .await
        //         .unwrap()
        //         .await
        //         .unwrap();
        // };

        // // all done from account A

        // let wallet: LocalWallet =
        //     "dc1235467601950f136c9ebde5478dde864851fd058ceed04cea93fae9e9b555"
        //         .parse()
        //         .unwrap();
        // let wallet = wallet.with_chain_id(4u32);
        // let taker = wallet.address();
        // println!("accepting address: {:?}", wallet.address());

        // let provider = Provider::try_from("http://localhost:8575").unwrap();
        // let provider = provider.interval(Duration::from_millis(100));
        // let provider = SignerMiddleware::new(provider, wallet.clone());
        // let provider = Arc::new(provider);
        // let client = Client::new(provider.clone(), OpenSeaApiConfig::with_api_key(""));

        // let prx = OpenseaProxyRegistry::new(*OPENSEA_PROXY_REGISTRY_RINKEBY, provider.clone());
        // let mut proxy_address: Address = prx.proxies(wallet.address()).call().await.unwrap();
        // if proxy_address.is_zero() {
        //     // need to create proxy..
        //     prx.register_proxy().send().await.unwrap().await.unwrap();
        //     proxy_address = prx.proxies(wallet.address()).call().await.unwrap();
        //     println!("created new proxy");
        // };
        // println!("proxy address: {:?}", proxy_address);

        // // approve token for sale
        // let nft = NFT::new(address, provider.clone());
        // if !nft
        //     .is_approved_for_all(wallet.address(), proxy_address)
        //     .call()
        //     .await
        //     .unwrap()
        // {
        //     println!("dont have approval, setting approve for all");
        //     nft.set_approval_for_all(proxy_address, true)
        //         .send()
        //         .await
        //         .unwrap()
        //         .await
        //         .unwrap();
        // }

        // let block = provider
        //     .get_block(BlockNumber::Latest)
        //     .await
        //     .unwrap()
        //     .unwrap();
        // let timestamp = block.timestamp.as_u64();
        // let args = SellArgs {
        //     taker: wallet.address(),
        //     recipient: maker,
        //     token: address,
        //     token_id: id,
        //     timestamp: Some(timestamp - 100),
        // };
        // let sell = buy.match_buy(args);
        // let sell = sell.sign_order(wallet).await;
        // let buy = MinimalOrder::from(buy);
        // let call = client.atomic_match(buy, sell, false).await.unwrap();
        // let call = call.gas_price(parse_units(500, 9).unwrap());
        // let result = call
        //     .from(taker)
        //     .gas(300_000)
        //     .send()
        //     .await
        //     .unwrap()
        //     .await
        //     .unwrap();

        // let owner = nft.owner_of(id).call().await.unwrap();
        // assert_eq!(owner, maker);
        // panic!("done")
    }

    #[tokio::test]
    // #[ignore]
    async fn can_buy_an_erc1155() {
        let provider = Provider::try_from("http://localhost:18545").unwrap();
        let provider = Arc::new(provider);

        let accounts = provider.get_accounts().await.unwrap();

        let taker = accounts[0].clone();

        let address = "0x47e22659d9ae152975e6cbfa2eed5dc8b75ac545"
            .parse::<Address>()
            .unwrap();
        let nft = NFT::new(address, provider.clone());
        let token_id = 1.into();

        let block = provider
            .get_block(BlockNumber::Latest)
            .await
            .unwrap()
            .unwrap();
        let timestamp = block.timestamp.as_u64();

        // set up the args
        let args = BuyArgs {
            token_id,
            taker,
            token: address,
            recipient: taker,
            timestamp: Some(timestamp - 100),
        };

        // instantiate the client
        let client = Client::new(provider.clone(), OpenSeaApiConfig::with_api_key(""));

        // execute the call
        let call = client.buy(args, 1).await.unwrap()[0].clone();
        let call = call.gas_price(parse_units(100, 9).unwrap());
        let sent = call.send().await.unwrap();

        // wait for it to be confirmed
        let receipt = sent.await.unwrap();
        dbg!(receipt);
        // check the owner matches
        let num = nft.balance_of(taker, token_id).call().await.unwrap();
        assert_eq!(num, 1.into());
    }
}
