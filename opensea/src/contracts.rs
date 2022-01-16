use ethers::contract::abigen;

abigen!(
    OpenSea,
    r#"[
        function transferFrom(address from, address to, uint256 tokenId) public returns (bool)
        function safeTransferFrom(address,address,uint256,uint256,bytes) public returns (bool)
        function atomicMatch_(address[14] addrs,uint[18] uints, uint8[8] feeMethodsSidesKindsHowToCalls, bytes calldataBuy, bytes calldataSell, bytes replacementPatternBuy, bytes replacementPatternSell, bytes staticExtradataBuy, bytes staticExtradataSell, uint8[2] vs, bytes32[5] rssMetadata) public payable"
    ]"#,
    event_derives(serde::Deserialize, serde::Serialize)
);

abigen!(OpenseaProxyRegistry, "proxy_abi.json",);

abigen!(ERC20, "erc20_abi.json",);

abigen!(
    NFT,
    r#"[
        function ownerOf(uint256 tokenId) public view override returns (address)
        function balanceOf(address,uint256) view returns (uint256)
        function approve(address to, uint256 tokenId) public virtual override
        function setApprovalForAll(address to, bool approved) public
        function isApprovedForAll(address owner, address operator) view returns (bool)
        function getApproved(uint256 tokenId) view returns (address)
    ]"#
);
