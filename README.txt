# solidity-nft-workshops

* references
    * https://www.linkedin.com/pulse/what-token-burning-how-does-work-azhar-siddiqui
    * https://medium.com/cryptronics/ethereum-smart-contract-security-73b0ede73fa8
    * https://medium.com/immunefi/the-ultimate-guide-to-reentrancy-19526f105ac
    * https://medium.com/neptune-mutual/understanding-signature-replay-attack-cbb70a7f46d8
    * https://slowmist.medium.com/intro-to-smart-contract-security-audit-signature-replay-b71c23910629
    * https://ethereum.stackexchange.com/questions/26/what-is-a-replay-attack
    * https://mirror.xyz/0xbuidlerdao.eth/lOE5VN-BHI0olGOXe27F0auviIuoSlnou_9t3XRJseY
    * https://medium.com/what-is-infura/what-is-infura-59dbdd778455
    * https://ethereum.stackexchange.com/questions/6897/what-is-the-difference-between-truffle-and-remix
    * https://stackoverflow.com/questions/74164255/x19ethereum-signed-message-n32-prefix-meaning
    * https://ethereum.stackexchange.com/questions/128552/why-would-you-use-a-signed-message-to-verify-the-sender
    * https://medium.com/mycrypto/the-magic-of-digital-signatures-on-ethereum-98fe184dc9c7
    * https://medium.com/@kaishinaw/signing-and-verifying-ethereum-messages-f5acd41ca1a8
    * https://github.com/ethers-io/ethers.js/issues/555
    * https://medium.com/@codetractio/walkthrough-of-an-ethereum-improvement-proposal-eip-6fda3966d171
    * https://medium.com/@moplabs/eip-155-with-mopai-75b322962d1b
    * https://medium.com/coinmonks/eip712-a-full-stack-example-e12185b03d54
    * https://medium.com/coinmonks/ethereum-signatures-for-hackers-and-auditors-101-4da766cd6344
    * https://blog.hook.xyz/validate-eip-712/
    * https://ethereum.stackexchange.com/questions/125128/what-is-domain-separator-in-eip712
    * https://kristaps.me/blog/solidity-eip-712-sign-ethers-js/
    * https://dev.to/fassko/what-are-meta-transactions-the-eip-712-standard-and-how-to-sign-a-message-with-metamask-4mil
    * https://medium.com/metamask/eip712-is-coming-what-to-expect-and-how-to-use-it-bb92fd1a7a26

* token burning
    * It is typically performed by the development team which can also buy back tokens and burn them
* https://example.com/nft/1
    ```
    {
      "name": "One Ring to Rule Them All",
      "description": "The One Ring, forged in the fires of Mount Doom, grants immense power to its bearer.",
      "image": "https://example.com/one_ring.jpg",
      "attributes": [
        {
          "trait_type": "Type",
          "value": "Artifact"
        },
        {
          "trait_type": "Rarity",
          "value": "Legendary"
        },
        {
          "trait_type": "Power",
          "value": "Dominion over all other rings"
        },
        {
          "trait_type": "Owner",
          "value": "Sauron"
        }
      ],
      "external_url": "https://example.com/one_ring",
      "franchise": "The Lord of the Rings",
      "lore": "Forged by the Dark Lord Sauron to control the other Rings of Power, the One Ring is a malevolent artifact of great evil."
    }

    ```

# best practices
    * don't use plain secret on-chain
        * problem: front-running attacks
            * all the transaction data is open and can be seen by others
                * even data of pending transaction can be seen by others
            * example: domain name registration
                * user is registering a unique value
                * attacker watch for the transactions on that contract
                    * send the high gas-price transaction to front run the user's transaction
        * solution: commit-and-reveal scheme
            * hash of the original secret is submitted to the blockchain
            * steps
                1. all parties submit their secret hash
                1. all parties reveal their choice by submitting salt (that was used to generate the secret hash)
    * don't use `tx.origin` for authorization
        * problem: intercepting transaction
            1. we have `Vault` contract, that has function `withdraw()` using `tx.origin` for authorization
            1. attacker deploys AttackerContract
            1. attacker ask the original owner of the Vault contract to send some ether to the AttackerContract
            1. AttackerContract calls the Vault.withdraw() function
        * solution: always use `msg.sender`
    * avoid dependency on untrusted external calls
        * problems
            * if the target contract is killed via selfdestruct, the external call to the function will always fail
            * reentrancy attack
                * re-enter origin contract before the state changes are finalized
            * unpredictable gas costs
    * reentrancy attacks
        * problem: re-enter origin contract before the state changes are finalized
            * example
                ```
                function withdraw(uint amount) public {
                     require(balanceOf[msg.sender] >= amount);
                     msg.sender.call{value: amount}(""); // invokes fallback function in caller, than invokes withdraw again
                     balanceOf[msg.sender] -= amount;
                     Withdrawal(msg.sender, amount);
                }
                ```
        * solution: checks-effects-interactions (CEI) pattern
            * example
                ```
                function withdraw(uint amount) public {
                    // Checks phase
                    require(balanceOf[msg.sender] >= amount, "Insufficient balance");

                    // Effects phase
                    balanceOf[msg.sender] -= amount;

                    // Interactions phase
                    (bool success, ) = msg.sender.call{value: amount}("");
                    require(success, "Transfer failed");

                    // Emit event after successful interaction
                    emit Withdrawal(msg.sender, amount);
                }
                ```
    * replay attack
        * problem
            * cross-chain signature replay
                * most typical situation is when the contract does not include a chainId when generating a signature
                * transaction signed by a key, that is valid on one Ethereum network/chain, is valid for all Ethereum chains
                    * Bitcoin: addresses in testnet use a different prefix from addresses in mainnet
                        * keys are different
                * example
                    ```
                    function deposit() public payable { // reply transaction from testnet on the mainnet
                        balances[msg.sender] += msg.value;
                    }
                    ```
            * same-chain signature replay
                * most typical situation is when the contract does not include a Nonce when generating a signature
                * example
                    ```
                    function deposit() public payable { // attacker rebroadcasts the same transaction with the same parameters
                        balances[msg.sender] += msg.value;
                    }
                    ```
        * solution
            * EIP155
                * called "simple replay attack protection"
                * defines the chainID field in Ethereum transactions to prevent replay attacks
                * before EIP155
                    * there are 6 inputs to an Ethereum transaction
                        * nonce, gasPrice, gasLimit, to, value, data
                    * transaction is not chain specific
                        * same addresses in different networks => can lead to unintended transactions
                * user should sign the data along with a unique nonce value each time
                    * example
                        ```
                        mapping(address => uint256) public nonces;

                        function deposit(uint256 nonce) public payable {
                            require(nonce > nonces[msg.sender], "Invalid nonce");
                            nonces[msg.sender] = nonce;
                            balances[msg.sender] += msg.value;
                        }
                        ```
                * every transaction signature should also encapsulate a unique identifier for the specific network
            * EIP191
                * called "signature data standard"
                * introduces a prefix to the data that is being signed
                    * example
                        ```
                        "\x19Ethereum Signed Message:\n32"
                        ```
                        * byte `0x19` standardized because an already existing implementation (in the Go Ethereum client software)
                        was using it before the standard was finalized
                        * last number `32` is the byte length of the message (excluding the prefix)
                * reason for prefixing is so that a cleverly designed message cannot possibly be a valid transaction
                    * allowing signing raw messages, without a prefix, enables an app to steal all ether, tokens and assets
                        * purpose is entirely to invalidate any payload as a valid RLP encoded transaction
                        * MetaMask does not permit you to perform this operation
                            * it will always force prefixing a signed message even when the message is a hash
                    * when you create a transaction: unsigned transaction -> hash it -> sign it
                    * when you create a message: unsigned message -> prefix it -> hash it -> sign it
                    * example
                        ```
                        let unsignedTransaction = "0xe980850218711a00825208948ba1f109551bd432803012645ac136ddd64dba72880de0b6b3a764000080";
                        ```
                        decoded with https://flightwallet.github.io/decode-eth-tx/
                        ```
                        {
                          "nonce": 0,
                          "gasPrice": 9000000000,
                          "gasLimit": 21000,
                          "to": "0x8ba1f109551bd432803012645ac136ddd64dba72",
                          "value": 1000000000000000000,
                          "data": ""
                        }
                        ```
                        * if attacked gives you this hash and you sign it => it is now a valid signed transaction which will send 1 ether to attacker
                        * string that begins with "\x19Ethereum Signed Message:" is not a valid transaction
                            * it is safe to sign it
                * eliminates the risk of replay attacks on other EVM platforms
                    * if there were no platform-specific prefixes, the resulting signature would be the same for all platforms
                * use case
                    * smart contract needs to verify a signed message
                    * external systems need to interact with Ethereum transactions in a standardized way
                * list of chain ids: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md?ref=blog.hook.xyz#list-of-chain-ids
            * EIP712
                * is a more advanced and secure method of signing a transaction
                * provides a way to hash and sign typed structs rather than just strings
                    * uses the keccak256 hashing algorithm
                * requires TypedData (JSON object input)
                    * example
                        ```
                        typedData := apitypes.TypedData{
                        	Types:       types,
                        	PrimaryType: "ERC721Order",
                        	Domain:      domain,
                        	Message:     message,
                        }
                        ```
                    * includes the following properties
                        * types
                            * used to define the structs that will be used in the message and specify their types
                            * is a mapping of string to a Type array
                                * example
                                    ```
                                    types := apitypes.Types{
                                    	"EIP712Domain": {
                                    		{Name: "name", Type: "string"},
                                    		{Name: "version", Type: "string"},
                                    		{Name: "chainId", Type: "uint256"},
                                    		{Name: "verifyingContract", Type: "address"},
                                    	},
                                    	"ERC721Order": {
                                    		{Name: "direction", Type: "uint8"},
                                    		...
                                    	},
                                    	"Fee": { // custom types
                                        	{Name: "recipient", Type: "address"},
                                        	{Name: "amount", Type: "uint256"},
                                        	{Name: "feeData", Type: "bytes"},
                                        },
                                    ```
                        * domain
                            * information specific to the protocol contract that the dapp used when asking for a signature
                            * designed to include bits of DApp unique information
                                * name
                                    * human-readable string that represents the name of the domai
                                    * often used to identify the dApp or smart contract associated with the message
                                * version
                                    * string representing the version of the domain
                                    * can be useful for distinguishing between different versions of the same dApp or smart contract
                                * chainId
                                    * wallet providers should prevent signing if it does not match the network it is currently connected to
                                    * it is crucial that chainId is verified on-chain
                                        * contracts have no way to find out which chain ID they are on
                                            * developers must hardcode chainId into their contracts and take extra care to make sure that it corresponds to the network they deploy on
                                * verifyingContract
                                    * address of the smart contract that will verify the signed message
                            * domain separator
                                * information from the domain also needs to be hashed and used as a domain separator
                                * purpose is to disambiguate between two dapps with identical structures
                                    * in order to avoid generating the same signatures for both
                                    * example
                                        * two DApps come up with an identical structure like Transfer(address from,address to,uint256 amount)
                                        * with domain separator the dApp developers are guaranteed that there can be no signature collision
                        * primaryType
                            * string that represents the outermost type of the message object
                        * message
                            * contains the order element names as strings mapped to their values
                            * example
                                ```
                                {
                                    amount: 100,
                                    token: “0x….”,
                                    id: 15,
                                    bidder: {
                                        userId: 323,
                                        wallet: “0x….”
                                    }
                                }
                                ```
                                can be split into two data structures
                                ```
                                Bid: {
                                    amount: uint256,
                                    bidder: Identity
                                }
                                Identity: {
                                    userId: uint256,
                                    wallet: address
                                }
                                ```
                        * example
                            ```
                            domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
                            typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.M
                            rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
                            hashBytes := keccak256(rawData)
                            hash := common.BytesToHash(hashBytes)
                            ```
                * standard for secure off-chain signature verification on the Ethereum blockchain
                * signature verification
                    * process of checking that the address of the signer is equal to the address that you derive from the signature
                        ![Alt Text](img/verifying_signature.png)
                    * ecrecover
                        * is vulnerable
                            * it interprets v values of both 27 and 28 as equivalent
                                * it only checks if v is greater than or equal to 27
                                * signatures produced with both v = 27 and v = 28 will yield the same public key
                            * use: OpenZeppelin’s ECDSA library
                        * used to derive the address of a sender based on the digital signature
                        * needs assembly
                    * example
                        * replicate this formatting/hash function
                        ```
                        struct Identity {
                            uint256 userId;
                            address wallet;
                        }
                        struct Bid {
                            uint256 amount;
                            Identity bidder;
                        }

                        string private constant IDENTITY_TYPE = "Identity(uint256 userId,address wallet)";
                        string private constant BID_TYPE = "Bid(uint256 amount,Identity bidder)Identity(uint256 userId,address wallet)";

                        uint256 constant chainId = 1;
                        address constant verifyingContract = 0x1C56346CD2A2Bf3202F771f50d3D14a367B48070;
                        bytes32 constant salt = 0xf2d857f4a3edcb9b78b4d503bfe733db1e3f6cdc2b7971ee739626c97e86a558;
                        string private constant EIP712_DOMAIN = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)";
                        bytes32 private constant DOMAIN_SEPARATOR = keccak256(abi.encode(
                            EIP712_DOMAIN_TYPEHASH,
                            keccak256("My amazing dApp"),
                            keccak256("2"),
                            chainId,
                            verifyingContract,
                        ));

                        function hashIdentity(Identity identity) private pure returns (bytes32) {
                            return keccak256(abi.encode(
                                IDENTITY_TYPEHASH,
                                identity.userId,
                                identity.wallet
                            ));
                        }
                        function hashBid(Bid memory bid) private pure returns (bytes32){
                            return keccak256(abi.encodePacked(
                                "\\x19\\x01",
                               DOMAIN_SEPARATOR,
                               keccak256(abi.encode(
                                    BID_TYPEHASH,
                                    bid.amount,
                                    hashIdentity(bid.bidder)
                                ))
                            ));

                        function verify(address signer, Bid memory bid, sigR, sigS, sigV) public pure returns (bool) {
                            return signer == ecrecover(hashBid(bid), sigV, sigR, sigS);
                        }
                        ```
                * wallets like Metamask can display the message in a more user-friendly manner
                    * the signer can actually check the data before signing
                        * display in a human-readable way that users can understand and review before signing
                    * example
                        ![Alt Text](img/eip721_metamask.png)
                * before EIP712
                    * it was difficult for users to verify the data they were asked to sign
                    * wallet signing interfaces would display a hashed message string
                        * the signer would have to assume that hash matched the message they thought they were signing
                * use case
                    * meta-transactions
                        * relayer pays the gas fees on behalf of the user
                            * relayer = service responsible for submitting transactions on behalf of users
                        * users sign a request (off-chain) for a specific action they want to perform on the blockchain
                            * includes information like the target contract, function to call, and any required parameters
    * manipulating contract balance
        * problem: ether can be sent forcibly to a contract
            * if contract has some decision logic using `address(this).balance` - attacked can influence it
            * example
                ```
                selfdestruct(addressOfAttackedContract)
                ```
        * solution: there is no possible way to prevent forceful ether sending from happening

# tools
* infura
    * is a kind of node storage (cluster)
    * set of tools that provides its services for integrating your application with the Ethereum network
    * you do not need to run your local blockchain for the mainnet and testnets
        * example: MetaMask internally uses an Infura link to connect to the Ethereum blockchain
    * also host the Inter Planetary File System (IPFS) nodes and the IPFS public gateway
* Truffle
    * development environment/framework for smart contracts
    * can be included in projects as a build dependency
* Remix
    * IDE in the browser
* linters
    * analyze the given source code and report programming errors, bugs, and stylistic errors
    * two commonly used linter tools available
        * solhint - provides security and style guideline-specific validations
        * ethlint -  similar to solhint
* solidity-coverage
    * ode coverage tool specifically designed for Solidity smart contracts

# tokens
* erc20
    * “with the ERC20 token standard APIs, it is not possible to get notifications of another action being triggered when an ERC20 standard-specific token is received at the deployed contract”
      * “The token transfers are received at the contract silently.”
      * “The ERC223 standard provides the methods that will be called once the tokens are transferred”
    * “In the OpenZeppelin's ERC20 standard implementation, the transfer() and transferFrom() functions also do not have a check for the contract address itself, such as require(to != address(this)). There is a reasoning behind this—to reduce the gas cost of the transaction, as there would be millions of transactions performed using these functions.”
      * “if the tokens are transferred to the contract address itself, those tokens will be locked forever because the contract code does not have a way to take the tokens out of the contract.”
      * “It is not recommended to change the ERC20 implementation and add the contract address check in it.”
      * “However, the functions related to reclaiming tokens can be used in your ERC20 implementation”
      * “This would enable the reclaiming of your contract-specific tokens, as well as other ERC20-specific tokens that were mistakenly sent to the contract”
    * “The implementation of the approve() function that we looked at in the previous section is prone to front-running attacks.”
      * “An attacker who initiates a transaction which is to be executed before a specific pending transaction that could benefit an attacker financially is called a front-running attack.”
        * “On the Ethereum blockchain, the transaction gets executed based on the GasPrice someone is offering to process their transaction.”
        * “anyone can read the transactions that are still pending and waiting to be executed in the transaction pool since Ethereum is a public blockchain”
        * “An attacker would observe the transactions that are still pending in the transaction pool and trigger some transaction that could benefit them.”
        * “Originally, Alice wanted Bob to get 1,500 tokens only. However, using the front-running attack, Bob ended up getting, in total, 2,500 tokens.”
          * “For example, after calling the approve() function once, if you want to change it without being attacked using front-running, you can use the increaseApproval() or decreaseApproval() functions.”
        * “To prevent front-running attacks, there are some techniques we can follow.”
          * “You can use the following implementation of the approve() function, which ensures that, before updating the value, it should be set to zero”
            * “require(_value == 0 || allowed[msg.sender][_spender] == 0);”
    * “To transfer the tokens using the transferFrom() function, approver must have called the approve() function prior.”
    * “if you are calling the transferFrom() function from within a Solidity contract, it is recommended to enclose the call with require() to ensure that the token transfer executed successfully and, in case of any transfer failure, the transaction should revert.”
      * “require(ERC20.transferFrom(from, to, value));”
    * “There are some advanced functions that were recently added in the ERC20 token implementations.”
      * “However, these functions are not part of the ERC20 standard APIs”
      * “These functions are just added to improve usage and reduce security issues and attacks”
      * i“n the new OpenZeppelin implementation of ERC20 contracts, there are more functions such as _mint(), _burn(), and _burnFrom() that were also added”
* erc721
    * “ERC721 is a Non-Fungible Token (NFT) standard”
      * “This standard is used in many cases where you want to transfer a whole item that cannot be broken into multiple parts, for example, a house deed or collectible cards”
      * “As you can see in the code, the ERC721 interface also inherits from the ERC165 standard.”
      * “The ERC165 standard is known as the Standard Interface Detection, using which we can publish and detect all interfaces a smart contract implements”
      * In the OpenZeppelin implementation of the ERC721 standard, there are two approval mechanisms: tokenApprovals and operatorApprovals
        * tokenApprovals:
          * mapping(uint256 => address) internal _tokenApprovals;
          * This is a mapping from a token ID to an approved address.
          * It allows a specific address to transfer the ownership of a specific token.
          * It is used for one-time approvals and is cleared after the transfer is completed.
        * operatorApprovals
          * mapping(address => mapping(address => bool)) internal _operatorApprovals;
          * This is a mapping from an owner address to an operator address to a boolean value.
          * It allows an operator to manage (transfer or perform other operations) any tokens owned by the approved owner.
          * This approval is persistent until explicitly revoked.
      * “The transferFrom() function is a public function, used to transfer the given tokenId from the owner's account to the receiver's account. For this function to work, the approval must have been given previously by the owner to the address of the caller of this function.
        * “require(_isApprovedOrOwner(msg.sender, tokenId));”
      * “The safeTransferFrom() function is a public function that is used to safely transfer the NFT from the owner's account to the recipient account.”
        * “safely transfer means that, when a recipient is a contract, you need to ensure that the recipient contract has callbacks registered to let the receiver contract get a notification when ERC721 token transfer is successful”
        * “require(_checkOnERC721Received(from, to, tokenId, _data))”
        * “it makes a call to the _checkOnERC721Received() internal function, which further calls the “callback functions (the onERC721Received() function on the contract receiving the token) in case the recipient of the NFT is a contract (not an Externally Owned Account (EOA)).”
        * “You can pass on the function bytes data into the safeTransferFrom() function in the _data argument”
          * “When this _data parameter is not empty, the further function call will be initiated from the receiver's onERC721Received() function”
      * “contract ABC is ERC721, ERC721Enumerable, ERC721Metadata”
* erc1155

* “ The following is an example of enclosing a token transfer call and an approve call within the require() function:”
  * “require(ERC20(tokenAddress).transferFrom(from, to, value));”
  * “OpenZeppelin provides the SafeERC20.sol contract to ensure the safety of these calls; it is helpful to protect the contract from unintended behavior.”
* “ReentrancyGuard: Using the nonReentrant modifier in the buyTokens() function to prevent reentrancy attacks.
* “By using the WhitelistCrowdsale.sol contract, you can allow ether to be received from known/whitelisted addresses; other addresses cannot send ether to the contract”
* “Let's look at where these contracts can be used:
  * validation/CappedCrowdsale.sol: A crowdsale with an upper limit for the total wei or ether contribution also known as hard-cap
  * validation/IndividuallyCappedCrowdsale.sol: A crowdsale with individually capped upper limit of wei investments
  * validation/PausableCrowdsale.sol: Allows investment only when it isn't paused by PauserRole
  * validation/TimedCrowdsale.sol: A crowdsale that opens and accept ether for a specified duration of time
  * distribution/FinalizableCrowdsale.sol: Allows a special action to be triggered when crowdsale is over
  * distribution/PostDeliveryCrowdsale.sol: A crowdsale that allows its investors to withdraw their tokens only after it finishes
  * emission/AllowanceCrowdsale.sol: A crowdsale in which another wallet contains tokens and allowance is provided to the crowdsale contract so that it can deliver the tokens to the investors
  * emission/MintedCrowdsale.sol: A crowdsale in which new tokens are minted only when investors send ether to the contract
  * price/IncreasingPriceCrowdsale.sol: A crowdsale that increases the rate of the token linearly according to the time”
* “When all of the tokens that have been created on the Ethereum blockchain follow the same standard APIs, it becomes easy for different web and mobile cryptocurrency wallets to support these tokens”
* “The cryptocurrency exchanges support trading of tokens on their exchange”
  * “If all of the tokens support this ERC20 standard, it would be easy for these exchanges to integrate and it would support trading.”
  * “Apart from the cryptocurrency wallets and exchanges, it is also easy for a decentralized exchange to support these standard tokens as they would have to call the ERC20 standard APIs from their smart contracts”
    * “For example, EtherDelta, IDEX, and KyberNetwork are some decentralized exchanges built on top of Ethereum blockchain and they support trading of ERC20 tokens.”
* “The ERC20 standard only defines the interface APIs—the implementation should be written according to your needs”
  * “The most updated and best place to look for the ERC20 implementation is the OpenZeppelin library of Solidity smart contracts”
* “allowed is a nested mapping of two Solidity mapping data types. In the ERC20 standard specification, it is possible for a token holder, X, to assign some allowances to another account, Y, so that Y is allowed to take the approved number of tokens from the token balance of X”
* “The developers must know that there are two types of transfer() functions.”
  * “One is used on the address data types to transfer the ether to that address from the contract”
    * “address(toAddress).transfer(amount);”
  * “The second type is the function defined by the ERC20 standard.”
    * “ERC20(TKNContractAddress).transfer(toAddress, amount);”
* “Coin: A native digital asset or cryptocurrency of a blockchain is called a coin. For example, the bitcoin blockchain has its native cryptocurrency asset, bitcoin (symbol: BTC). The Ethereum blockchain has its native cryptocurrency asset, ether (symbol: ETH), which is required in the blockchain to perform any transaction.”
* “Token: A digital asset or cryptocurrency that is built on top of an existing blockchain is called a token. For example, Maker (symbol: MKR) and Augur (symbol: REP) are ERC20-compliant tokens and are built on the Ethereum blockchain using Solidity smart contracts.”
* “There are two types of exchanges:”
  * “Centralized Exchange: On a centralized exchange, you have to send your cryptocurrency coin or token to the exchange's account. Then, they allow you to trade on their platform.”
    * “As the coins and tokens are held on an exchange's account, there might be a trust issue.”
    * “It is also possible that if the exchange's account is hacked, you will lose your cryptocurrencies”
    * “Binance and Bitfinex are some examples of centralized exchanges”
  * “Decentralized Exchange: On a decentralized exchange, you do not have to send your cryptocurrency coin or token to exchange's account.”
    * y“our coins are kept in your wallet only.”
    * “Instead, you directly trade via exchange platform; coins aren't even kept on the exchange platform”
    * “KyberNetwork, IDEX, and EtherDelta are some of the decentralized exchanges that are available for P2P trading.”
* “Ethereum has its own native currency, ether, which is not ERC20-compliant.”
* https://nfting.medium.com/the-history-of-cryptokitties-ethereums-first-official-gaming-application-499729e50794
* https://betterprogramming.pub/cryptokitties-smart-contract-breakdown-2c3c250d33f6
* https://spectrum.ieee.org/cryptokitties































# design patterns
    * security
        * pull-over-push (withdrawal pattern)
            * example of the problem
                ```
                for(uint i = 0; i < users.length; i++) { users[i].transfer(amount); };”
                ```
                * if some address is a contract it may have continually failing fallback function
                    * leads to whole transaction failure each time
            * solution: user should be able to claim their dividend from the contract
            * use cases
                * send ether/token to multiple addresses
                * avoid paying transaction fees (push transaction)
                    * transaction initiator has to pay the transaction fee
                    * users pay transaction fees (pull transaction)
        * access restriction
            * restricts unauthorized function calls
            * based on roles
            * use modifiers to check for the access rights
        * emergency stop
            * ability to pause the contract functions in unwanted situations
            * use cases
                * contract to be handled differently in case of any emergency situations
    * creational patterns
        * factory
            * create a new child contract from a parent contract
            * https://eips.ethereum.org/EIPS/eip-1167
            * example
                * master contract can create a new child contract called Loan
                    * Loan contract has logic to handle contract terms and conditions along with the funds as well
            * use case
                * new contract is required for each request to be processed
                * keep the funds separate in a different contract
    * behavioral patterns
        * state machine
            * allows a contract to transition from different states
            * enables certain functions to be executed in each state
            * use cases
                * contract needs to have different set of functions based on the state
        * iterable map pattern
            * example
                ```
                mapping(uint256 => uint256) private data;
                uint256[] private keys;

                function removeValue(uint256 key) external {
                    require(data[key] != 0, "Key does not exist");
                    for (uint256 i = 0; i < keys.length; i++) {
                        if (keys[i] == key) {
                            // Swap the element to be removed with the last element
                            keys[i] = keys[keys.length - 1];
                            // Shorten the keys array by one
                            keys.pop();
                            break;
                        }
                    }
                    delete data[key];
                }
                ```
            * allows to iterate over the mapping entries
            * iteration over the mapping entries should not cause an out-of-gas exception
            * iteration should be used only in the view function
            * does not support removal of elements
            * use cases
                * need to filter some data out of the mapping
        * whitelisted addresses
            * maintain a curated list of addresses by the owner
            * use cases
                * whitelisted address allowed/disallowed to perform a certain task
    * gas-optimization
        * worth to check: https://github.com/mtumilowicz/ethereum-gas-workshop
        * keccak256 for equality check
            * example: string equality
            * use case
                * gas-optimized solution for equality
        * variable packing
            * minimize slots used by storage
            * each storage slot is 32 bytes
            * use case
                * gas-optimized solution for storage
    * life cycle
        * “Once a contract is destroyed, it cannot be recreated on the same address. ”
        * mortal pattern allows a contract to be destroyed from the Ethereum blockchain.”
            * “The mortal pattern should be used in the following cases, when:
                * You do not want a contract to be present on the blockchain once its job is finished
                * You want the ether held on the contract to be sent to the owner and the contract is not required further
                * You do not need the contract state data after the contract reaches a specific state”
        * auto deprecate
            * allows time-based access to certain function calls
            * example (using chainLink oracle)
                ```
                modifier onlyPremium() {
                    require(subscriptionExpiry[msg.sender] >= getCurrentTime(), "Must be a premium member");
                    _;
                }

                function getCurrentTime() internal returns (uint256) {
                    Chainlink.Request memory req = buildChainlinkRequest(jobId, address(this), this.fulfill.selector);
                    req.add("get", "https://chain.link/v1/time");
                    req.add("path", "now");

                    return sendChainlinkRequestTo(oracle, req, fee);
                }
                ```
            * use cases
                * allow/restrict a function call for a specified duration of time
                * auto-expired contract
                * periodic paid service-based model
                * existing user can purchase a premium status for a limited duration