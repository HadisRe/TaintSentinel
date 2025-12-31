#  Bad Randomness Definition
Bad randomness vulnerability affects smart contracts that require randomness, particularly gambling and lottery applications. These contracts typically generate pseudo-random numbers using predictable blockchain properties such as block.number, block.timestamp, block.difficulty, or blockhash(). Since miners have control over these values, malicious actors can manipulate timestamps or influence block properties to alter outcomes in their favor. For instance, contracts that rely on block.timestamp and private seeds for randomness generation can be exploited by attackers timing their transactions strategically, while predictable seeds fail to provide sufficient entropy, making future outcomes predictable.

To address bad randomness vulnerabilities, developers should avoid blockchain-internal sources due to their transparency and predictability. Secure alternatives include external oracles like Chainlink VRF which provides provably fair randomness, and commit-reveal schemes that require participants to submit concealed values before revealing them. Additional approaches include public-key cryptosystems such as the Signidice algorithm for two-party contracts, and cross-chain oracles like BTCRelay that leverage Bitcoin's Proof-of-Work entropy. These solutions, combined with time-delay mechanisms and multi-source entropy aggregation, provide robust protection against miner manipulation and ensure fair randomness generation.

# Comprehensive Analysis of Bad Randomness Sources in Smart Contracts
 
## Analysis Approach

This analysis examines bad randomness sources in two categories:

1. **Primary Bad Randomness Sources:** Sources that are inherently vulnerable when used directly for randomness generation
2. **Combinatorial Vulnerabilities:** How these primary sources, when combined together, create compounded vulnerabilities

We evaluate each source across different usage contexts to distinguish between safe and vulnerable patterns.

---

## Primary Bad Randomness Sources

### 1. **block.timestamp**

 
```solidity
// Vulnerability Type: PRIMARY - Direct manipulation by miners (±15 second window)
uint random = block.timestamp % 10;                    // Miner manipulation possible
if (block.timestamp % 2 == 0) { winner(); }           // Binary exploitation
uint seed = uint(block.timestamp);                     // Direct randomness casting
bytes32 hash = keccak256(abi.encodePacked(block.timestamp)); // Hash doesn't fix weakness

// Real exploit pattern from SmartBillions hack (2018)
function play() external {
    if (block.timestamp % 1000 == 0) {                 // 400+ ETH loss pattern
        payable(msg.sender).transfer(jackpot);
    }
}
```

####  **Safe Patterns:**
```solidity
// Safe: Time gates with sufficient margin (>15 seconds)
require(block.timestamp >= saleEndTime);               // Time-based access control
require(startTime <= block.timestamp <= endTime);     // Time range validation
require(block.timestamp >= lastAction + 1 hours);     // Cooldown mechanisms
lastActivity = block.timestamp;                       // Event timestamping

// Safe: Long-term time comparisons
if (block.timestamp >= deployTime + 365 days) {       // Annual operations
    enableFeature();
}
```

####  **Context Analysis Matrix:**
The Context Analysis Matrix for block.timestamp reveals critical distinctions between safe and vulnerable usage patterns. Time-based access control and event timestamping are classified as safe because they typically involve longer time margins (hours, days, or weeks) where the miner's ±15 second manipulation window becomes negligible relative to the intended time spans. Long-term comparisons remain secure since applications using annual or monthly timeframes can tolerate minor timestamp variations without compromising functionality. However, randomness generation, modulo operations, and direct casting to uint are consistently vulnerable because miners can deliberately manipulate block timestamps within a 15-second window to influence outcomes, making these patterns predictable and exploitable for financial gain. The key security principle is that block.timestamp becomes safe only when the application's time tolerance significantly exceeds the miner's manipulation capabilities.


| Usage Context | Safe | Vulnerable | Notes |
|---------------|------|------------|-------|
| Time-based access control | ✅ | ❌ | Safe with >15s margin |
| Event timestamping | ✅ | ❌ | No manipulation incentive |
| Randomness generation | ❌ | ✅ | Always vulnerable |
| Modulo operations | ❌ | ✅ | Predictable patterns |
| Direct casting to uint | ❌ | ✅ | Miner manipulation |
| Long-term comparisons | ✅ | ❌ | Hours/days tolerance |



---

### 2. **blockhash()**

 
```solidity
// Vulnerability Type: PRIMARY - Miner manipulation + limited 256-block history
bytes32 hash = blockhash(block.number - 1);           // Recent blocks = miner control
uint random = uint(blockhash(block.number)) % 100;    // Current block = always 0
bytes32 seed = blockhash(block.number - 50);          // Still in miner influence range

// False security: Delayed but insufficient
function badRandom() external {
    bytes32 hash = blockhash(block.number - 5);       // Still predictable
    require(hash != 0);                               // Doesn't fix core issue
    return uint(hash) % 100;
}

// 256-block limitation exploit
function exploitOldBlock() external {
    bytes32 hash = blockhash(block.number - 300);     // Returns 0 (beyond 256 blocks)
    uint predictable = uint(keccak256(abi.encodePacked(hash))); // Always same result
}
```

 ```solidity
// Safe: Proper commit-reveal with safeguards
mapping(address => bytes32) public commitments;
mapping(address => uint) public commitBlocks;

function commit(bytes32 commitment) external {
    commitments[msg.sender] = commitment;
    commitBlocks[msg.sender] = block.number;
}

function reveal(uint nonce) external {
    require(block.number > commitBlocks[msg.sender] + 1);     // Minimum delay
    require(block.number < commitBlocks[msg.sender] + 256);   // Within 256-block range
    
    bytes32 hash = blockhash(commitBlocks[msg.sender] + 1);
    require(hash != 0, "Block hash not available");
    
    bytes32 commitment = keccak256(abi.encodePacked(nonce, msg.sender));
    require(commitments[msg.sender] == commitment, "Invalid commitment");
    
    uint result = uint(keccak256(abi.encodePacked(hash, nonce))) % 100;
}

// Safe: Future block commitment with proper validation
mapping(address => uint256) public revealBlock;

function commitBlock(uint256 _futureBlock) external {
    require(revealBlock[msg.sender] == 0, "Can only commit 1 time per address");
    require(_futureBlock > block.number + 10, "Must commit to future block at least 10 blocks");
    revealBlock[msg.sender] = _futureBlock;
}

function getRandomness() external view returns (uint256) {
    uint256 selectedBlock = revealBlock[msg.sender];
    require(block.number > selectedBlock, "Not reach the target block yet");
    require(block.number <= selectedBlock + 256, "Commit expired");
    return blockhash(selectedBlock);
}
```

####  **Context Analysis Matrix:**
The blockhash() function presents a more complex vulnerability landscape due to Ethereum's 256-block limitation and the deterministic nature of block mining. Direct randomness generation and recent blocks (1-10) are vulnerable because miners retain influence over recently mined blocks and can coordinate to manipulate outcomes, especially when the economic incentive exceeds block rewards. Current block hash and blocks beyond the 256-limit are predictably vulnerable since they always return zero - the former because the hash hasn't been computed yet, and the latter due to EVM's storage limitations. However, properly implemented commit-reveal schemes and future block commitments achieve safety by creating a separation of knowledge: users cannot predict future block hashes when committing, while miners cannot know user secrets when mining blocks. The critical insight is that blockhash() requires sophisticated protocols with minimum delays and validation checks to transform an inherently manipulable data source into a cryptographically secure randomness foundation.

| Usage Context | Safe | Vulnerable | Notes |
|---------------|------|------------|-------|
| Direct randomness generation | ❌ | ✅ | Always manipulable by miners |
| Current block hash | ❌ | ✅ | Always returns 0 |
| Recent blocks (1-10) | ❌ | ✅ | Miner manipulation possible |
| Blocks beyond 256 limit | ❌ | ✅ | Always returns 0 - predictable |
| Commit-reveal scheme | ✅ | ❌ | Safe with proper implementation |
| Future block commitment | ✅ | ❌ | Safe with minimum delay + validation |
| Historical verification | ✅ | ❌ | Non-randomness use cases only |
| Combination with user input | ❌ | ✅ | Still manipulable |


 
### 3. **block.number**
 ```solidity
// Vulnerability Type: PRIMARY - Completely predictable
uint random = block.number % 10;                      // 100% predictable
if (block.number % 100 == 0) { specialEvent(); }     // Timing manipulation possible
uint seed = block.number + block.timestamp;           // Combination still weak

// Lottery exploit pattern
function lottery() external {
    if (block.number % userCount == userIndex[msg.sender]) {
        payable(msg.sender).transfer(prize);          // Predictable winner
    }
}
```

 ```solidity
// Safe: Block-based timing and access control
require(block.number > startBlock);                   // Launch timing
uint elapsed = block.number - startBlock;             // Duration calculation
if (block.number >= endBlock) { closeAuction(); }    // Deadline enforcement

// Safe: Rate limiting
require(block.number >= lastActionBlock[msg.sender] + 100); // Block-based cooldown
```

####  **Context Analysis Matrix:**

| Usage Context | Safe | Vulnerable | Notes |
|---------------|------|------------|-------|
| Direct randomness generation | ❌ | ✅ | 100% predictable sequence |
| Modulo operations for randomness | ❌ | ✅ | Exploitable patterns |
| Lottery/gambling selection | ❌ | ✅ | Winner predetermined |
| Timing-based special events | ❌ | ✅ | Attackers can time transactions |
| Access control timing | ✅ | ❌ | Safe for start/end conditions |
| Duration calculations | ✅ | ❌ | Mathematical operations only |
| Rate limiting/cooldowns | ✅ | ❌ | Prevents spam without randomness |
| Sequential operations | ✅ | ❌ | Order-dependent logic |
| Combination with other sources | ❌ | ✅ | Doesn't improve randomness |
---

## **Context Analysis Matrix Explanations**

**Block Number Vulnerability Analysis:** The Context Analysis Matrix for `block.number` demonstrates its fundamental unsuitability for randomness generation due to its completely predictable and sequential nature. Direct randomness generation, modulo operations, and lottery selections are consistently vulnerable because `block.number` follows a deterministic sequence that attackers can predict and exploit by timing their transactions precisely. As documented in recent IEEE research on Ethereum smart contract vulnerabilities, attackers can manipulate their entry timing in lottery contracts by calculating when `block.number % userCount` will equal their desired index, effectively predetermining winners. Timing-based special events also remain vulnerable since malicious actors can monitor the blockchain state and execute transactions exactly when beneficial conditions occur, such as when `block.number % 100 == 0` triggers special rewards.

**Block Number Safety in Non-Randomness Contexts:** Conversely, `block.number` achieves safety when used for legitimate timing control and sequential operations that don't rely on unpredictability. Access control timing, duration calculations, and rate limiting mechanisms leverage block numbers for their intended purpose - providing a reliable, monotonically increasing counter for blockchain state progression. These safe patterns work because they don't depend on randomness; instead, they utilize the predictable nature of block progression for legitimate business logic such as auction deadlines, cooldown periods, and launch timing. The DASP Top 10 security framework specifically acknowledges this distinction, noting that while block variables are dangerous for randomness, they remain appropriate for deterministic timing operations where predictability is actually desired rather than problematic.

---

### 4. **block.difficulty / block.prevrandao**

 ```solidity
// Pre-merge vulnerability (Proof of Work)
uint random = block.difficulty % 100;                 // Miner manipulation

// Post-merge (Ethereum 2.0 - The Merge) - still vulnerable
uint random = block.prevrandao % 100;                 // Validator predictability
bytes32 seed = keccak256(abi.encodePacked(block.prevrandao)); // Hash doesn't help

// False security: Thinking merge fixed randomness issues
function postMergeRandom() external view returns (uint) {
    return block.prevrandao % 1000;                   // Still manipulable by validators
}

// Last revealer attack pattern
function gambling() external payable {
    if (block.prevrandao % 2 == 0) {                  // Proposer can withhold block
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

 ```solidity
// Generally NO safe patterns for randomness exist
// EIP-4399 explicitly states: not suitable for secure randomness

// Very limited non-financial usage (with full risk understanding):
function nonCriticalCosmetic() external {
    if (block.prevrandao % 1000 == 0) {               // Cosmetic features only
        enableRainbowTheme();                         // No financial impact
    }
}

// Historical verification (non-randomness purpose):
function verifyEpochTransition(uint epochNumber) external view {
    require(block.prevrandao != 0, "Invalid RANDAO value"); // Data validation only
}
```

####  **Context Analysis Matrix:**

| Usage Context | Safe | Vulnerable | Notes |
|---------------|------|------------|-------|
| Direct randomness generation | ❌ | ✅ | Last revealer attack possible |
| Modulo operations | ❌ | ✅ | Proposer can withhold blocks |
| Financial applications | ❌ | ✅ | Economic incentive for manipulation |
| Gaming/gambling logic | ❌ | ✅ | 1-bit influence per proposer |
| Block withholding scenarios | ❌ | ✅ | Proposers can censor transactions |
| Consecutive slot control | ❌ | ✅ | Multiple validators coordination |
| Future RANDAO commitment | ⚠️ | ⚠️ | Requires 4+ epoch lookahead |
| Historical verification | ✅ | ❌ | Non-randomness data validation |
| Non-financial cosmetics | ✅ | ❌ | No economic manipulation incentive |


---

## 5. block.gaslimit

```solidity
// Vulnerability Type: PRIMARY - Miner can adjust gas limit within protocol bounds
uint random = block.gaslimit % 100;                   // Miner influence possible
bytes32 seed = keccak256(abi.encodePacked(block.gaslimit)); // Hash does not fix weakness

// Gambling exploit pattern
function lottery() external {
    uint winner = uint(keccak256(abi.encodePacked(block.gaslimit, msg.sender))) % players.length;
    payable(players[winner]).transfer(prize);         // Miner can influence outcome
}

// Combined with other weak sources
function badRandom() external view returns (uint) {
    return uint(keccak256(abi.encodePacked(
        block.gaslimit,
        block.timestamp,
        block.number
    ))) % 1000;                                       // All inputs are manipulable
}
```

Safe Patterns:

```solidity
// Safe: Gas limit checks for contract operations
require(block.gaslimit >= 8000000, "Gas limit too low");

// Safe: Estimating available gas for operations
if (block.gaslimit > 10000000) {
    performHeavyOperation();
}
```

Context Analysis Matrix:

The block.gaslimit value represents the maximum gas allowed in a block. Miners have the ability to adjust this value within certain protocol-defined bounds. While the adjustment range is limited, it still provides enough flexibility for miners to influence outcomes in randomness-dependent applications. The gas limit changes gradually between blocks, making it somewhat predictable. When combined with other weak sources, it adds minimal entropy and should never be trusted for random number generation.

| Usage Context | Safe | Vulnerable | Notes |
|---------------|------|------------|-------|
| Direct randomness generation | No | Yes | Miner can adjust within bounds |
| Modulo operations | No | Yes | Predictable patterns |
| Combined with other block values | No | Yes | Does not improve entropy |
| Gas availability checks | Yes | No | Legitimate operational use |
| Contract capacity planning | Yes | No | Non-randomness purpose |


## **Context Analysis Matrix Explanations**

**Block Difficulty/PREVRANDAO Pre-Merge vs Post-Merge Analysis:** The transition from `block.difficulty` to `block.prevrandao` via EIP-4399 fundamentally changed the underlying mechanism but did not resolve the core randomness vulnerability. Pre-merge, `block.difficulty` was manipulable by miners who could influence difficulty adjustments and timing attacks. Post-merge, `block.prevrandao` represents the beacon chain's RANDAO value, which, while more sophisticated than PoW difficulty, remains vulnerable to validator manipulation through the "last revealer attack" as documented in recent research. According to the official EIP-4399 specification, each block proposer maintains "1 bit of influence power per slot," allowing validators to either propose a block with their RANDAO contribution or withhold it entirely, creating predictable bias in subsequent randomness outputs. This manipulation capability persists regardless of whether the value is used directly or processed through hash functions.

**RANDAO Manipulation Techniques and Their Impact:** Current research from the Ethereum community and recent cryptographic analyses reveal multiple attack vectors against RANDAO-based randomness. The most significant is block withholding, where proposers can deliberately skip their assigned slots to influence future RANDAO mixes, with the limitation that their influence lasts only until the next honest proposal. More concerning for smart contract applications is transaction censoring, where proposers can delay specific transactions to force them into blocks with known RANDAO values, as highlighted in Zellic's security research. Additionally, when validators control consecutive slots (which occurs naturally in the protocol), they can explore multiple possible outcomes before committing to a strategy. The Ethereum Foundation's own documentation acknowledges these limitations, explicitly stating that RANDAO is designed for consensus-layer security rather than application-layer randomness, making external oracles like Chainlink VRF necessary for secure on-chain randomness in financial applications.

---


## 6. block.coinbase

```solidity
// Vulnerability Type: PRIMARY - Known to miner before block is mined
uint random = uint(block.coinbase) % 100;             // Miner knows their own address
bytes32 seed = keccak256(abi.encodePacked(block.coinbase)); // Predictable to miner

// Vulnerable lottery using coinbase
function pickWinner() external {
    uint index = uint(keccak256(abi.encodePacked(
        block.coinbase,
        block.timestamp
    ))) % participants.length;
    winner = participants[index];                     // Miner can predict outcome
}

// False security with multiple sources
function generateRandom() external view returns (uint) {
    return uint(keccak256(abi.encodePacked(
        block.coinbase,
        block.difficulty,
        block.number
    ))) % 1000;                                       // Miner controls all inputs
}
```

Safe Patterns:

```solidity
// Safe: Identifying block miner for logging
event BlockMined(address indexed miner, uint blockNumber);

function logMiner() external {
    emit BlockMined(block.coinbase, block.number);
}

// Safe: Miner reward distribution
function distributeMinerReward() external {
    payable(block.coinbase).transfer(reward);
}
```

Context Analysis Matrix:

The block.coinbase variable returns the address of the miner who mines the current block. Since miners know their own address before mining, they can easily predict any value derived from it. This makes block.coinbase completely unsuitable for randomness generation. The only legitimate uses are for identifying the block miner or distributing mining rewards.

| Usage Context | Safe | Vulnerable | Notes |
|---------------|------|------------|-------|
| Direct randomness generation | No | Yes | Miner knows own address |
| Seed for random functions | No | Yes | Completely predictable to miner |
| Combined with other sources | No | Yes | Does not add unpredictability |
| Miner identification | Yes | No | Intended purpose |
| Reward distribution | Yes | No | Non-randomness use case |
| Event logging | Yes | No | Informational only |


## Additional Considerations

### Rarely Used but Potentially Vulnerable Sources

While the four primary sources above represent the most commonly misused randomness sources in smart contracts, developers should be aware that **any deterministic or user-controlled value** can create vulnerabilities when used for randomness generation.

**Less Common Sources:**
- `tx.gasprice` - User-controlled gas price
- `gasleft()` - Execution-dependent remaining gas
- `msg.sender` - User-controlled caller address
- `tx.origin` - Transaction origin address

Although these sources are **rarely documented** in security literature as randomness sources, they remain **theoretically exploitable** if used for random number generation due to their predictable or user-controllable nature.

---

## Weak Source Combinations

### ** CRITICAL FINDING: No Safe Combinations Exist**

All combinations of weak randomness sources remain vulnerable:

```solidity
// Pattern 1: Multiple blockchain sources - ALL VULNERABLE
bytes32 seed1 = keccak256(abi.encodePacked(
    block.timestamp,    // Miner controlled (±15s)
    block.number,       // Completely predictable  
    block.prevrandao    // Validator influenced
));

// Pattern 2: User + blockchain sources - ALL VULNERABLE  
bytes32 seed2 = keccak256(abi.encodePacked(
    msg.sender,         // User controlled
    tx.gasprice,        // User controlled
    block.timestamp     // Miner controlled
));

// Pattern 3: Private variable illusion - BLOCKCHAIN IS PUBLIC
contract FalseEntropy {
    uint256 private secretSeed = 12345;  // Not actually secret on blockchain
    
    function badRandom() external view returns (uint) {
        return uint(keccak256(abi.encodePacked(
            secretSeed,           // Visible on blockchain
            block.timestamp,      // Miner controlled
            msg.sender           // User controlled
        ))) % 100;
    }
}
```

** Universal Rule:** Combining weak sources NEVER creates strong randomness

---

## Hash Functions in Randomness Context

### **Common Cryptographic Functions:**
- `keccak256()` - Most common hash function in Solidity
- `sha256()` - SHA-2 hash function
- `ripemd160()` - RIPEMD hash function

### **Security Analysis**

```solidity
//  Weak inputs = weak output (regardless of hash function)
bytes32 bad1 = keccak256(abi.encodePacked(block.timestamp, msg.sender));
bytes32 bad2 = sha256(abi.encodePacked(block.timestamp, msg.sender));
bytes32 bad3 = ripemd160(abi.encodePacked(block.timestamp, msg.sender));

// Secure inputs = secure output
bytes32 safe = keccak256(abi.encodePacked(
    oracleRandomness,    // External secure source (Chainlink VRF)
    userCommitment       // Proper commit-reveal scheme
));
```

** Key Principle:** Hash functions are cryptographically secure; the vulnerability lies in predictable inputs. Using `keccak256(weak_input)` doesn't make the weak input secure.

---



## References
- [SWC-120: Weak Sources of Randomness](https://swcregistry.io/docs/SWC-120)
- [ConsenSys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [ConsenSys Best Practices - Timestamp Dependence](https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/timestamp-dependence/)
- [ConsenSys Smart Contract Best Practices - Randomness](https://consensys.github.io/smart-contract-best-practices/attacks/randomness/)
- [NIST FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [EIP-4399: PREVRANDAO](https://eips.ethereum.org/EIPS/eip-4399)
- [Smart Contract Vulnerabilities - Timestamp Dependence](https://github.com/KadenZipfel/smart-contract-attack-vectors/blob/master/vulnerabilities/timestamp-dependence.md)
- [OWASP Smart Contract Top 10 - Insufficient Entropy](https://owasp.org/www-project-smart-contract-top-10/)
- [Ethereum Yellow Paper - Block Header Specification](https://ethereum.github.io/yellowpaper/paper.pdf)
- [DASP Top 10 - Bad Randomness](https://dasp.co/)
- [IEEE Transactions on Software Engineering - Demystifying Random Number Vulnerabilities](https://dl.acm.org/doi/10.1109/TSE.2023.3271417)
- [Exploiting Predictable Randomness in Ethereum Smart Contracts](https://www.kayssel.com/post/web3-2-lottery/)
- [ImmuneBytes - Smart Contract Vulnerabilities](https://immunebytes.com/blog/smart-contract-vulnerabilities/)
- [Ethereum.org - Block Proposal](https://ethereum.org/en/developers/docs/consensus-mechanisms/pos/block-proposal/)
- [ETH2 Book - Randomness](https://eth2book.info/latest/part2/building_blocks/randomness/)
- [Zellic Research - ETH 2 Proof-of-Stake Developer Guide](https://www.zellic.io/blog/eth2-proof-of-stake-developer-guide/)

- [Ethereum Stack Exchange - 256 Block Limitation](https://ethereum.stackexchange.com/questions/418/why-are-contracts-limited-to-only-the-previous-256-block-hashes)
- [Smart Contract Security Testing Guide - Randomness](https://docs.inspex.co/smart-contract-security-testing-guide/testing-categories/7-testing-randomness)
- [SlowMist - Common Vulnerabilities in Solidity: Randomness](https://www.slowmist.com/articles/solidity-security/Common-Vulnerabilities-in-Solidity-Randomness.html)
- [Gitcoin Blog - Commit Reveal Scheme on Ethereum](https://www.gitcoin.co/blog/commit-reveal-scheme-on-ethereum)
---

