#  Bad Randomness in Smart Contracts

##   What is it?
Bad randomness vulnerability affects smart contracts that require randomness, particularly gambling and lottery applications. These contracts typically generate pseudo-random numbers using predictable blockchain properties such as block.number, block.timestamp, block.difficulty, or blockhash(). Since miners have control over these values, malicious actors can manipulate timestamps or influence block properties to alter outcomes in their favor. For instance, contracts that rely on block.timestamp and private seeds for randomness generation can be exploited by attackers timing their transactions strategically, while predictable seeds fail to provide sufficient entropy, making future outcomes predictable.

To address bad randomness vulnerabilities, developers should avoid blockchain-internal sources due to their transparency and predictability. Secure alternatives include external oracles like Chainlink VRF which provides provably fair randomness, and commit-reveal schemes that require participants to submit concealed values before revealing them. Additional approaches include public-key cryptosystems such as the Signidice algorithm for two-party contracts, and cross-chain oracles like BTCRelay that leverage Bitcoin's Proof-of-Work entropy. These solutions, combined with time-delay mechanisms and multi-source entropy aggregation, provide robust protection against miner manipulation and ensure fair randomness generation.
##  Problematic Sources:

### 1. block.timestamp
  **Problem:** Miners can partially control it

### 2. block.number  
  **Problem:** Completely predictable

### 3. blockhash()
  **Problem:** Manipulable for recent blocks

##   Vulnerable Example:
 
```Solidity
contract VulnerableLottery {
    uint256 private seed;
    function play() public payable {
        require(msg.value == 1 ether);
        uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, seed))); // BAD!
        if (random % 10 == 0) {
            msg.sender.transfer(9 ether);}
        seed = random;}}

```
