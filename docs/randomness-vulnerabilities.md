# 🎲 Bad Randomness in Smart Contracts

## 🔍 What is it?
Bad randomness occurs when smart contracts use predictable sources to generate random values.

## ⚠️ Problematic Sources:

### 1. block.timestamp
❌ **Problem:** Miners can partially control it

### 2. block.number  
❌ **Problem:** Completely predictable

### 3. blockhash()
❌ **Problem:** Manipulable for recent blocks

## 💡 Vulnerable Example:
```solidity
function lottery() public {
    uint256 random = block.timestamp % 100;  // ❌ BAD!
    // winner selection...
}
