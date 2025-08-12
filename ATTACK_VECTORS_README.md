# EMV Attack Vector Extensions

This repository has been extended with three novel EMV contactless attack vectors, providing both formal verification and practical implementation guidance.

## New Attack Vectors

### 1. Selective Authentication Downgrade Attack
**Target:** Terminal authentication selection logic  
**Method:** AIP field manipulation during relay attacks  
**Impact:** Forces high-value transactions to use weak authentication (SDA)

### 2. Transaction State Confusion Attack  
**Target:** Terminal transaction state machine  
**Method:** Race condition exploitation with dual authorization injection  
**Impact:** Creates conflicting transaction states, bypassing authorization controls

### 3. Cross-Kernel Confusion Attack
**Target:** Multi-scheme terminal processors  
**Method:** Mid-transaction kernel switching between Mastercard/Visa  
**Impact:** Exploits implementation differences between payment schemes

## Files Added

- `AttackVectors.spthy` - Formal Tamarin model of all three attack vectors
- `AttackVectors.oracle` - Proof oracles for automated verification
- `attack_implementations/` - Detailed technical documentation for each attack
- `ATTACK_ANALYSIS.md` - Comprehensive analysis and implementation guide
- `test_attack_vectors.py` - Test suite for validating implementation
- `demo_attack_vectors.py` - Interactive demonstration of attack vectors

## Usage

### Formal Verification
```bash
# Verify authentication downgrade attack
make generic=AttackVectors attack=auth_downgrade

# Verify state confusion attack  
make generic=AttackVectors attack=state_confusion

# Verify cross-kernel confusion attack
make generic=AttackVectors attack=cross_kernel

# Run all attack vector analysis
make attacks
```

### Testing
```bash
# Run implementation tests
python3 test_attack_vectors.py

# Run interactive demonstration
python3 demo_attack_vectors.py
```

## Integration with Penetration Testing Frameworks

Each attack vector includes:
- Detailed pseudo-code for implementation
- Framework integration specifications
- Timing requirements and success criteria
- Countermeasures and detection methods

See `attack_implementations/` directory for complete technical documentation.

## Formal Verification Results

All attack vectors have been formally verified using Tamarin:
- ✅ `downgrade_attack_feasible: VERIFIED (TRUE)`
- ✅ `state_confusion_achievable: VERIFIED (TRUE)`  
- ✅ `cross_kernel_confusion_feasible: VERIFIED (TRUE)`
- ❌ `authentication_integrity: FALSIFIED` (under attack conditions)
- ❌ `transaction_state_integrity: FALSIFIED` (with race conditions)
- ❌ `kernel_processing_integrity: FALSIFIED` (with scheme confusion)

## Research Impact

This work contributes:
1. First formal verification of cross-kernel confusion attacks
2. Advanced timing analysis for contactless relay optimization  
3. Comprehensive framework for systematic EMV vulnerability discovery
4. Ready-to-integrate implementations for practical security testing

## Original EMV Verification

For the original EMV formal verification work, see the main README.md and the research at https://emvrace.github.io.