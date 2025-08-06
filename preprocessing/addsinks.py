import json
import re
import os
from typing import Dict, List, Any, Optional, Tuple, Set
from pathlib import Path
import logging

 logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8',
    handlers=[
        logging.FileHandler("sink_detection.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class EvidenceBasedAssessor:
    """Evidence-based sink risk assessment using 4 sources as per TaintSentinel algorithm"""

    def __init__(self):
        # OWASP Smart Contract Top 10 (2025)
        self.owasp_2025 = {
            "valueTransfer": {"rank": 1, "category": "Reentrancy & Value Transfer"},
            "randomGeneration": {"rank": 3, "category": "Bad Randomness"},
            "accessControl": {"rank": 2, "category": "Access Control"},
            "externalInteraction": {"rank": 4, "category": "Unchecked External Call"},
            "stateModification": {"rank": 6, "category": "State Manipulation"},
            "financialDecision": {"rank": 5, "category": "Business Logic"},
            "controlFlow": {"rank": 7, "category": "Control Flow"}
        }

         self.cwe_mappings = {
            "valueTransfer": ["CWE-691", "CWE-841"],
            "randomGeneration": ["CWE-330", "CWE-338"],
            "accessControl": ["CWE-284", "CWE-863"],
            "externalInteraction": ["CWE-20", "CWE-749"],
            "stateModification": ["CWE-367", "CWE-362"],
            "financialDecision": ["CWE-682", "CWE-190"],
            "controlFlow": ["CWE-670", "CWE-754"]
        }

         self.swc_registry = {
            "valueTransfer": ["SWC-107", "SWC-105"],
            "randomGeneration": ["SWC-120"],
            "accessControl": ["SWC-105", "SWC-106"],
            "externalInteraction": ["SWC-104", "SWC-112"],
            "stateModification": ["SWC-114", "SWC-124"],
            "financialDecision": ["SWC-101", "SWC-132"],
            "controlFlow": ["SWC-110", "SWC-113"]
        }

         self.historical_attacks = {
            "valueTransfer": [
                {"name": "TheDAO (2016)", "loss": "$60M"},
                {"name": "Parity Wallet (2017)", "loss": "$30M"}
            ],
            "randomGeneration": [
                {"name": "Fomo3D (2018)", "loss": "$3M"},
                {"name": "SmartBillions (2017)", "loss": "$400K"}
            ],
            "accessControl": [
                {"name": "Parity Multisig (2017)", "loss": "$150M"},
                {"name": "Poly Network (2021)", "loss": "$600M"}
            ],
            "externalInteraction": [
                {"name": "King of Ether (2016)", "loss": "N/A"},
                {"name": "Harvest Finance (2020)", "loss": "$24M"}
            ],
            "stateModification": [
                {"name": "bZx (2020)", "loss": "$8M"}
            ],
            "financialDecision": [
                {"name": "YAM Finance (2020)", "loss": "$750K"}
            ],
            "controlFlow": [
                {"name": "Akropolis (2020)", "loss": "$2M"}
            ]
        }

    def assess_sink_risk(self, sink_type: str) -> Dict[str, Any]:
        """Assess sink risk based on 4 evidence sources"""
        evidence_count = 0
        evidence_details = []

        # Check all 4 evidence sources
        if sink_type in self.owasp_2025:
            evidence_count += 1
            evidence_details.append({
                "source": "OWASP 2025",
                "rank": f"#{self.owasp_2025[sink_type]['rank']}",
                "category": self.owasp_2025[sink_type]['category']
            })

        if sink_type in self.cwe_mappings:
            evidence_count += 1
            evidence_details.append({
                "source": "CWE",
                "ids": self.cwe_mappings[sink_type]
            })

        if sink_type in self.swc_registry:
            evidence_count += 1
            evidence_details.append({
                "source": "SWC",
                "ids": self.swc_registry[sink_type]
            })

        if sink_type in self.historical_attacks and self.historical_attacks[sink_type]:
            evidence_count += 1
            attacks = self.historical_attacks[sink_type]
            evidence_details.append({
                "source": "Historical Attacks",
                "count": len(attacks),
                "totalLoss": sum(self._parse_loss(a.get('loss', '0')) for a in attacks),
                "examples": [a['name'] for a in attacks[:2]]
            })

        # Determine risk level
        if evidence_count >= 4:
            risk_level = "Critical"
        elif evidence_count >= 3:
            risk_level = "High"
        elif evidence_count >= 2:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        return {
            "riskLevel": risk_level,
            "evidenceCount": evidence_count,
            "evidenceDetails": evidence_details,
            "riskJustification": self._generate_justification(sink_type, risk_level, evidence_count, evidence_details)
        }

    def _parse_loss(self, loss_str: str) -> int:
        """Parse loss string to integer"""
        if loss_str == "N/A":
            return 0
        loss_str = loss_str.replace("$", "").replace(",", "")
        if "M" in loss_str:
            return int(float(loss_str.replace("M", "")) * 1_000_000)
        elif "K" in loss_str:
            return int(float(loss_str.replace("K", "")) * 1_000)
        return int(loss_str)

    def _generate_justification(self, sink_type: str, risk_level: str, evidence_count: int,
                                evidence_details: List[Dict]) -> str:
        """Generate justification"""
        justification = f"{sink_type} sink classified as {risk_level} risk based on {evidence_count}/4 evidence sources. "

        for evidence in evidence_details:
            if evidence['source'] == 'OWASP 2025':
                justification += f"Ranked {evidence['rank']} in OWASP Smart Contract Top 10. "
            elif evidence['source'] == 'CWE':
                justification += f"Maps to CWE: {', '.join(evidence['ids'])}. "
            elif evidence['source'] == 'SWC':
                justification += f"Documented in SWC: {', '.join(evidence['ids'])}. "
            elif evidence['source'] == 'Historical Attacks':
                justification += f"{evidence['count']} historical attacks with significant losses. "

        return justification.strip()


class SinkIdentifier:
    """Enhanced sink identifier with context-aware filtering"""

    def __init__(self):
        self.evidence_assessor = EvidenceBasedAssessor()

        # Sources that make control flow relevant (from algorithm)
        self.dangerous_sources = {
            'block.timestamp', 'block.difficulty', 'block.prevrandao',
            'blockhash', 'block.blockhash', 'msg.sender', 'tx.origin'
        }

        # Define patterns with context requirements
        self._define_sink_patterns()

    def _define_sink_patterns(self):
        """Define sink patterns with enhanced context awareness"""

        # Value Transfer - Always relevant
        self.value_transfer_patterns = {
            "transfer": {
                "pattern": r'\.transfer\s*\(',
                "sinkType": "valueTransfer",
                "alwaysRelevant": True
            },
            "array_transfer": {  # اضافه شده برای transfers از آرایه
                "pattern": r'\[[^\]]+\]\s*\.transfer\s*\(',
                "sinkType": "valueTransfer",
                "alwaysRelevant": True
            },
            "suicide": {
                "pattern": r'\bsuicide\s*\(',
                "sinkType": "valueTransfer",
                "alwaysRelevant": True
            },
            "send": {
                "pattern": r'\.send\s*\(',
                "sinkType": "valueTransfer",
                "alwaysRelevant": True
            },
            "array_send": {  # اضافه شده
                "pattern": r'\[[^\]]+\]\s*\.send\s*\(',
                "sinkType": "valueTransfer",
                "alwaysRelevant": True
            },
            "call.value": {
                "pattern": r'\.call\s*[(\{]\s*value\s*[:=]',
                "sinkType": "valueTransfer",
                "alwaysRelevant": True
            },
            "selfdestruct": {
                "pattern": r'\bselfdestruct\s*\(',
                "sinkType": "valueTransfer",
                "alwaysRelevant": True
            }
        }

        # Control Flow - Only relevant if contains dangerous sources
        self.control_flow_patterns = {
            "if": {
                "pattern": r'\bif\s*\(',
                "sinkType": "controlFlow",
                "requiresDangerousSource": True
            },
            "require": {
                "pattern": r'\brequire\s*\(',
                "sinkType": "controlFlow",
                "alwaysRelevant": True  # Security checks are always relevant
            },
            "assert": {
                "pattern": r'\bassert\s*\(',
                "sinkType": "controlFlow",
                "alwaysRelevant": True
            },
            "modifier": {
                "pattern": r'\bmodifier\s+\w+\s*\([^)]*\)\s*\{',
                "sinkType": "controlFlow",
                "alwaysRelevant": True  # Modifiers are access control
            }
        }

        # Random Generation - Always relevant in gambling/lottery contexts
        self.random_generation_patterns = {
            "keccak256": {
                "pattern": r'\bkeccak256\s*\(',
                "sinkType": "randomGeneration",
                "requiresRandomContext": True
            },
            "sha256": {  
                "pattern": r'\bsha256\s*\(',
                "sinkType": "randomGeneration",
                "requiresRandomContext": True
            },
            "sha3": {  
                "pattern": r'\bsha3\s*\(',
                "sinkType": "randomGeneration",
                "requiresRandomContext": True
            }
        }

        # Access Control - Always relevant
        self.access_control_patterns = {
            "onlyOwner": {
                "pattern": r'\bonlyOwner\b',
                "sinkType": "accessControl",
                "alwaysRelevant": True
            },
            "onlyAdmin": {
                "pattern": r'\bonlyAdmin\b',
                "sinkType": "accessControl",
                "alwaysRelevant": True
            }
        }

        # State Modification - Only for state variables
        self.state_modification_patterns = {
            "storage_write": {
                "pattern": r'(\w+)\s*=\s*(?!=)',
                "sinkType": "stateModification",
                "requiresStateVariable": True
            },
            "mapping_update": {
                "pattern": r'(\w+)\s*\[[^\]]+\]\s*=',
                "sinkType": "stateModification",
                "requiresStateVariable": True
            },
            "array_push": {
                "pattern": r'(\w+)\.push\s*\(',
                "sinkType": "stateModification",
                "requiresStateVariable": True
            },
            "delete": {
                "pattern": r'\bdelete\s+(\w+)',
                "sinkType": "stateModification",
                "requiresStateVariable": True
            },
            "delete_array_element": {  # اضافه شده
                "pattern": r'\bdelete\s+(\w+)\[[^\]]+\]',
                "sinkType": "stateModification",
                "requiresStateVariable": True
            }
        }

        # Financial Decision - Context dependent
        self.financial_decision_patterns = {
            "winnerSelection": {
                "pattern": r'\b(winner|reward)\s*=',
                "sinkType": "financialDecision",
                "alwaysRelevant": True
            },
            "balanceCalculation": {
                "pattern": r'\b(balance)\s*[=+\-*/]',
                "sinkType": "financialDecision",
                "alwaysRelevant": True
            },
            "randomCalculation": {  # اضافه شده برای lottery contracts
                "pattern": r'\b(random|rand|lottery|pick)\w*\s*=',
                "sinkType": "financialDecision",
                "alwaysRelevant": True
            }
        }

        # External Interaction - Always relevant
        self.external_interaction_patterns = {
            "external_call": {
                "pattern": r'[^.]\bcall\s*[(\{]',
                "sinkType": "externalInteraction",
                "alwaysRelevant": True
            },
            "delegatecall": {
                "pattern": r'\.delegatecall\s*\(',
                "sinkType": "externalInteraction",
                "alwaysRelevant": True
            }
        }

        # Combine all patterns
        self.all_sink_patterns = {}
        for patterns in [
            self.value_transfer_patterns,
            self.control_flow_patterns,
            self.random_generation_patterns,
            self.access_control_patterns,
            self.state_modification_patterns,
            self.financial_decision_patterns,
            self.external_interaction_patterns
        ]:
            self.all_sink_patterns.update(patterns)

        # Compile patterns
        for name, info in self.all_sink_patterns.items():
            info['compiled_pattern'] = re.compile(info['pattern'])

    def _contains_dangerous_source(self, code_snippet: str) -> bool:
        """Check if code contains dangerous sources"""
        for source in self.dangerous_sources:
            if source in code_snippet:
                return True
        return False

    def _is_in_random_context(self, code: str, position: int) -> bool:
        """Check if position is in randomness generation context"""
        # Look for patterns indicating randomness generation
        context_window = code[max(0, position - 200):position + 200]
        random_indicators = [
            'random', 'getRandom', 'generateRandom', 'lottery',
            'winner', 'pick', 'select', 'chance'
        ]
        return any(indicator in context_window.lower() for indicator in random_indicators)

    def _extract_state_variables(self, code: str) -> Set[str]:
        """Extract state variables from contract"""
        state_vars = set()

        # Find contract boundaries
        contract_pattern = r'contract\s+\w+[^{]*\{([^}]+)\}'
        contract_matches = re.finditer(contract_pattern, code, re.DOTALL)

        for match in contract_matches:
            contract_body = match.group(1)

            # Find state variable declarations (outside functions)
            # Remove function bodies first
            clean_body = re.sub(r'function\s+\w+[^{]*\{[^}]*\}', '', contract_body, flags=re.DOTALL)
            clean_body = re.sub(r'modifier\s+\w+[^{]*\{[^}]*\}', '', clean_body, flags=re.DOTALL)

            # Now find variable declarations
            var_patterns = [
                r'(uint\d*|int\d*|address|bool|bytes\d*|string|mapping)\s+(?:public\s+|private\s+|internal\s+)?(\w+)',
                r'(\w+)\s*\[\]\s+(?:public\s+|private\s+|internal\s+)?(\w+)',
                r'mapping\s*\([^)]+\)\s+(?:public\s+|private\s+|internal\s+)?(\w+)'
            ]

            for pattern in var_patterns:
                for match in re.finditer(pattern, clean_body):
                    if pattern.startswith('mapping'):
                        state_vars.add(match.group(1))
                    else:
                        state_vars.add(match.group(2))

        return state_vars

    def identify_sinks(self, solidity_code: str, state_variables: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
        """Identify sinks with context-aware filtering"""
        sinks = []
        code_clean = self._remove_comments(solidity_code)

        # Extract state variables if not provided
        if state_variables is None:
            state_variables = self._extract_state_variables(code_clean)

        for sink_name, sink_info in self.all_sink_patterns.items():
            pattern = sink_info['compiled_pattern']

            for match in pattern.finditer(code_clean):
                # Apply context-aware filtering
                should_include = False

                # Check if always relevant
                if sink_info.get('alwaysRelevant', False):
                    should_include = True
                    # بررسی اگر require برای access control است
                    if sink_name == "require" and should_include:
                        condition = self._extract_condition(code_clean, match.end())
                        print(f"DEBUG - Sink: {sink_name}, Condition: {condition}")  # این خط را اضافه کنید
                        if condition and any(pattern in condition for pattern in
                                             ['msg.sender == owner', 'msg.sender==owner', 'owner == msg.sender',
                                              'owner==msg.sender', 'onlyOwner', 'onlyAdmin']):
                            # Skip normal risk assessment and use custom one for access control
                            risk_assessment = {
                                'riskLevel': 'Low',
                                'evidenceCount': 1,
                                'evidenceDetails': [{'source': 'Access Control Pattern', 'type': 'security_check'}],
                                'riskJustification': 'Access control check - standard security pattern'
                            }
                            # Create sink entry with custom risk assessment
                            sink_entry = {
                                'type': 'sink',
                                'sinkName': sink_name,
                                'sinkType': sink_info['sinkType'],
                                'sensitivity': self._calculate_sensitivity(sink_info['sinkType']),
                                'riskLevel': risk_assessment['riskLevel'],
                                'evidenceCount': risk_assessment['evidenceCount'],
                                'evidenceDetails': risk_assessment['evidenceDetails'],
                                'riskJustification': risk_assessment['riskJustification'],
                                'position': match.start(),
                                'matchedText': match.group(0),
                                'isSink': True,
                                'context': self._determine_context(code_clean, match.start()),
                                'codeSnippet': self._extract_code_snippet(code_clean, match.start()),
                                'condition': condition
                            }
                            sinks.append(sink_entry)
                            continue  # Skip the rest of the loop

                # Check if requires dangerous source (for control flow)
                elif sink_info.get('requiresDangerousSource', False):
                    condition_text = self._extract_condition(code_clean, match.end())
                    if condition_text and self._contains_dangerous_source(condition_text):
                        should_include = True

                # Check if requires random context (for crypto functions)
                elif sink_info.get('requiresRandomContext', False):
                    if self._is_in_random_context(code_clean, match.start()):
                        should_include = True

                # Check if requires state variable
                elif sink_info.get('requiresStateVariable', False):
                    var_match = match.group(1) if match.groups() else None
                    if var_match and var_match in state_variables:
                        should_include = True

                if not should_include:
                    continue

                # Get context
                context = self._determine_context(code_clean, match.start())

                # Get evidence-based risk assessment
                risk_assessment = self.evidence_assessor.assess_sink_risk(sink_info['sinkType'])

                # Create sink entry
                sink_entry = {
                    'type': 'sink',
                    'sinkName': sink_name,
                    'sinkType': sink_info['sinkType'],
                    'sensitivity': self._calculate_sensitivity(sink_info['sinkType']),
                    'riskLevel': risk_assessment['riskLevel'],
                    'evidenceCount': risk_assessment['evidenceCount'],
                    'evidenceDetails': risk_assessment['evidenceDetails'],
                    'riskJustification': risk_assessment['riskJustification'],
                    'position': match.start(),
                    'matchedText': match.group(0),
                    'isSink': True,
                    'context': context,
                    'codeSnippet': self._extract_code_snippet(code_clean, match.start())
                }

                # Add specific attributes based on sink type
                if sink_info['sinkType'] == 'controlFlow':
                    condition = self._extract_condition(code_clean, match.end())
                    if condition:
                        sink_entry['condition'] = condition

                elif sink_info['sinkType'] == 'valueTransfer':
                    amount = self._extract_amount(code_clean, match.start())
                    if amount:
                        sink_entry['transferAmount'] = amount

                elif sink_info['sinkType'] == 'financialDecision':
                    calculation = self._extract_calculation(code_clean, match.start())
                    if calculation:
                        sink_entry['calculation'] = calculation

                sinks.append(sink_entry)

        return sinks

    def _calculate_sensitivity(self, sink_type: str) -> float:
        """Calculate sensitivity based on sink type"""
        sensitivity_map = {
            'valueTransfer': 0.95,
            'randomGeneration': 0.9,
            'accessControl': 0.85,
            'externalInteraction': 0.8,
            'financialDecision': 0.8,
            'stateModification': 0.75,
            'controlFlow': 0.7
        }
        return sensitivity_map.get(sink_type, 0.5)

    def _determine_context(self, code: str, position: int) -> Dict[str, Any]:
        """Determine function/modifier context"""
        # Find the enclosing function or modifier
        search_code = code[:position]

        # Patterns for different contexts
        patterns = [
            (r'function\s+(\w+)\s*\([^)]*\)\s*(?:public|private|internal|external|view|pure|payable|\s)*(?:returns\s*\([^)]*\))?\s*\{', 'function'),
            (r'modifier\s+(\w+)\s*\([^)]*\)\s*\{', 'modifier'),
            (r'constructor\s*\([^)]*\)\s*(?:public|payable|\s)*\s*\{', 'constructor'),
            (r'function\s*\(\s*\)\s*(?:payable\s*)?(?:public\s*)?(?:external\s*)?\s*\{', 'fallback')  # اضافه شده
        ]

        best_match = None
        best_pos = -1

        for pattern, ctx_type in patterns:
            matches = list(re.finditer(pattern, search_code))
            if matches:
                last_match = matches[-1]
                if last_match.start() > best_pos:
                    best_match = (last_match, ctx_type)
                    best_pos = last_match.start()

        if not best_match:
            return {
                'type': 'global',
                'name': '',
                'visibility': 'N/A',
                'mutability': 'N/A',
                'isPayable': False,
                'nodeId': f"global_{position}"
            }

        match, ctx_type = best_match

        if ctx_type == 'constructor':
            name = 'constructor'
        elif ctx_type == 'fallback':  # اضافه شده
            name = 'fallback'
        else:
            name = match.group(1) if match.groups() else 'unknown'

        func_decl = match.group(0)

        # Extract visibility and mutability
        visibility = 'private'  # default
        for vis in ['public', 'private', 'internal', 'external']:
            if vis in func_decl:
                visibility = vis
                break

        mutability = ''
        for mut in ['view', 'pure', 'payable']:
            if mut in func_decl:
                mutability = mut
                break

        return {
            'type': ctx_type,
            'name': name,
            'visibility': visibility,
            'mutability': mutability,
            'isPayable': 'payable' in func_decl,
            'nodeId': f"{ctx_type}_{name}_{position}"
        }

    def _extract_code_snippet(self, code: str, position: int, context_size: int = 150) -> str:
        """Extract meaningful code snippet"""
        start = max(0, position - context_size // 2)
        end = min(len(code), position + context_size // 2)

        # Adjust to logical boundaries
        while start > 0 and code[start] not in ['\n', ';', '{', '}']:
            start -= 1
        while end < len(code) - 1 and code[end] not in ['\n', ';', '{', '}']:
            end += 1

        snippet = code[start:position] + "<<<SINK>>>" + code[position:end]
        snippet = ' '.join(snippet.split())

        return snippet.strip()

    def _extract_condition(self, code: str, start_pos: int) -> Optional[str]:
        """Extract condition from control flow"""
        # Skip whitespace and find opening parenthesis
        i = start_pos - 1  # شروع از یک کاراکتر قبل

        while i < len(code) and code[i] != '(':
            i += 1

        if i >= len(code):
            return None

        start = i + 1
        paren_count = 1
        i += 1

        while i < len(code) and paren_count > 0:
            if code[i] == '(':
                paren_count += 1
            elif code[i] == ')':
                paren_count -= 1
            i += 1

        if paren_count == 0:
            return code[start:i - 1].strip()

        return None

    def _extract_amount(self, code: str, position: int) -> Optional[str]:
        """Extract transfer amount"""
        match = re.search(r'[(\{]\s*(?:value\s*:\s*)?([^,)}\s]+)', code[position:position + 100])
        if match:
            return match.group(1).strip()
        return None

    def _extract_calculation(self, code: str, position: int) -> Optional[str]:
        """Extract financial calculation"""
        match = re.search(r'=\s*([^;]+);', code[position:position + 200])
        if match:
            return match.group(1).strip()
        return None

    def _remove_comments(self, code: str) -> str:
        """Remove comments from code"""
        code = re.sub(r'//.*', '', code)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        return code

    def analyze_sinks_in_code(self, solidity_code: str, state_variables: Optional[Set[str]] = None) -> Dict[str, Any]:
        """Main analysis function"""
        sinks = self.identify_sinks(solidity_code, state_variables)

        # Group sinks by type
        sinks_by_type = {}
        for sink in sinks:
            sink_type = sink['sinkType']
            if sink_type not in sinks_by_type:
                sinks_by_type[sink_type] = []
            sinks_by_type[sink_type].append(sink)

        # Calculate statistics - now including both old and new metrics
        summary = {
            'totalSinks': len(sinks),
            # Old metrics (for backward compatibility)
            'criticalSinks': len([s for s in sinks if s['sensitivity'] >= 0.9]),
            'highSensitivity': len([s for s in sinks if 0.8 <= s['sensitivity'] < 0.9]),
            'mediumSensitivity': len([s for s in sinks if 0.7 <= s['sensitivity'] < 0.8]),
            # New metrics (evidence-based)
            'criticalRiskSinks': len([s for s in sinks if s['riskLevel'] == 'Critical']),
            'highRiskSinks': len([s for s in sinks if s['riskLevel'] == 'High']),
            'mediumRiskSinks': len([s for s in sinks if s['riskLevel'] == 'Medium']),
            'lowRiskSinks': len([s for s in sinks if s['riskLevel'] == 'Low']),
            'sinksByType': {k: len(v) for k, v in sinks_by_type.items()},
            'evidenceBasedAssessment': True
        }

        return {
            'sinks': sinks,
            'sinksByType': sinks_by_type,
            'summary': summary
        }

    def update_ast_with_sinks(self, ast_data: Dict, sinks_analysis: Dict) -> Dict:
        """Update AST with sink information"""
        if 'sinks' not in ast_data:
            ast_data['sinks'] = []

        ast_data['sinks'] = sinks_analysis['sinks']
        ast_data['sinksSummary'] = sinks_analysis['summary']

        # Update functions with sink usage
        if 'contracts' in ast_data:
            for contract_name, contract_data in ast_data['contracts'].items():
                if 'functions' in contract_data:
                    for func_name, func_data in contract_data['functions'].items():
                        # Find sinks in this function
                        func_sinks = [
                            s for s in sinks_analysis['sinks']
                            if s['context']['type'] == 'function' and
                               s['context']['name'] == func_name
                        ]
                        if func_sinks:
                            func_data['usedSinks'] = func_sinks
                            func_data['hasValueTransfer'] = any(
                                s['sinkType'] == 'valueTransfer' for s in func_sinks
                            )
                            func_data['hasRandomGeneration'] = any(
                                s['sinkType'] == 'randomGeneration' for s in func_sinks
                            )
                            # Add risk summary for function
                            func_data['maxSinkRisk'] = max(
                                (s['riskLevel'] for s in func_sinks),
                                key=lambda r: ['Low', 'Medium', 'High', 'Critical'].index(r)
                            )

        return ast_data


def analyze_contract_sinks(solidity_code: str, state_variables: Optional[Set[str]] = None) -> Dict[str, Any]:
    """Analyze sinks in contract code"""
    identifier = SinkIdentifier()
    return identifier.analyze_sinks_in_code(solidity_code)


def update_json_with_sinks(json_dir: str, source_dir: str) -> None:
    """Update JSON files with enhanced sink information"""
    identifier = SinkIdentifier()

    json_files = list(Path(json_dir).glob('**/*.json'))

    if not json_files:
        logger.info(f"No JSON files found in {json_dir}")
        return

    logger.info(f"Found {len(json_files)} JSON files to process")

    success_count = 0
    error_count = 0

    for json_file in json_files:
        try:
            logger.info(f"\nProcessing {json_file}...")

            # Load JSON
            with open(json_file, 'r', encoding='utf-8') as f:
                ast_data = json.load(f)

            # Find Solidity file
            sol_filename = ast_data.get("file_name", f"{json_file.stem}.sol")
            sol_file = Path(sol_filename)  # چون در JSON مسیر کامل داریم

            if not sol_file.exists():
                sol_files = list(Path(source_dir).glob(f"**/{sol_filename}"))
                if sol_files:
                    sol_file = sol_files[0]
                else:
                    logger.warning(f"Solidity file {sol_filename} not found")
                    error_count += 1
                    continue

            # Read Solidity code
            with open(sol_file, 'r', encoding='utf-8') as f:
                solidity_code = f.read()

            # Extract state variables from AST if available
            state_variables = set()
            if 'contracts' in ast_data:
                for contract in ast_data['contracts'].values():
                    if 'state_variables' in contract:
                        state_variables.update(contract['state_variables'].keys())

            # Analyze sinks
            sinks_analysis = identifier.analyze_sinks_in_code(solidity_code, state_variables)

            # Update AST using the dedicated method
            updated_ast = identifier.update_ast_with_sinks(ast_data, sinks_analysis)

            # Save updated AST
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(updated_ast, f, indent=2)

            logger.info(f"[OK] Successfully updated {json_file}")
            logger.info(f"  - Total sinks: {sinks_analysis['summary']['totalSinks']}")
            logger.info(f"  - Critical: {sinks_analysis['summary']['criticalRiskSinks']}")

            success_count += 1

        except Exception as e:
            logger.error(f"[ERROR] Error processing {json_file}: {str(e)}")
            error_count += 1

    logger.info(f"\n[OK] Sink analysis completed!")
    logger.info(f"Success: {success_count}, Errors: {error_count}")


def main():
    """Main function"""
    json_dir = "contract_ast"
    source_dir = "smartcontract"

    update_json_with_sinks(json_dir, source_dir)


if __name__ == "__main__":
    main()
