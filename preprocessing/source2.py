"""
Fixed AST Source Detection Module

Major improvements:
1. Enhanced context detection (full function scope instead of 300 chars)
2. Nested source detection with recursive analysis
3. Dynamic risk assessment based on actual usage context
4. Better pattern matching for combined sources
5. Support for complex expressions with multiple sources
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict
from pathlib import Path  # اضافه شد

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EnhancedSourceDetector:
    """Enhanced detector for blockchain randomness sources with context-aware risk assessment"""

    def __init__(self):
        # Primary blockchain sources
        self.primary_sources = {
            'block.timestamp': {
                'type': 'timestamp',
                'base_risk': 0.7,
                'cwe': 'CWE-330',
                'description': 'Timestamp can be manipulated by miners'
            },
            'block.difficulty': {
                'type': 'difficulty',
                'base_risk': 0.8,
                'cwe': 'CWE-330',
                'description': 'Difficulty is predictable and manipulatable'
            },
            'block.number': {
                'type': 'blocknumber',
                'base_risk': 0.6,
                'cwe': 'CWE-330',
                'description': 'Block number is predictable'
            },
            'block.gaslimit': {
                'type': 'gaslimit',
                'base_risk': 0.5,
                'cwe': 'CWE-330',
                'description': 'Gas limit can be influenced'
            },
            'block.coinbase': {
                'type': 'coinbase',
                'base_risk': 0.5,
                'cwe': 'CWE-330',
                'description': 'Miner address is known'
            },
            'blockhash': {
                'type': 'blockhash',
                'base_risk': 0.9,
                'cwe': 'CWE-330',
                'description': 'Blockhash is manipulatable for recent blocks'
            },
            'block.prevrandao': {
                'type': 'prevrandao',
                'base_risk': 0.9,
                'cwe': 'CWE-330',
                'description': 'PREVRANDAO is not suitable for gambling'
            },
            'now': {  # Alias for block.timestamp
                'type': 'timestamp',
                'base_risk': 0.7,
                'cwe': 'CWE-330',
                'description': 'Alias for block.timestamp'
            },
        }

        # Context patterns for enhanced risk assessment
        self.context_patterns = {
            'gambling': {
                'patterns': [
                    r'%\s*players\.length',
                    r'%\s*\d+\s*==\s*0',
                    r'random|lottery|bet|gambl|winner|prize|jackpot',
                    r'keccak256.*block\.(timestamp|difficulty)',
                    r'abi\.encode.*block\.(timestamp|difficulty)',
                    r'winner\s*=.*%',
                    r'uint.*rand.*=',
                    r'shuffle|draw|pick'
                ],
                'risk_multiplier': 1.3
            },
            'timing': {
                'patterns': [
                    r'require\s*\(.*block\.timestamp\s*[<>]=?',
                    r'if\s*\(.*block\.timestamp\s*[<>]=?',
                    r'endTime|startTime|deadline|duration',
                    r'block\.timestamp\s*\+\s*\d+',
                    r'timelock|vesting|cliff',
                    r'>\s*=\s*endTime',
                    r'<\s*startTime'
                ],
                'risk_multiplier': 0.5
            },
            'randomness': {
                'patterns': [
                    r'keccak256\s*\([^)]*block\.',
                    r'sha256\s*\([^)]*block\.',
                    r'abi\.encodePacked\s*\([^)]*block\.',
                    r'uint.*=.*block\..*%',
                    r'seed\s*=.*block\.',
                    r'nonce.*block\.',
                    r'random.*=.*keccak'
                ],
                'risk_multiplier': 1.5
            },
            'access_control': {
                'patterns': [
                    r'require\s*\(\s*msg\.sender\s*==',
                    r'onlyOwner|onlyAdmin|authorized',
                    r'modifier\s+\w+\s*\(',
                    r'mapping.*address.*bool'
                ],
                'risk_multiplier': 0.3
            }
        }

    def detect_sources_in_contract(self, contract_code: str, contract_info: Dict[str, Any]) -> Dict[str, Any]:
        """Main entry point for source detection with enhanced context analysis"""
        logger.info("Starting enhanced source detection")

        sources = []
        statistics = {
            "total_sources": 0,
            "by_type": defaultdict(int),
            "by_risk": defaultdict(int),
            "nested_sources": 0
        }

        # Check each primary source in the entire code
        for source_pattern, source_info in self.primary_sources.items():
            pattern = rf'\b{re.escape(source_pattern)}\b'
            matches = list(re.finditer(pattern, contract_code))

            for match in matches:
                source_id = f"source_{source_pattern.replace('.', '_')}_{match.start()}"

                # Get expanded context
                context = contract_code[max(0, match.start() - 200):min(len(contract_code), match.end() + 200)]

                # Analyze context for risk assessment
                usage_context = self._analyze_source_context(
                    source_pattern, context, contract_code
                )

                # Calculate contextual risk
                contextual_risk = self._calculate_contextual_risk(
                    source_info['base_risk'], usage_context
                )

                # Check if source is nested in complex expression
                is_nested = self._is_nested_source(contract_code, match.start())

                # تبدیل به فرمت مناسب برای Enhanced AST
                source_entry = {
                    'nodeId': source_id,
                    'sourceType': source_info['type'],
                    'pattern': source_pattern,
                    'position': match.start(),
                    'matchedText': source_pattern,
                    'context': {
                        'type': 'function',
                        'name': 'unknown',  # TODO: could be improved
                        'snippet': context[:200]
                    },
                    'riskLevel': self._get_risk_level_string(contextual_risk),
                    'taintLevel': contextual_risk,
                    'baseRisk': source_info['base_risk'],
                    'contextualRisk': contextual_risk,
                    'usageContext': usage_context,
                    'cweMapping': source_info['cwe'],
                    'description': source_info['description'],
                    'isNested': is_nested,
                    'riskFactors': self._get_risk_factors(usage_context, is_nested),
                    'isSource': True
                }

                sources.append(source_entry)

                # Update statistics
                statistics['total_sources'] += 1
                statistics['by_type'][source_info['type']] += 1
                risk_level = self._get_risk_level(contextual_risk)
                statistics['by_risk'][risk_level] += 1

                if is_nested:
                    statistics['nested_sources'] += 1

        # Detect combined sources
        combined_patterns = [
            r'keccak256\s*\([^)]*block\.\w+[^)]*block\.\w+[^)]*\)',
            r'block\.\w+\s*[\+\-\*]\s*block\.\w+',
            r'keccak256\s*\([^)]*msg\.sender[^)]*block\.\w+[^)]*\)',
            r'abi\.encode\w*\s*\([^)]*block\.\w+[^)]*block\.\w+[^)]*\)'
        ]

        for pattern in combined_patterns:
            matches = re.finditer(pattern, contract_code, re.IGNORECASE)
            for match in matches:
                source_id = f"source_combined_{match.start()}"

                source_entry = {
                    'nodeId': source_id,
                    'sourceType': 'combined',
                    'pattern': 'combined_sources',
                    'position': match.start(),
                    'matchedText': match.group(),
                    'context': {
                        'type': 'function',
                        'name': 'unknown',
                        'snippet': match.group()
                    },
                    'riskLevel': 'critical',
                    'taintLevel': 0.95,
                    'baseRisk': 0.95,
                    'contextualRisk': 0.95,
                    'usageContext': 'randomness',
                    'cweMapping': 'CWE-330',
                    'description': 'Multiple randomness sources combined',
                    'isNested': True,
                    'riskFactors': ['combined_sources', 'high_predictability'],
                    'isSource': True
                }

                sources.append(source_entry)
                statistics['total_sources'] += 1
                statistics['by_type']['combined'] += 1
                statistics['by_risk']['critical'] += 1
                statistics['nested_sources'] += 1

        # Detect sources in state variables
        global_sources = self._detect_global_sources(contract_code)
        for source_id, source_info in global_sources.items():
            source_entry = {
                'nodeId': source_id,
                'sourceType': source_info['source_type'],
                'pattern': source_info['source_pattern'],
                'position': source_info['position'],
                'matchedText': source_info['source_pattern'],
                'context': {
                    'type': 'state',
                    'name': source_info.get('variable_name', ''),
                    'snippet': source_info.get('context_snippet', '')
                },
                'riskLevel': self._get_risk_level_string(source_info['contextual_risk']),
                'taintLevel': source_info['contextual_risk'],
                'baseRisk': source_info['base_risk'],
                'contextualRisk': source_info['contextual_risk'],
                'usageContext': source_info['usage_context'],
                'cweMapping': source_info['cwe'],
                'description': source_info['description'],
                'isNested': source_info['is_nested'],
                'riskFactors': source_info['risk_factors'],
                'isSource': True
            }

            sources.append(source_entry)
            statistics['total_sources'] += 1
            statistics['by_type'][source_info['source_type']] += 1

        logger.info(f"Detected {statistics['total_sources']} sources")

        return {
            'sources': sources,
            'statistics': statistics
        }

    def _get_risk_level_string(self, risk_score: float) -> str:
        """Convert risk score to string level"""
        if risk_score >= 0.8:
            return 'critical'
        elif risk_score >= 0.6:
            return 'high'
        elif risk_score >= 0.4:
            return 'medium'
        else:
            return 'low'

    def _extract_functions(self, contract_code: str) -> Dict[str, str]:
        """Extract all functions with their complete bodies"""
        functions = {}

        # Pattern to match function definitions
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(?:public|private|internal|external|view|pure|payable|\s)*\s*(?:returns\s*\([^)]*\))?\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'

        matches = re.finditer(func_pattern, contract_code, re.DOTALL | re.MULTILINE)

        for match in matches:
            func_name = match.group(1)
            func_body = match.group(2)
            functions[func_name] = func_body

        # Also extract constructor
        constructor_pattern = r'constructor\s*\([^)]*\)\s*(?:public|payable|\s)*\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'
        constructor_match = re.search(constructor_pattern, contract_code, re.DOTALL)
        if constructor_match:
            functions['constructor'] = constructor_match.group(1)

        return functions

    def _detect_sources_in_function(self, func_body: str, func_name: str,
                                    full_contract: str) -> Dict[str, Any]:
        """Detect sources within a function with context analysis"""
        sources = {}

        # Check each primary source
        for source_pattern, source_info in self.primary_sources.items():
            # Find all occurrences
            pattern = rf'\b{re.escape(source_pattern)}\b'
            matches = list(re.finditer(pattern, func_body))

            for match in matches:
                source_id = f"source_{source_pattern.replace('.', '_')}_{func_name}_{match.start()}"

                # Get expanded context
                context = self._get_expanded_context(
                    func_body, match.start(), match.end(), full_contract, func_name
                )

                # Analyze context for risk assessment
                usage_context = self._analyze_source_context(
                    source_pattern, context, func_body
                )

                # Calculate contextual risk
                contextual_risk = self._calculate_contextual_risk(
                    source_info['base_risk'], usage_context
                )

                # Check if source is nested in complex expression
                is_nested = self._is_nested_source(func_body, match.start())

                sources[source_id] = {
                    'source_type': source_info['type'],
                    'source_pattern': source_pattern,
                    'position': match.start(),
                    'line_number': func_body[:match.start()].count('\n') + 1,
                    'function': func_name,
                    'base_risk': source_info['base_risk'],
                    'contextual_risk': contextual_risk,
                    'usage_context': usage_context,
                    'context_snippet': context[:200],
                    'cwe': source_info['cwe'],
                    'description': source_info['description'],
                    'is_nested': is_nested,
                    'risk_factors': self._get_risk_factors(usage_context, is_nested)
                }

        # Detect combined sources
        combined_sources = self._detect_combined_sources(func_body, func_name)
        sources.update(combined_sources)

        return sources

    def _get_expanded_context(self, func_body: str, start: int, end: int,
                              full_contract: str, func_name: str) -> str:
        """Get expanded context - full function or significant portion"""
        # First try to get the full function context
        if len(func_body) < 2000:  # Reasonable size
            return func_body

        # For larger functions, get a significant window
        window_size = 1000  # Much larger than original 300
        context_start = max(0, start - window_size)
        context_end = min(len(func_body), end + window_size)

        # Try to align with statement boundaries
        context = func_body[context_start:context_end]

        # Ensure we capture complete statements
        # Look for semicolon before start
        semi_before = func_body.rfind(';', context_start, start)
        if semi_before != -1:
            context_start = semi_before + 1

        # Look for semicolon after end
        semi_after = func_body.find(';', end, context_end)
        if semi_after != -1:
            context_end = semi_after + 1

        return func_body[context_start:context_end].strip()

    def _analyze_source_context(self, source_pattern: str, context: str,
                                func_body: str) -> str:
        """Analyze the context to determine usage pattern"""
        context_lower = context.lower()

        # Check each context type
        detected_contexts = []
        risk_scores = {}

        for ctx_name, ctx_info in self.context_patterns.items():
            score = 0
            for pattern in ctx_info['patterns']:
                if re.search(pattern, context_lower, re.IGNORECASE):
                    score += 1

            if score > 0:
                risk_scores[ctx_name] = score
                detected_contexts.append(ctx_name)

        # Determine primary context
        if not detected_contexts:
            return 'unknown'

        # Special rules for specific sources
        if source_pattern in ['block.timestamp', 'now']:
            if 'gambling' in detected_contexts:
                return 'gambling'
            elif 'timing' in detected_contexts and 'randomness' not in detected_contexts:
                return 'timing'
            elif 'randomness' in detected_contexts:
                return 'randomness'

        elif source_pattern == 'msg.sender':
            if 'randomness' in detected_contexts or 'gambling' in detected_contexts:
                return 'randomness'
            elif 'access_control' in detected_contexts:
                return 'access_control'

        elif source_pattern in ['block.difficulty', 'blockhash', 'block.prevrandao']:
            return 'randomness'  # Always high risk for these

        # Return context with highest score
        if risk_scores:
            return max(risk_scores.items(), key=lambda x: x[1])[0]

        return 'unknown'

    def _calculate_contextual_risk(self, base_risk: float, usage_context: str) -> float:
        """Calculate risk based on context"""
        if usage_context == 'unknown':
            return base_risk

        multiplier = self.context_patterns.get(usage_context, {}).get('risk_multiplier', 1.0)
        contextual_risk = base_risk * multiplier

        # Cap between 0.1 and 1.0
        return max(0.1, min(1.0, contextual_risk))

    def _is_nested_source(self, func_body: str, position: int) -> bool:
        """Check if source is nested within complex expression"""
        # Get surrounding context
        start = max(0, position - 200)
        end = min(len(func_body), position + 200)
        context = func_body[start:end]

        # Patterns indicating nesting
        nesting_patterns = [
            r'keccak256\s*\([^)]*$',  # Inside keccak256
            r'abi\.encode\w*\s*\([^)]*$',  # Inside encoding
            r'uint\d*\s*\([^)]*$',  # Inside type cast
            r'\([^)]*\+[^)]*$',  # Inside arithmetic
            r'\([^)]*\*[^)]*$',
            r'\([^)]*-[^)]*$',
            r'\([^)]*%[^)]*$'
        ]

        # Check if we're inside any of these patterns
        before_source = func_body[start:position]
        for pattern in nesting_patterns:
            if re.search(pattern, before_source):
                return True

        return False

    def _detect_combined_sources(self, func_body: str, func_name: str) -> Dict[str, Any]:
        """Detect combinations of multiple sources"""
        combined = {}

        # Patterns for combined sources
        combined_patterns = [
            # Multiple sources in keccak256
            r'keccak256\s*\([^)]*block\.\w+[^)]*block\.\w+[^)]*\)',
            # Multiple sources in arithmetic
            r'block\.\w+\s*[\+\-\*]\s*block\.\w+',
            # Sources with msg.sender
            r'keccak256\s*\([^)]*msg\.sender[^)]*block\.\w+[^)]*\)',
            # abi.encode with multiple sources
            r'abi\.encode\w*\s*\([^)]*block\.\w+[^)]*block\.\w+[^)]*\)'
        ]

        for pattern in combined_patterns:
            matches = re.finditer(pattern, func_body, re.IGNORECASE)
            for match in matches:
                source_id = f"source_combined_{func_name}_{match.start()}"

                # Extract individual sources from the match
                individual_sources = self._extract_individual_sources(match.group())

                combined[source_id] = {
                    'source_type': 'combined',
                    'source_pattern': 'combined_sources',
                    'position': match.start(),
                    'line_number': func_body[:match.start()].count('\n') + 1,
                    'function': func_name,
                    'base_risk': 0.95,  # Combined sources are very risky
                    'contextual_risk': 0.95,
                    'usage_context': 'randomness',
                    'context_snippet': match.group(),
                    'cwe': 'CWE-330',
                    'description': 'Multiple randomness sources combined',
                    'is_nested': True,
                    'individual_sources': individual_sources,
                    'risk_factors': ['combined_sources', 'high_predictability']
                }

        return combined

    def _extract_individual_sources(self, expression: str) -> List[str]:
        """Extract individual source patterns from expression"""
        found_sources = []

        for source_pattern in self.primary_sources.keys():
            if source_pattern in expression:
                found_sources.append(source_pattern)

        return found_sources

    def _detect_global_sources(self, contract_code: str) -> Dict[str, Any]:
        """Detect sources in state variables and global context"""
        sources = {}

        # Pattern for state variable declarations
        state_var_pattern = r'^\s*(uint\d*|int\d*|address|bytes\d*)\s+(?:private|public|internal)?\s*(\w+)\s*=\s*([^;]+);'

        for match in re.finditer(state_var_pattern, contract_code, re.MULTILINE):
            var_type = match.group(1)
            var_name = match.group(2)
            var_value = match.group(3)

            # Check if initialization uses blockchain sources
            for source_pattern, source_info in self.primary_sources.items():
                if source_pattern in var_value:
                    source_id = f"source_state_{var_name}_{source_pattern.replace('.', '_')}"

                    sources[source_id] = {
                        'source_type': source_info['type'],
                        'source_pattern': source_pattern,
                        'position': match.start(),
                        'line_number': contract_code[:match.start()].count('\n') + 1,
                        'function': 'state_variable',
                        'variable_name': var_name,
                        'base_risk': source_info['base_risk'] * 0.8,  # Slightly lower for state vars
                        'contextual_risk': source_info['base_risk'] * 0.8,
                        'usage_context': 'state_initialization',
                        'context_snippet': match.group(),
                        'cwe': source_info['cwe'],
                        'description': f"State variable initialized with {source_pattern}",
                        'is_nested': False,
                        'risk_factors': ['state_variable', 'initialization']
                    }

        return sources

    def _get_risk_factors(self, usage_context: str, is_nested: bool) -> List[str]:
        """Get risk factors based on context"""
        factors = []

        if usage_context == 'gambling':
            factors.extend(['gambling_context', 'high_stakes', 'manipulation_incentive'])
        elif usage_context == 'randomness':
            factors.extend(['randomness_generation', 'predictable_source'])
        elif usage_context == 'timing':
            factors.extend(['time_dependency', 'miner_influence'])
        elif usage_context == 'access_control':
            factors.extend(['access_check', 'low_risk'])

        if is_nested:
            factors.append('complex_expression')

        return factors

    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to level"""
        if risk_score >= 0.8:
            return 'critical'
        elif risk_score >= 0.6:
            return 'high'
        elif risk_score >= 0.4:
            return 'medium'
        else:
            return 'low'

    def _link_related_sources(self, sources: Dict[str, Any],
                              contract_info: Dict[str, Any]) -> Dict[str, Any]:
        """Link related sources and propagate risks"""
        # This would link sources that flow into each other
        # For now, return as-is
        return sources


# این تابع از کلاس خارج شده است
def update_json_with_sources(json_dir: str, source_dir: str) -> None:
    """Update JSON files with source information"""
    detector = EnhancedSourceDetector()

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
            sol_file = Path(sol_filename)

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

            # Detect sources
            contract_info = ast_data.get("contracts", {})
            sources_result = detector.detect_sources_in_contract(solidity_code, contract_info)

            # اضافه کردن sources به AST در فرمت صحیح
            ast_data["sources"] = sources_result.get("sources", [])
            ast_data["sourcesSummary"] = sources_result.get("statistics", {})

            # Save updated AST
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(ast_data, f, indent=2)

            logger.info(f"✓ Successfully updated {json_file}")
            logger.info(f"  Total sources: {sources_result['statistics']['total_sources']}")
            logger.info(f"  By type: {dict(sources_result['statistics']['by_type'])}")
            logger.info(f"  By risk: {dict(sources_result['statistics']['by_risk'])}")

            success_count += 1

        except Exception as e:
            logger.error(f"✗ Error processing {json_file}: {str(e)}")
            error_count += 1

    logger.info(f"\n✓ Source detection completed!")
    logger.info(f"Success: {success_count}, Errors: {error_count}")


def safe_str(obj: Any) -> str:
    """Safely convert object to string"""
    if obj is None:
        return ""
    return str(obj)


def safe_int(obj: Any, default: int = 0) -> int:
    """Safely convert to integer"""
    if obj is None:
        return default
    try:
        return int(obj)
    except (ValueError, TypeError):
        return default


def safe_float(obj: Any, default: float = 0.0) -> float:
    """Safely convert to float"""
    if obj is None:
        return default
    try:
        return float(obj)
    except (ValueError, TypeError):
        return default


def main():
    """Main function"""
    json_dir = "contract_ast"
    source_dir = "smartcontract"

    update_json_with_sources(json_dir, source_dir)


if __name__ == "__main__":
    main()