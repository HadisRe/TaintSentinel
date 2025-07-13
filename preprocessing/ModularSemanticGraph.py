"""
Semantic Graph Builder - بدون Taint Analysis
فقط ساخت گراف و شناسایی sources/sinks
"""

import json
import os
import re
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
import networkx as nx


@dataclass
class SemanticNode:
    """Node with source/sink information"""
    id: str
    node_type: str
    label: str
    function_name: str = ""
    line_start: int = 0
    line_end: int = 0
    is_source: bool = False
    is_sink: bool = False
    source_types: List[str] = field(default_factory=list)
    sink_types: List[str] = field(default_factory=list)
    code_snippet: str = ""

    # Variables for future taint analysis
    defined_vars: Set[str] = field(default_factory=set)
    used_vars: Set[str] = field(default_factory=set)

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.node_type,
            "label": self.label,
            "function": self.function_name,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "is_source": self.is_source,
            "is_sink": self.is_sink,
            "sources": self.source_types,
            "sinks": self.sink_types,
            "code_snippet": self.code_snippet,
            "defined_vars": list(self.defined_vars),
            "used_vars": list(self.used_vars)
        }


class SemanticGraphBuilder:
    """Builder که فقط گراف می‌سازد بدون taint analysis"""

    def __init__(self, contract_name: str, contract_path: str = "contract_ast",
                 source_path: str = "smartcontract", debug: bool = True):
        self.contract_name = contract_name
        self.contract_path = contract_path  # برای AST و CFG
        self.source_path = source_path  # برای فایل‌های .sol
        self.debug = debug

        # Graph components
        self.nodes: Dict[str, SemanticNode] = {}
        self.edges: List[Dict[str, str]] = []

        # Source code analysis
        self.source_code = ""
        self.functions = {}
        self.ast_data = {}

        # Variable definitions for future taint analysis
        self.var_definitions = {}  # var -> node where defined
        self.var_dependencies = defaultdict(set)  # var -> set of vars it depends on

        # Counters
        self.node_counter = 0

        # Track marked nodes to prevent over-marking
        self.marked_source_nodes = set()
        self.marked_sink_nodes = set()
        self.state_variables = {}

    def build_graph(self):
        """مراحل اصلی ساخت گراف"""
        print(f"\n{'=' * 80}")
        print(f" Building Semantic Graph for: {self.contract_name}")
        print('=' * 80)

        # Step 1: Load source code and AST
        if not self._step1_load_data():
            return False

        # Step 2: Parse functions from source code
        if not self._step2_parse_functions():
            return False

        # Step 3: Create nodes from code structure
        if not self._step3_create_nodes():
            return False

        # Step 4: Extract variable definitions and uses
        if not self._step4_extract_variables():
            return False

        # Step 5: Mark sources using AST
        if not self._step5_mark_sources():
            return False

        # Step 6: Mark sinks using AST
        if not self._step6_mark_sinks():
            return False

        # Step 7: Create edges
        if not self._step7_create_edges():
            return False

        # Step 8: Save results
        self._step8_save_results()

        return True

    def _step1_load_data(self) -> bool:
        """Load source code and AST"""
        print("\nSTEP 1: Loading data...")

        # Load AST first - از contract_path
        ast_file = os.path.join(self.contract_path, f"{self.contract_name}_ast.json")
        if os.path.exists(ast_file):
            with open(ast_file, 'r', encoding='utf-8') as f:
                self.ast_data = json.load(f)
            print(f"    Loaded AST data")
        else:
            print(f"   AST file not found!")
            return False

        # Try to load source code - از source_path
        possible_names = [
            f"{self.contract_name}.sol",
            f"{self.contract_name.replace('mint', 'Mint')}.sol",
            f"{self.contract_name.replace('Mint', 'mint')}.sol",
            f"{self.contract_name.upper()}.sol",
            f"{self.contract_name.lower()}.sol"
        ]

        source_loaded = False
        for filename in possible_names:
            sol_file = os.path.join(self.source_path, filename)  # تغییر مسیر به source_path
            if os.path.exists(sol_file):
                with open(sol_file, 'r', encoding='utf-8') as f:
                    self.source_code = f.read()
                print(f"   Loaded source code from: {filename}")
                source_loaded = True
                break

        if not source_loaded:
            # Extract from AST if possible
            self.source_code = self._extract_code_from_ast()
            print(f"   Using code extracted from AST (limited)")

        return True

    def _extract_code_from_ast(self) -> str:
        """Extract code snippets from AST"""
        code_parts = []

        def extract_code(obj):
            if isinstance(obj, dict):
                if 'codeSnippet' in obj:
                    code_parts.append(obj['codeSnippet'])
                elif 'code' in obj:
                    code_parts.append(obj['code'])

                for value in obj.values():
                    extract_code(value)
            elif isinstance(obj, list):
                for item in obj:
                    extract_code(item)

        extract_code(self.ast_data)
        return '\n'.join(code_parts)

    def _step2_parse_functions(self) -> bool:
        """Parse functions from source code or AST"""
        print("\n STEP 2: Parsing functions...")

        # Try regex first if we have good source code
        if len(self.source_code) > 100:  # Likely full source
            function_pattern = r'function\s+(\w+)\s*\([^)]*\)[^{]*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'
            matches = list(re.finditer(function_pattern, self.source_code, re.DOTALL))

            if matches:
                for match in matches:
                    func_name = match.group(1)
                    func_body = match.group(2)
                    func_start = match.start()
                    func_end = match.end()

                    line_start = self.source_code[:func_start].count('\n') + 1
                    line_end = self.source_code[:func_end].count('\n') + 1

                    self.functions[func_name] = {
                        'name': func_name,
                        'body': func_body,
                        'start': func_start,
                        'end': func_end,
                        'line_start': line_start,
                        'line_end': line_end
                    }

        # If no functions found, extract from AST
        if not self.functions:
            self._extract_functions_from_ast()

        print(f"   Found {len(self.functions)} functions")
        return True

    def _extract_functions_from_ast(self):
        """Extract function info from AST"""
        if 'contracts' in self.ast_data:
            for contract_name, contract_data in self.ast_data.get('contracts', {}).items():
                if 'functions' in contract_data:
                    for func_name, func_data in contract_data['functions'].items():
                        self.functions[func_name] = {
                            'name': func_name,
                            'body': '',
                            'start': 0,
                            'end': 0,
                            'line_start': 0,
                            'line_end': 0
                        }

    def _step3_create_nodes(self) -> bool:
        """Create nodes from code structure"""
        print("\n STEP 3: Creating nodes...")

        # Create entry node
        entry_node = self._create_node("entry", "Contract Entry", "")

        # Create nodes for each function
        for func_name in self.functions:
            self._create_function_nodes(func_name)

        # NEW: Create nodes for state variables with initialization
        self._create_state_variable_nodes()

        # NEW: Create nodes for fallback function if not already created
        self._create_fallback_nodes()

        # If no functions found, create nodes from AST patterns
        if len(self.nodes) < 5:
            self._create_nodes_from_ast_patterns()

        print(f"    Created {len(self.nodes)} nodes")
        return True

    def _create_state_variable_nodes(self):
        """Create nodes for state variable declarations with initialization"""
        if not self.source_code or len(self.source_code) < 100:
            return

        print("  Creating nodes for state variables...")

        # Pattern for state variable declarations with initialization
        state_var_pattern = r'\s*(uint\d*|int\d*|address|bytes\d*|bool|string|mapping)\s+(?:private|public|internal|constant)?\s*(\w+)\s*=\s*([^;]+);'
        matches = list(re.finditer(state_var_pattern, self.source_code, re.MULTILINE))

        for match in matches:
            var_type = match.group(1)
            var_name = match.group(2)
            var_init = match.group(3)

            # Check if initialization contains blockchain sources
            contains_source = any(source in var_init for source in [
                'block.timestamp', 'block.number', 'block.difficulty',
                'block.coinbase', 'blockhash', 'now', 'tx.origin',
                'keccak256', 'sha256', 'sha3'
            ])

            if contains_source:
                # Create node for this state variable
                line_num = self.source_code[:match.start()].count('\n') + 1

                node = self._create_node(
                    "state_initialization",
                    f"{var_name} = {var_init[:50]}...",
                    "state_variable",
                    line_num,
                    match.group(0)
                )
                # ذخیره نام متغیر و node_id آن
                self.state_variables[var_name] = node.id

                # Connect to entry node
                entry_nodes = [n for n in self.nodes.values() if n.node_type == 'entry']
                if entry_nodes:
                    self.edges.append({
                        'source': entry_nodes[0].id,
                        'target': node.id,
                        'type': 'initialization'
                    })

                print(f"    Created node for state variable: {var_name}")

    def _create_fallback_nodes(self):
        """Create nodes for fallback functions"""
        if not self.source_code or len(self.source_code) < 100:
            return

        print("  Looking for fallback functions...")

        # Pattern for fallback function
        fallback_pattern = r'function\s*\(\s*\)\s*(?:payable\s*)?(?:public\s*)?(?:external\s*)?\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'

        matches = list(re.finditer(fallback_pattern, self.source_code, re.DOTALL))

        for match in matches:
            func_body = match.group(1)
            func_start = match.start()
            func_end = match.end()

            line_start = self.source_code[:func_start].count('\n') + 1
            line_end = self.source_code[:func_end].count('\n') + 1

            # Add to functions dict if not already there
            if 'fallback' not in self.functions:
                self.functions['fallback'] = {
                    'name': 'fallback',
                    'body': func_body,
                    'start': func_start,
                    'end': func_end,
                    'line_start': line_start,
                    'line_end': line_end
                }

                # Create nodes for fallback
                self._create_function_nodes('fallback')
                print(f"  Created nodes for fallback function")

    # Update _step2_parse_functions to include fallback pattern
    def _step2_parse_functions(self) -> bool:
        """Parse functions from source code or AST"""
        print("\n STEP 2: Parsing functions...")

        # Try regex first if we have good source code
        if len(self.source_code) > 100:  # Likely full source
            # Regular functions
            function_pattern = r'function\s+(\w+)\s*\([^)]*\)[^{]*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'
            matches = list(re.finditer(function_pattern, self.source_code, re.DOTALL))

            if matches:
                for match in matches:
                    func_name = match.group(1)
                    func_body = match.group(2)
                    func_start = match.start()
                    func_end = match.end()

                    line_start = self.source_code[:func_start].count('\n') + 1
                    line_end = self.source_code[:func_end].count('\n') + 1

                    self.functions[func_name] = {
                        'name': func_name,
                        'body': func_body,
                        'start': func_start,
                        'end': func_end,
                        'line_start': line_start,
                        'line_end': line_end
                    }

            # NEW: Also parse fallback functions
            fallback_pattern = r'function\s*\(\s*\)\s*(?:payable\s*)?(?:public\s*)?(?:external\s*)?\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'
            fallback_matches = list(re.finditer(fallback_pattern, self.source_code, re.DOTALL))

            for match in fallback_matches:
                func_body = match.group(1)
                func_start = match.start()
                func_end = match.end()

                line_start = self.source_code[:func_start].count('\n') + 1
                line_end = self.source_code[:func_end].count('\n') + 1

                self.functions['fallback'] = {
                    'name': 'fallback',
                    'body': func_body,
                    'start': func_start,
                    'end': func_end,
                    'line_start': line_start,
                    'line_end': line_end
                }

        # If no functions found, extract from AST
        if not self.functions:
            self._extract_functions_from_ast()

        print(f"    Found {len(self.functions)} functions")
        return True
    def _create_node(self, node_type: str, label: str, function: str,
                     line: int = 0, code_snippet: str = "") -> SemanticNode:
        """Create a new node"""
        node_id = f"N{self.node_counter}"
        self.node_counter += 1

        node = SemanticNode(
            id=node_id,
            node_type=node_type,
            label=label[:100],
            function_name=function,
            line_start=line,
            code_snippet=code_snippet
        )

        self.nodes[node_id] = node
        return node

    def _create_function_nodes(self, func_name: str):
        """Create nodes for a function"""
        func_info = self.functions[func_name]

        # Function entry
        func_entry = self._create_node(
            "function_entry",
            f"{func_name}()",
            func_name,
            func_info['line_start']
        )
        # اتصال function entry به contract entry
        entry_nodes = [n for n in self.nodes.values() if n.node_type == 'entry']
        if entry_nodes:
            self.edges.append({
                'source': entry_nodes[0].id,
                'target': func_entry.id,
                'type': 'function_call'
            })

        # Parse function body if available
        if func_info['body']:
            self._parse_function_body(func_name, func_info['body'], func_entry)
        else:
            # Create basic flow
            func_exit = self._create_node(
                "function_exit",
                f"exit {func_name}",
                func_name,
                func_info['line_end']
            )

            self.edges.append({
                'source': func_entry.id,
                'target': func_exit.id,
                'type': 'control_flow'
            })

    def _parse_function_body(self, func_name: str, body: str, entry_node: SemanticNode):
        """Parse function body and create nodes"""
        # Important statement patterns
        patterns = [
            (r'require\s*\([^;]+\);', 'require'),
            (r'assert\s*\([^;]+\);', 'assert'),
            (r'if\s*\([^)]+\)', 'condition'),
            (r'(\w+)\s*=\s*([^;]+);', 'assignment'),
            (r'keccak256\s*\([^)]+\)', 'keccak'),
            (r'sha256\s*\([^)]+\)', 'sha256'),
            (r'sha3\s*\([^)]+\)', 'sha3'),
            (r'\.transfer\s*\([^)]+\)', 'transfer'),
            (r'\.send\s*\([^)]+\)', 'send'),
            (r'return\s+([^;]+);', 'return')
        ]

        statements = []

        # Find all statements
        for pattern, stmt_type in patterns:
            for match in re.finditer(pattern, body):
                statements.append({
                    'type': stmt_type,
                    'text': match.group(0),
                    'start': match.start(),
                    'match': match
                })

        # Sort by position
        statements.sort(key=lambda x: x['start'])

        # Create nodes and edges
        last_node = entry_node

        for stmt in statements:
            # Create node
            node = self._create_node(
                stmt['type'],
                stmt['text'][:80],
                func_name,
                0,
                stmt['text']
            )

            # Create edge from last node
            self.edges.append({
                'source': last_node.id,
                'target': node.id,
                'type': 'control_flow'
            })

            last_node = node

        # Function exit
        func_exit = self._create_node(
            "function_exit",
            f"exit {func_name}",
            func_name
        )

        self.edges.append({
            'source': last_node.id,
            'target': func_exit.id,
            'type': 'control_flow'
        })

    def _create_nodes_from_ast_patterns(self):
        """Create nodes from AST when function parsing fails"""
        print("  Creating nodes from AST patterns...")

        # Don't create nodes directly from sources/sinks
        # Instead, create basic structure that will be marked later
        node_count = len(self.nodes)

        # Create some basic nodes if we have code snippets
        code_snippets = []

        def find_snippets(obj):
            if isinstance(obj, dict):
                if 'codeSnippet' in obj and len(obj['codeSnippet']) > 10:
                    code_snippets.append(obj['codeSnippet'])
            elif isinstance(obj, list):
                for item in obj:
                    find_snippets(item)

        find_snippets(self.ast_data)

        # Create nodes for unique code snippets
        seen = set()
        for snippet in code_snippets[:20]:  # Limit to prevent too many nodes
            if snippet not in seen:
                seen.add(snippet)
                self._create_node(
                    "statement",
                    snippet[:80],
                    "unknown",
                    0,
                    snippet
                )

    def _step4_extract_variables(self) -> bool:
        """Extract variable definitions and uses for future taint analysis"""
        print("\n STEP 4: Extracting variable information...")

        for node in self.nodes.values():
            if node.code_snippet:
                # Extract defined variables (left side of assignment)
                assignment_pattern = r'(\w+)\s*=\s*(.+)'
                match = re.search(assignment_pattern, node.code_snippet)
                if match:
                    var_name = match.group(1)
                    rhs = match.group(2)

                    # Skip type declarations (قانون کلی)
                    if not re.match(r'^(uint|int|address|bool|string|bytes)', var_name):
                        node.defined_vars.add(var_name)
                        self.var_definitions[var_name] = node.id

                        # Extract all variables from RHS
                        used_vars = self._extract_variables(rhs)
                        node.used_vars.update(used_vars)

                        # اضافه کردن blockchain properties اگر وجود دارند (قانون کلی)
                        blockchain_props = []
                        if 'tx.origin' in rhs:
                            blockchain_props.append('tx.origin')
                        if 'block.timestamp' in rhs or 'now' in rhs:
                            blockchain_props.append('block.timestamp')
                        if 'block.number' in rhs:
                            blockchain_props.append('block.number')
                        if 'gasleft()' in rhs:
                            blockchain_props.append('gasleft')
                        if 'msg.sender' in rhs:
                            blockchain_props.append('msg.sender')
                        if 'msg.value' in rhs:
                            blockchain_props.append('msg.value')
                        if 'block.difficulty' in rhs:
                            blockchain_props.append('block.difficulty')
                        if 'block.coinbase' in rhs:
                            blockchain_props.append('block.coinbase')

                        # ترکیب همه dependencies
                        all_deps = used_vars.union(set(blockchain_props))
                        if all_deps:
                            self.var_dependencies[var_name] = all_deps

                # Extract variables used in other contexts
                else:
                    used_vars = self._extract_variables(node.code_snippet)
                    node.used_vars.update(used_vars)

        print(f"    Found {len(self.var_definitions)} variable definitions")
        print(f"   Found {len(self.var_dependencies)} variable dependencies")

        return True

    def _extract_variables(self, code: str) -> Set[str]:
        """Extract variable names from code snippet"""
        # لیست جامع‌تر keywords و built-ins
        keywords = {'if', 'else', 'return', 'require', 'assert', 'function',
                    'uint', 'int', 'address', 'bool', 'string', 'bytes',
                    'uint8', 'uint16', 'uint32', 'uint64', 'uint128', 'uint256',
                    'int8', 'int16', 'int32', 'int64', 'int128', 'int256',
                    'public', 'private', 'internal', 'external', 'payable',
                    'memory', 'storage', 'calldata', 'view', 'pure',
                    'this', 'msg', 'block', 'tx', 'now', 'true', 'false',
                    'new', 'delete', 'push', 'pop', 'length',
                    # Built-in functions
                    'keccak256', 'sha256', 'sha3', 'abi', 'encodePacked',
                    'encode', 'encodeWithSelector', 'encodeWithSignature',
                    'decode', 'gasleft', 'blockhash', 'require', 'assert',
                    'revert', 'selfdestruct', 'suicide', 'transfer', 'send',
                    'call', 'delegatecall', 'staticcall',
                    # Common property names
                    'sender', 'value', 'data', 'origin', 'gasprice',
                    'timestamp', 'number', 'difficulty', 'coinbase'}

        # قانون کلی: حذف محتوای strings
        code_clean = code
        # حذف double-quoted strings
        code_clean = re.sub(r'"[^"]*"', '""', code_clean)
        # حذف single-quoted strings
        code_clean = re.sub(r"'[^']*'", "''", code_clean)
        # حذف comments
        code_clean = re.sub(r'//.*$', '', code_clean, flags=re.MULTILINE)
        code_clean = re.sub(r'/\*.*?\*/', '', code_clean, flags=re.DOTALL)

        var_pattern = r'\b([a-zA-Z_]\w*)\b'
        variables = set()

        for match in re.finditer(var_pattern, code_clean):
            var = match.group(1)
            if var not in keywords and not var.isupper() and len(var) > 1:
                variables.add(var)

        # قانون کلی: اگر property access هست (مثل msg.sender)، آخرین بخش را حذف کن
        property_pattern = r'\b(?:msg|tx|block|this)\s*\.\s*(\w+)'
        for match in re.finditer(property_pattern, code_clean):
            prop_name = match.group(1)
            variables.discard(prop_name)

        return variables
    def _step5_mark_sources(self) -> bool:
        """Mark sources using improved pattern matching"""
        print("\nSTEP 5: Marking sources...")

        # Get sources from AST
        ast_sources = self.ast_data.get('sources', [])
        if not ast_sources:
            vuln = self.ast_data.get('vulnerability_analysis', {})
            ast_sources = vuln.get('sources', [])

        print(f"  Found {len(ast_sources)} sources in AST")

        # Group sources by type
        sources_by_type = defaultdict(list)
        for source in ast_sources:
            # پشتیبانی از فرمت جدید AST که EnhancedSourceDetector تولید می‌کند
            source_type = source.get('sourceType') or source.get('type', '')
            sources_by_type[source_type].append(source)

        marked_count = 0

        # Process each source type
        for source_type, sources in sources_by_type.items():
            if self.debug:
                print(f"  Processing {len(sources)} {source_type} sources...")

            for source in sources:
                # پشتیبانی از فرمت جدید
                matched_text = source.get('matchedText', '') or source.get('pattern', '')

                # Find best matching node with stricter criteria
                best_node = self._find_node_for_source(matched_text, source_type)

                if best_node and best_node.id not in self.marked_source_nodes:
                    best_node.is_source = True
                    if source_type not in best_node.source_types:
                        best_node.source_types.append(source_type)
                    self.marked_source_nodes.add(best_node.id)
                    marked_count += 1

                    if self.debug:
                        print(f"     Marked {best_node.id}: {best_node.label[:40]}...")

                # اگر node پیدا نشد و source مهم است (state variables مثلاً)
                elif not best_node and source.get('riskLevel') in ['critical', 'high', None]:
                    # ایجاد یک node جدید برای این source
                    node_id = f"SRC_{self.node_counter}"
                    self.node_counter += 1

                    context = source.get('context', {})
                    label = f"{source_type}: {matched_text[:50]}"

                    new_node = SemanticNode(
                        id=node_id,
                        node_type='source_node',
                        label=label,
                        function_name=context.get('name', 'state' if context.get('type') == 'state' else 'unknown'),
                        line_start=0,
                        code_snippet=context.get('snippet', matched_text),
                        is_source=True,
                        source_types=[source_type]
                    )

                    self.nodes[node_id] = new_node
                    self.marked_source_nodes.add(node_id)
                    marked_count += 1

                    # اتصال به entry node
                    entry_nodes = [n for n in self.nodes.values() if n.node_type == 'entry']
                    if entry_nodes:
                        self.edges.append({
                            'source': entry_nodes[0].id,
                            'target': node_id,
                            'type': 'source_flow'
                        })

                    if self.debug:
                        print(f"     Created node {node_id} for: {matched_text[:40]}...")

        # Pattern-based source marking for full source code
        if len(self.source_code) > 100:
            self._mark_sources_by_pattern()

        print(f"    Total marked sources: {len(self.marked_source_nodes)}")

        return True

    def _find_node_for_source(self, matched_text: str, source_type: str) -> Optional[SemanticNode]:
        """Find node for source with strict matching"""
        if not matched_text or len(matched_text) < 3:
            return None

        # Define strict patterns for each source type
        source_patterns = {
            'blocknumber': [r'block\.number', r'block\s*\.\s*number'],
            'blockhash': [r'blockhash\s*\(', r'block\.blockhash'],
            'timestamp': [r'block\.timestamp', r'\bnow\b', r'block\s*\.\s*timestamp'],
            'difficulty': [r'block\.difficulty', r'block\s*\.\s*difficulty'],
            'gaslimit': [r'block\.gaslimit', r'gasleft\s*\(\)'],
            'coinbase': [r'block\.coinbase', r'tx\.origin'],
            'gas': [r'gasleft\s*\(\)', r'msg\.gas']
        }

        patterns = source_patterns.get(source_type, [])

        # Look for nodes that actually contain these patterns
        candidates = []

        for node in self.nodes.values():
            if not node.code_snippet:
                continue

            score = 0

            # Check if node contains the specific pattern
            for pattern in patterns:
                if re.search(pattern, node.code_snippet, re.IGNORECASE):
                    score += 5
                    break

            # Additional scoring
            if node.node_type in ['assignment', 'keccak', 'sha256', 'sha3']:
                score += 2

            # Check if it's actually using the source (not just in a string or comment)
            if score > 0 and not self._is_in_string_or_comment(node.code_snippet, patterns[0] if patterns else ''):
                candidates.append((score, node))

        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            return candidates[0][1]

        return None

    def _is_in_string_or_comment(self, code: str, pattern: str) -> bool:
        """Check if pattern is inside string or comment"""
        # Simple check - could be improved
        if '"' in code or "'" in code or '//' in code or '/*' in code:
            # Remove strings and comments
            cleaned = re.sub(r'"[^"]*"', '', code)
            cleaned = re.sub(r"'[^']*'", '', cleaned)
            cleaned = re.sub(r'//.*$', '', cleaned, flags=re.MULTILINE)
            cleaned = re.sub(r'/\*.*?\*/', '', cleaned, flags=re.DOTALL)

            return pattern not in cleaned

        return False

    def _mark_sources_by_pattern(self):
        """Mark sources by pattern when we have full source code"""
        # Strict patterns for sources
        patterns = {
            r'\bblock\.timestamp\b': 'timestamp',
            r'\bnow\b(?!\w)': 'timestamp',
            r'\bblock\.number\b': 'blocknumber',
            r'\bblockhash\s*\(': 'blockhash',
            r'\bblock\.difficulty\b': 'difficulty',
            r'\bgasleft\s*\(\)': 'gas',
            r'\btx\.origin\b': 'tx_origin',
            r'\bblock\.coinbase\b': 'coinbase'
        }

        for node in self.nodes.values():
            if node.is_source or node.id in self.marked_source_nodes:
                continue

            if not node.code_snippet:
                continue

            for pattern, source_type in patterns.items():
                if re.search(pattern, node.code_snippet) and not self._is_in_string_or_comment(node.code_snippet,
                                                                                               pattern):
                    node.is_source = True
                    if source_type not in node.source_types:
                        node.source_types.append(source_type)
                    self.marked_source_nodes.add(node.id)
                    break

    def _step6_mark_sinks(self) -> bool:
        """Mark sinks with priority for randomness-related sinks"""
        print("\n STEP 6: Marking sinks...")

        # Get sinks from AST
        ast_sinks = self.ast_data.get('sinks', [])
        if not ast_sinks:
            vuln = self.ast_data.get('vulnerability_analysis', {})
            ast_sinks = vuln.get('sinks', [])

        print(f"  Found {len(ast_sinks)} sinks in AST")

        # Priority sink types for bad randomness
        priority_types = ['randomGeneration', 'stateModification', 'valueTransfer']  # اضافه کردن valueTransfer

        # Group sinks by type
        sinks_by_type = defaultdict(list)
        for sink in ast_sinks:
            sink_type = sink.get('sinkType') or sink.get('type', '')
            sinks_by_type[sink_type].append(sink)

        marked_count = 0

        # Process priority sinks first
        for sink_type in priority_types:
            if sink_type in sinks_by_type:
                sinks = sinks_by_type[sink_type]
                if self.debug:
                    print(f"  Processing {len(sinks)} {sink_type} sinks...")

                for sink in sinks:
                    code_snippet = sink.get('codeSnippet', '')
                    matched_text = sink.get('matchedText', '')
                    best_node = self._find_node_for_sink(code_snippet, sink_type)

                    if best_node and best_node.id not in self.marked_sink_nodes:
                        best_node.is_sink = True
                        if sink_type not in best_node.sink_types:
                            best_node.sink_types.append(sink_type)
                        self.marked_sink_nodes.add(best_node.id)
                        marked_count += 1

                    # اگر node پیدا نشد و sink مهم است، node جدید بساز
                    elif not best_node and sink.get('riskLevel') in ['Critical',
                                                                     'High'] and sink_type in priority_types:
                        node_id = f"SINK_{self.node_counter}"
                        self.node_counter += 1

                        context = sink.get('context', {})
                        label = f"{sink_type}: {matched_text[:50] if matched_text else code_snippet[:50]}"

                        new_node = SemanticNode(
                            id=node_id,
                            node_type='sink_node',
                            label=label,
                            function_name=context.get('name',
                                                      'fallback' if context.get('type') == 'fallback' else 'unknown'),
                            line_start=0,
                            code_snippet=code_snippet,
                            is_sink=True,
                            sink_types=[sink_type]
                        )

                        self.nodes[node_id] = new_node
                        self.marked_sink_nodes.add(node_id)
                        marked_count += 1

                        # اتصال sink به نزدیکترین node
                        if context.get('name') and context.get('name') != 'unknown':
                            # پیدا کردن function entry node
                            func_nodes = [n for n in self.nodes.values()
                                          if n.function_name == context.get('name') and n.node_type == 'function_entry']
                            if func_nodes:
                                self.edges.append({
                                    'source': func_nodes[0].id,
                                    'target': node_id,
                                    'type': 'sink_flow'
                                })

                        if self.debug:
                            print(f"     Created sink node {node_id} for: {label[:40]}...")

        # Process other non-priority sinks
        for sink_type, sinks in sinks_by_type.items():
            if sink_type not in priority_types:
                for sink in sinks:
                    code_snippet = sink.get('codeSnippet', '')
                    best_node = self._find_node_for_sink(code_snippet, sink_type)

                    if best_node and best_node.id not in self.marked_sink_nodes:
                        best_node.is_sink = True
                        if sink_type not in best_node.sink_types:
                            best_node.sink_types.append(sink_type)
                        self.marked_sink_nodes.add(best_node.id)
                        marked_count += 1

        # Pattern-based sink marking - فقط اگر AST خالی بود
        if len(ast_sinks) == 0:
            self._mark_sinks_by_pattern()

        print(f"  ✅ Total marked sinks: {len(self.marked_sink_nodes)}")

        return True

    def _find_node_for_sink(self, code_snippet: str, sink_type: str) -> Optional[SemanticNode]:
        """Find node for sink with appropriate matching"""
        if not code_snippet:
            return None

        # Clean the snippet for better matching
        clean_snippet = code_snippet.replace("<<<SINK>>>", "").strip()

        # Key patterns for different sink types
        sink_patterns = {
            'randomGeneration': [r'keccak256\s*\(', r'sha3\s*\(', r'sha256\s*\('],
            'stateModification': [r'\w+\s*=\s*', r'\.push\s*\(', r'delete\s+'],
            'valueTransfer': [r'\.transfer\s*\(', r'\.send\s*\(', r'\.call\.value\s*\(',
                              r'\[[^\]]+\]\s*\.transfer\s*\('],  # اضافه کردن pattern آرایه
            'controlFlow': [r'if\s*\(', r'require\s*\(', r'assert\s*\(']
        }

        patterns = sink_patterns.get(sink_type, [])
        candidates = []

        for node in self.nodes.values():
            if not node.code_snippet:
                continue

            score = 0

            # Check for pattern match
            for pattern in patterns:
                if re.search(pattern, node.code_snippet):
                    score += 3
                    break

            # Check for partial text match
            if clean_snippet and len(clean_snippet) > 10:
                if clean_snippet in node.code_snippet or node.code_snippet in clean_snippet:
                    score += 4

            # Bonus for matching node types
            if sink_type == 'randomGeneration' and node.node_type in ['keccak', 'sha256', 'sha3']:
                score += 5
            elif sink_type == 'stateModification' and node.node_type == 'assignment':
                score += 2
            elif sink_type == 'valueTransfer' and node.node_type in ['transfer', 'send']:
                score += 3

            if score > 0:
                candidates.append((score, node))

        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            return candidates[0][1]

        return None

    def _mark_sinks_by_pattern(self):
        """Mark sinks by pattern, especially for randomness"""
        for node in self.nodes.values():
            if node.is_sink or node.id in self.marked_sink_nodes:
                continue

            if not node.code_snippet:
                continue

            # Check for hash functions (potential random generation)
            if re.search(r'(keccak256|sha3|sha256)\s*\(', node.code_snippet):
                # Check if it's using blockchain data
                if any(source in node.code_snippet.lower() for source in
                       ['block.', 'now', 'msg.sender', 'tx.origin']):
                    node.is_sink = True
                    if 'randomGeneration' not in node.sink_types:
                        node.sink_types.append('randomGeneration')
                    self.marked_sink_nodes.add(node.id)
                    continue

            # Transfer operations
            if re.search(r'\.(transfer|send|call\.value)\s*\(', node.code_snippet):
                node.is_sink = True
                if 'valueTransfer' not in node.sink_types:
                    node.sink_types.append('valueTransfer')
                self.marked_sink_nodes.add(node.id)

    def _step7_create_edges(self) -> bool:
        """Create edges based on control flow and data dependencies"""
        print("\n STEP 7: Creating edges...")

        # Control flow edges already created during node creation
        control_edges = len(self.edges)

        # Add data dependency edges
        data_edges_added = 0

        for var, def_node_id in self.var_definitions.items():
            # Find nodes that use this variable
            for node_id, node in self.nodes.items():
                if var in node.used_vars and node_id != def_node_id:
                    # Add data dependency edge
                    self.edges.append({
                        'source': def_node_id,
                        'target': node_id,
                        'type': 'data_dependency',
                        'var': var
                    })
                    data_edges_added += 1

        # این خط باید اینجا باشد - خارج از loop
        self._create_state_variable_edges()

        print(f"   Control flow edges: {control_edges}")
        print(f"    Data dependency edges: {data_edges_added}")
        print(f"    Total edges: {len(self.edges)}")

        return True
        print(f"    Control flow edges: {control_edges}")
        print(f"    Data dependency edges: {data_edges_added}")
        print(f"    Total edges: {len(self.edges)}")

        return True

    def _create_state_variable_edges(self):
        """Create edges from state variables to nodes that use them"""
        if not self.state_variables:
            return

        print("  Creating edges for state variable usage...")
        edges_added = 0

        # برای هر node در گراف
        for node_id, node in self.nodes.items():
            # اگر state variable خود نیست
            if node.node_type == 'state_initialization':
                continue

            # برای هر state variable
            for var_name, var_node_id in self.state_variables.items():
                # بررسی استفاده از متغیر در code snippet
                if node.code_snippet:
                    # Pattern 1: استفاده ساده از متغیر
                    var_pattern = rf'\b{re.escape(var_name)}\b'

                    # Pattern 2: assignment به متغیر (مثل new_amount = ...)
                    assignment_pattern = rf'^{re.escape(var_name)}\s*='

                    if (re.search(var_pattern, node.code_snippet) or
                            re.match(assignment_pattern, node.code_snippet.strip())):

                        # جلوگیری از edge تکراری
                        existing_edge = any(
                            e['source'] == var_node_id and e['target'] == node_id
                            for e in self.edges
                        )

                        if not existing_edge:
                            # ایجاد edge از state variable به این node
                            self.edges.append({
                                'source': var_node_id,
                                'target': node_id,
                                'type': 'state_variable_usage'
                            })
                            edges_added += 1

                            if self.debug:
                                print(f"    Edge: {var_node_id} → {node_id} (uses {var_name})")

                        # برای nodes که متغیر را modify می‌کنند، edge برگشتی هم بسازیم
                        if re.match(assignment_pattern, node.code_snippet.strip()):
                            reverse_edge = any(
                                e['source'] == node_id and e['target'] == var_node_id
                                for e in self.edges
                            )

                            if not reverse_edge:
                                self.edges.append({
                                    'source': node_id,
                                    'target': var_node_id,
                                    'type': 'state_modification'
                                })
                                edges_added += 1

                                if self.debug:
                                    print(f"    Edge: {node_id} → {var_node_id} (modifies {var_name})")

        print(f"   Added {edges_added} state variable edges")
    def _step8_save_results(self):
        """Save results for future taint analysis"""
        print("\n STEP 8: Saving results...")

        nodes_list = [node.to_dict() for node in self.nodes.values()]

        # Calculate statistics
        source_types_count = defaultdict(int)
        sink_types_count = defaultdict(int)

        for node in self.nodes.values():
            for st in node.source_types:
                source_types_count[st] += 1
            for st in node.sink_types:
                sink_types_count[st] += 1

        result = {
            'contract': self.contract_name,
            'nodes': nodes_list,
            'edges': self.edges,
            'var_definitions': self.var_definitions,
            'var_dependencies': {k: list(v) for k, v in self.var_dependencies.items()},
            'statistics': {
                'total_nodes': len(self.nodes),
                'total_edges': len(self.edges),
                'source_nodes': len(self.marked_source_nodes),
                'sink_nodes': len(self.marked_sink_nodes),
                'source_types': dict(source_types_count),
                'sink_types': dict(sink_types_count),
                'variable_definitions': len(self.var_definitions),
                'variable_dependencies': len(self.var_dependencies)
            }
        }

        output_file = os.path.join(self.contract_path,
                                   f"{self.contract_name}_semantic_graph.json")

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        print(f"    Saved to: {output_file}")

    def visualize_graph(self):
        """Simple visualization of the graph"""
        print("\nGRAPH SUMMARY:")
        print("=" * 80)

        # Track which variables are defined by source nodes (pseudo-taint tracking)
        tainted_vars = set()
        for node in self.nodes.values():
            if node.is_source and node.defined_vars:
                tainted_vars.update(node.defined_vars)

        # Show sources
        print("\nSOURCES:")
        source_nodes = [n for n in self.nodes.values() if n.is_source]
        for node in source_nodes[:10]:  # Limit display
            print(f"  {node.id}: {node.label[:50]}")
            print(f"    Types: {', '.join(node.source_types)}")
            if node.defined_vars:
                print(f"    Defines: {node.defined_vars}")
                print(f"    Taints: {node.defined_vars}")  # این متغیرها tainted می‌شوند

        if len(source_nodes) > 10:
            print(f"  ... and {len(source_nodes) - 10} more sources")

        # Show sinks
        print("\nSINKS:")

        # Priority sinks first
        priority_sinks = [n for n in self.nodes.values()
                          if n.is_sink and any(t in ['randomGeneration', 'stateModification']
                                               for t in n.sink_types)]
        if priority_sinks:
            print("\n  [Priority - Random Generation / State Modification]")
            for node in priority_sinks[:5]:
                print(f"  {node.id}: {node.label[:50]}")
                print(f"    Types: {', '.join(node.sink_types)}")
                if node.used_vars:
                    print(f"    Uses: {list(node.used_vars)[:5]}")
                    # Check for tainted vars
                    used_tainted = node.used_vars.intersection(tainted_vars)
                    if used_tainted:
                        print(f"    Uses tainted: {used_tainted}")

        # Other sinks
        other_sinks = [n for n in self.nodes.values()
                       if n.is_sink and n not in priority_sinks]
        if other_sinks:
            print("\n  [Other Sinks]")
            for node in other_sinks[:3]:
                print(f"  {node.id}: {node.label[:30]}")
                print(f"    Types: {', '.join(node.sink_types)}")
                if node.used_vars:
                    used_tainted = node.used_vars.intersection(tainted_vars)
                    if used_tainted:
                        print(f"    Uses tainted: {used_tainted}")

        # Show data dependencies - این بخش اضافه شده
        print("\n DATA DEPENDENCIES:")
        displayed_deps = 0
        for var, deps in self.var_dependencies.items():
            if displayed_deps >= 10:  # محدود کردن نمایش
                remaining = len(self.var_dependencies) - displayed_deps
                if remaining > 0:
                    print(f"  ... and {remaining} more dependencies")
                break

            taint_marker = " (TAINTED)" if var in tainted_vars else ""
            deps_list = list(deps) if isinstance(deps, set) else deps
            print(f"  {var}{taint_marker} depends on: {deps_list}")
            displayed_deps += 1

        # Summary
        print(f"\n SUMMARY:")
        print(f"  Total Nodes: {len(self.nodes)}")
        print(f"  Total Edges: {len(self.edges)}")
        print(f"  Sources: {len(self.marked_source_nodes)}")
        print(f"  Sinks: {len(self.marked_sink_nodes)}")
        print(f"  Variables Tracked: {len(self.var_definitions)}")
        print(f"  Variable Dependencies: {len(self.var_dependencies)}")
        print(f"  Tainted Variables: {len(tainted_vars)}")

def test_graph_builder(contract_name: str):
    """Test the graph builder"""
    builder = SemanticGraphBuilder(contract_name, debug=True)

    if builder.build_graph():
        builder.visualize_graph()
        return True

    return False


def process_all_contracts(contract_path: str = "contract_ast", source_path: str = "smartcontract"):
    """Process all contracts in the directory"""
    print("\n Processing all contracts...")

    # Find all AST files
    ast_files = [f for f in os.listdir(contract_path) if f.endswith("_ast.json")]

    print(f"Found {len(ast_files)} AST files")

    successful = 0
    failed = 0

    for ast_file in ast_files:
        contract_name = ast_file.replace("_ast.json", "")
        print(f"\n{'=' * 100}")
        print(f"Processing: {contract_name}")
        print('=' * 100)

        try:
            # ایجاد builder با مسیر source_path
            builder = SemanticGraphBuilder(contract_name, contract_path, source_path, debug=True)
            if builder.build_graph():
                builder.visualize_graph()
                successful += 1
            else:
                failed += 1
        except Exception as e:
            print(f"Error processing {contract_name}: {str(e)}")
            failed += 1

    print(f"\n{'=' * 80}")
    print(f" FINAL SUMMARY:")
    print(f"  Successful: {successful}")
    print(f"   Failed: {failed}")
    print(f"  Total: {len(ast_files)}")
    print('=' * 80)


if __name__ == "__main__":
    # اجرا برای کل dataset
    process_all_contracts()