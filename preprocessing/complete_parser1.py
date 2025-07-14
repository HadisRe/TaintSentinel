import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import subprocess
import sys
import re

try:
    from solcx import compile_source, install_solc, set_solc_version, get_installable_solc_versions
except ImportError:
    print("Installing py-solc-x...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "py-solc-x"])
    from solcx import compile_source, install_solc, set_solc_version, get_installable_solc_versions


class ImprovedSolidityASTBuilder:
     

    def __init__(self, default_solc_version="0.8.19"):
        self.default_solc_version = default_solc_version
        self.current_version = None
        self.error_log = []
        self._setup_solc(default_solc_version)

    def _setup_solc(self, version):
         try:
            if version == "0.5.25":
                print(f"Version {version} not available on Windows, using 0.5.17 instead")
                version = "0.5.17"

            install_solc(version)
            set_solc_version(version)
            self.current_version = version
            print(f"Solc version {version} is ready")
        except Exception as e:
            print(f"Error setting up solc {version}: {e}")

    def _extract_pragma_version(self, source_code: str) -> Optional[str]:
         pragma_pattern = r'pragma\s+solidity\s+([^;]+);'
        match = re.search(pragma_pattern, source_code)

        if not match:
            return None

        version_spec = match.group(1).strip()

         if "0.5.25" in version_spec:
            return "0.5.17"

         version_spec = version_spec.replace('^', '').replace('~', '')

         if '>=' in version_spec:
            parts = version_spec.split()
            for part in parts:
                if part.startswith('>='):
                    base_version = part[2:]
                    return self._find_compatible_version(base_version)
        elif '>' in version_spec and '<' in version_spec:
            parts = version_spec.split()
            for part in parts:
                if part.startswith('>') and not part.startswith('>='):
                    base_version = part[1:]
                    return self._find_compatible_version(base_version)
        else:
            version = version_spec.strip()

            if version == "0.5.25":
                return "0.5.17"

            if version.count('.') == 2:
                return version
            elif version.count('.') == 1:
                return version + '.0'

        return None

    def _find_compatible_version(self, min_version: str) -> str:
         if min_version == "0.5.25":
            return "0.5.17"

        try:
            available_versions = get_installable_solc_versions()

            min_parts = [int(x) for x in min_version.split('.')]

            suitable_versions = []
            for v in available_versions:
                if isinstance(v, str) and v.count('.') == 2:
                    v_parts = [int(x) for x in v.split('.')]
                    if v_parts >= min_parts:
                        suitable_versions.append(v)

            if suitable_versions:
                return min(suitable_versions)
            else:
                return self.default_solc_version

        except:
            return self.default_solc_version

    def _enhanced_auto_fix_code(self, source_code: str, error_message: str, version: str) -> Tuple[str, bool]:
         fixed = False
        original_code = source_code

         source_code, fixed = self._auto_fix_code(source_code, error_message, version)

 
         if "This function only accepts a single \"bytes\" argument" in error_message:
            print("  → Fixing keccak256 multi-argument issue")
            # تبدیل keccak256(a, b, c) به keccak256(abi.encodePacked(a, b, c))
            pattern = r'keccak256\s*\(([^)]+,[^)]+)\)'

            def replace_keccak(match):
                args = match.group(1)
                return f'keccak256(abi.encodePacked({args}))'

            source_code = re.sub(pattern, replace_keccak, source_code)
            fixed = True

         if "Visibility for constructor is ignored" in error_message:
            print("  → Fixing constructor visibility")
             source_code = re.sub(r'constructor\s*\([^)]*\)\s*(public|internal|private|external)',
                                 r'constructor\1', source_code)
            fixed = True

         if "sha3" in source_code and version >= "0.5.0":
            print("  → Fixing sha3 -> keccak256")
            source_code = re.sub(r'\bsha3\b', 'keccak256', source_code)
            fixed = True

         if "throw" in source_code and version >= "0.5.0":
            print("  → Fixing throw -> revert()")
            source_code = re.sub(r'\bthrow\b', 'revert()', source_code)
            fixed = True

         if "suicide" in source_code:
            print("  → Fixing suicide -> selfdestruct")
            source_code = re.sub(r'\bsuicide\b', 'selfdestruct', source_code)
            fixed = True

        return source_code, fixed

    def _auto_fix_code(self, source_code: str, error_message: str, version: str) -> Tuple[str, bool]:
          fixed = False
        original_code = source_code

         if "16.66" in source_code and "not implicitly convertible" in error_message:
            print("  → Fixing floating point issue (16.66 -> 1666/100)")
            source_code = source_code.replace("* 16.66", "* 1666 / 100")
            fixed = True

         if "uint8(keccak256" in source_code and "Explicit type conversion not allowed" in error_message:
            print("  → Fixing uint8 conversion issue")
            pattern = r'uint8\s*\(\s*keccak256'
            replacement = 'uint8(uint256(keccak256'
            source_code = re.sub(pattern, replacement, source_code)
            fixed = True

         if "Data location must be \"memory\"" in error_message:
            print("  → Fixing string memory issue")
            source_code = re.sub(r'(\(string\s+)', r'(string memory ', source_code)
            source_code = re.sub(r'(,\s*string\s+)', r', string memory ', source_code)
            fixed = True

         if "transfer" in error_message and "address payable" in error_message:
            print("  → Fixing address payable issue")
            pattern = r'(\w+)\.transfer\s*\('
            matches = re.findall(pattern, source_code)

            for var_name in matches:
                addr_pattern = f'address\\s+{var_name}'
                addr_replacement = f'address payable {var_name}'
                source_code = re.sub(addr_pattern, addr_replacement, source_code)
                fixed = True

         if version >= "0.7.0" and "now" in source_code:
            print("  → Fixing 'now' deprecated issue")
            source_code = re.sub(r'\bnow\b', 'block.timestamp', source_code)
            fixed = True

        return source_code, fixed

    def _clean_source_code(self, source_code: str) -> str:
         if source_code.startswith('\ufeff'):
            source_code = source_code[1:]

         source_code = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F-\x9F]', '', source_code)

         source_code = source_code.replace('\r\n', '\n').replace('\r', '\n')

        return source_code

    def build_ast_from_file(self, file_path: str) -> Dict[str, Any]:
         try:
             content = None
            for encoding in ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue

            if content is None:
                with open(file_path, 'rb') as f:
                    raw_content = f.read()
                content = raw_content.decode('utf-8', errors='ignore')

             content = self._clean_source_code(content)

            return self.build_ast_from_source(content, file_path)

        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            self.error_log.append({
                "file": file_path,
                "error": f"File reading error: {str(e)}",
                "version": "N/A"
            })
            return None

    def build_ast_from_source(self, source_code: str, file_name: str = "Contract.sol") -> Dict[str, Any]:
         max_attempts = 5  # افزایش تعداد تلاش
        attempt = 0

        while attempt < max_attempts:
            attempt += 1

            try:
                 required_version = self._extract_pragma_version(source_code)

                 if "^0.5.25" in source_code:
                    print(f"Fixing pragma from ^0.5.25 to ^0.5.17")
                    source_code = source_code.replace("^0.5.25", "^0.5.17")
                    required_version = "0.5.17"

                if required_version and required_version != self.current_version:
                    print(f"Switching to Solc version {required_version} for {file_name}")
                    self._setup_solc(required_version)

 
                compiled = compile_source(
                    source_code,
                    output_values=['ast', 'abi', 'bin'],
                    solc_version=self.current_version
                )

                 first_key = list(compiled.keys())[0]
                ast = compiled[first_key]['ast']

                 processed_ast = self._process_ast(ast, file_name)

                return processed_ast

            except Exception as e:
                error_str = str(e)
                print(f"Attempt {attempt} - Error compiling {file_name}: {error_str[:200]}...")

                 if attempt < max_attempts:
                    fixed_code, was_fixed = self._enhanced_auto_fix_code(source_code, error_str, self.current_version)

                    if was_fixed:
                        print(f"  → Applied automatic fixes, retrying...")
                        source_code = fixed_code
                        continue

 
                if attempt == max_attempts - 2:
                     if "Expected pragma" in error_str:
                        test_versions = ["0.8.19", "0.7.6", "0.6.12", "0.5.17", "0.4.26"]
                    else:
                        test_versions = ["0.8.19", "0.7.6", "0.6.12", "0.5.17", "0.4.26"]

                    for test_version in test_versions:
                        if test_version != self.current_version:
                            print(f"  → Trying version {test_version}")
                            self._setup_solc(test_version)
                            break
                    continue

                 if self.current_version != self.default_solc_version and attempt == max_attempts - 1:
                    print(f"Retrying with default version {self.default_solc_version}")
                    self._setup_solc(self.default_solc_version)
                    continue

 
                self.error_log.append({
                    "file": file_name,
                    "error": error_str,
                    "version": self.current_version
                })

        return None

     def _process_ast(self, raw_ast: Dict[str, Any], file_name: str) -> Dict[str, Any]:
        """پردازش AST خام و افزودن اطلاعات اضافی - پشتیبانی از فرمت‌های قدیم و جدید"""
        processed = {
            "type": "SourceUnit",
            "file_name": file_name,
            "compiler_version": self.current_version,
            "contracts": {},
            "imports": [],
            "pragmas": [],
            "ast": raw_ast
        }

        if 'nodes' in raw_ast:
            nodes = raw_ast['nodes']
            node_type_key = 'nodeType'
        elif 'children' in raw_ast:
            nodes = raw_ast['children']
            node_type_key = 'name'
        else:
            print(f"Warning: Unknown AST format for {file_name}")
            return processed

        for node in nodes:
            node_type = node.get(node_type_key)

            if node_type == 'ContractDefinition':
                if 'name' in node and node_type_key == 'nodeType':
                    contract_name = node['name']
                elif 'attributes' in node and 'name' in node['attributes']:
                    contract_name = node['attributes']['name']
                else:
                    continue

                processed['contracts'][contract_name] = self._process_contract(node, node_type_key)

            elif node_type == 'ImportDirective':
                processed['imports'].append(node)

            elif node_type == 'PragmaDirective':
                processed['pragmas'].append(node)

        return processed

    def _process_contract(self, contract_node: Dict[str, Any], node_type_key: str = 'nodeType') -> Dict[str, Any]:
 
        if 'attributes' in contract_node:
            attrs = contract_node['attributes']
            contract_info = {
                "name": attrs.get('name', ''),
                "id": contract_node.get('id', 0),
                "type": attrs.get('contractKind', 'contract'),
                "abstract": attrs.get('abstract', False),
                "inheritance": [],
                "functions": {},
                "modifiers": {},
                "state_variables": {},
                "events": {},
                "structs": {},
                "enums": {},
                "errors": {},
                "raw_ast": contract_node
            }

            if 'baseContracts' in attrs and attrs['baseContracts']:
                for base in attrs['baseContracts']:
                    if base and isinstance(base, dict):
                        contract_info['inheritance'].append({
                            "name": base.get('name', 'Unknown'),
                            "id": base.get('id', 0)
                        })

            if 'children' in contract_node:
                for child in contract_node['children']:
                    child_type = child.get('name')

                    if child_type == 'FunctionDefinition':
                        func_info = self._process_function_old(child)
                        contract_info['functions'][func_info['name']] = func_info

                    elif child_type == 'ModifierDefinition':
                        mod_info = self._process_modifier_old(child)
                        contract_info['modifiers'][mod_info['name']] = mod_info

                    elif child_type == 'VariableDeclaration':
                        if child.get('attributes', {}).get('stateVariable', False):
                            var_info = self._process_state_variable_old(child)
                            contract_info['state_variables'][var_info['name']] = var_info

                    elif child_type == 'EventDefinition':
                        event_info = self._process_event_old(child)
                        contract_info['events'][event_info['name']] = event_info

                    elif child_type == 'StructDefinition':
                        struct_info = self._process_struct_old(child)
                        contract_info['structs'][struct_info['name']] = struct_info

                    elif child_type == 'EnumDefinition':
                        enum_info = self._process_enum_old(child)
                        contract_info['enums'][enum_info['name']] = enum_info

        else:
            contract_info = {
                "name": contract_node['name'],
                "id": contract_node['id'],
                "type": contract_node['contractKind'],
                "abstract": contract_node.get('abstract', False),
                "inheritance": [],
                "functions": {},
                "modifiers": {},
                "state_variables": {},
                "events": {},
                "structs": {},
                "enums": {},
                "errors": {},
                "raw_ast": contract_node
            }

            if 'baseContracts' in contract_node:
                for base in contract_node['baseContracts']:
                    contract_info['inheritance'].append({
                        "name": base['baseName']['name'],
                        "id": base['baseName']['id']
                    })

            if 'nodes' in contract_node:
                for node in contract_node['nodes']:
                    node_type = node['nodeType']

                    if node_type == 'FunctionDefinition':
                        func_info = self._process_function(node)
                        contract_info['functions'][func_info['name']] = func_info

                    elif node_type == 'ModifierDefinition':
                        mod_info = self._process_modifier(node)
                        contract_info['modifiers'][mod_info['name']] = mod_info

                    elif node_type == 'VariableDeclaration' and node.get('stateVariable', False):
                        var_info = self._process_state_variable(node)
                        contract_info['state_variables'][var_info['name']] = var_info

                    elif node_type == 'EventDefinition':
                        event_info = self._process_event(node)
                        contract_info['events'][event_info['name']] = event_info

                    elif node_type == 'StructDefinition':
                        struct_info = self._process_struct(node)
                        contract_info['structs'][struct_info['name']] = struct_info

                    elif node_type == 'EnumDefinition':
                        enum_info = self._process_enum(node)
                        contract_info['enums'][enum_info['name']] = enum_info

                    elif node_type == 'ErrorDefinition':
                        error_info = self._process_error(node)
                        contract_info['errors'][error_info['name']] = error_info

        return contract_info

     def _process_function(self, node: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": node.get('name', 'constructor' if node['kind'] == 'constructor' else 'fallback'),
            "id": node['id'],
            "kind": node['kind'],
            "visibility": node['visibility'],
            "state_mutability": node['stateMutability'],
            "virtual": node.get('virtual', False),
            "override": node.get('overrides', []),
            "parameters": self._process_parameters(node.get('parameters', {})),
            "returns": self._process_parameters(node.get('returnParameters', {})),
            "modifiers": [mod['modifierName']['name'] for mod in node.get('modifiers', [])],
            "body": node.get('body'),
            "implemented": node.get('implemented', True),
            "raw_ast": node
        }

    def _process_modifier(self, node: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": node['name'],
            "id": node['id'],
            "visibility": node.get('visibility', 'internal'),
            "virtual": node.get('virtual', False),
            "override": node.get('overrides', []),
            "parameters": self._process_parameters(node.get('parameters', {})),
            "body": node.get('body'),
            "raw_ast": node
        }

    def _process_state_variable(self, node: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": node['name'],
            "id": node['id'],
            "type": self._get_type_name(node['typeName']),
            "visibility": node['visibility'],
            "constant": node.get('constant', False),
            "immutable": node.get('mutability') == 'immutable',
            "initial_value": node.get('value'),
            "raw_ast": node
        }

    def _process_event(self, node: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": node['name'],
            "id": node['id'],
            "anonymous": node.get('anonymous', False),
            "parameters": self._process_event_parameters(node.get('parameters', {})),
            "raw_ast": node
        }

    def _process_struct(self, node: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": node['name'],
            "id": node['id'],
            "visibility": node.get('visibility', 'internal'),
            "members": [
                {
                    "name": member['name'],
                    "type": self._get_type_name(member['typeName']),
                    "id": member['id']
                }
                for member in node.get('members', [])
            ],
            "raw_ast": node
        }

    def _process_enum(self, node: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": node['name'],
            "id": node['id'],
            "members": [member['name'] for member in node.get('members', [])],
            "raw_ast": node
        }

    def _process_error(self, node: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": node['name'],
            "id": node['id'],
            "parameters": self._process_parameters(node.get('parameters', {})),
            "raw_ast": node
        }

    def _process_function_old(self, node: Dict[str, Any]) -> Dict[str, Any]:
        attrs = node.get('attributes', {})

        return {
            "name": attrs.get('name', 'unnamed'),
            "id": node.get('id', 0),
            "kind": attrs.get('kind', 'function'),
            "visibility": attrs.get('visibility', 'internal'),
            "state_mutability": attrs.get('stateMutability', 'nonpayable'),
            "virtual": attrs.get('virtual', False),
            "override": attrs.get('overrides', []),
            "parameters": self._process_parameters_old(node),
            "returns": [],
            "modifiers": attrs.get('modifiers', []),
            "body": self._find_node_by_name(node.get('children', []), 'Block'),
            "implemented": attrs.get('implemented', True),
            "raw_ast": node
        }

    def _process_parameters_old(self, func_node: Dict[str, Any]) -> List[Dict[str, Any]]:
        parameters = []

        for child in func_node.get('children', []):
            if child.get('name') == 'ParameterList':
                for param_child in child.get('children', []):
                    if param_child.get('name') == 'VariableDeclaration':
                        attrs = param_child.get('attributes', {})
                        parameters.append({
                            "name": attrs.get('name', ''),
                            "type": attrs.get('type', 'unknown'),
                            "id": param_child.get('id', 0),
                            "storage_location": attrs.get('storageLocation', 'default')
                        })
                break

        return parameters

    def _find_node_by_name(self, nodes: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
        for node in nodes:
            if node.get('name') == name:
                return node
        return None

    def _process_state_variable_old(self, node: Dict[str, Any]) -> Dict[str, Any]:
        attrs = node.get('attributes', {})

        return {
            "name": attrs.get('name', ''),
            "id": node.get('id', 0),
            "type": attrs.get('type', 'unknown'),
            "visibility": attrs.get('visibility', 'internal'),
            "constant": attrs.get('constant', False),
            "immutable": False,
            "initial_value": attrs.get('value'),
            "raw_ast": node
        }

    def _process_event_old(self, node: Dict[str, Any]) -> Dict[str, Any]:
        attrs = node.get('attributes', {})

        return {
            "name": attrs.get('name', ''),
            "id": node.get('id', 0),
            "anonymous": attrs.get('anonymous', False),
            "parameters": [],
            "raw_ast": node
        }

    def _process_modifier_old(self, node: Dict[str, Any]) -> Dict[str, Any]:
        attrs = node.get('attributes', {})

        return {
            "name": attrs.get('name', ''),
            "id": node.get('id', 0),
            "visibility": attrs.get('visibility', 'internal'),
            "virtual": attrs.get('virtual', False),
            "override": [],
            "parameters": [],
            "body": self._find_node_by_name(node.get('children', []), 'Block'),
            "raw_ast": node
        }

    def _process_struct_old(self, node: Dict[str, Any]) -> Dict[str, Any]:
        attrs = node.get('attributes', {})

        return {
            "name": attrs.get('name', ''),
            "id": node.get('id', 0),
            "visibility": attrs.get('visibility', 'internal'),
            "members": [],
            "raw_ast": node
        }

    def _process_enum_old(self, node: Dict[str, Any]) -> Dict[str, Any]:
        attrs = node.get('attributes', {})

        return {
            "name": attrs.get('name', ''),
            "id": node.get('id', 0),
            "members": [],
            "raw_ast": node
        }

    def _process_parameters(self, params_node: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not params_node or 'parameters' not in params_node:
            return []

        return [
            {
                "name": param.get('name', ''),
                "type": self._get_type_name(param['typeName']),
                "id": param['id'],
                "storage_location": param.get('storageLocation', 'default')
            }
            for param in params_node['parameters']
        ]

    def _process_event_parameters(self, params_node: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not params_node or 'parameters' not in params_node:
            return []

        return [
            {
                "name": param.get('name', ''),
                "type": self._get_type_name(param['typeName']),
                "indexed": param.get('indexed', False),
                "id": param['id']
            }
            for param in params_node['parameters']
        ]

    def _get_type_name(self, type_node: Dict[str, Any]) -> str:
        if not type_node or not isinstance(type_node, dict):
            return "unknown"

        node_type = type_node.get('nodeType')
        if not node_type:
            return type_node.get('typeString', 'unknown')

        if node_type == 'ElementaryTypeName':
            return type_node.get('name', 'unknown')
        elif node_type == 'UserDefinedTypeName':
            if 'pathNode' in type_node and isinstance(type_node['pathNode'], dict):
                return type_node['pathNode'].get('name', 'unknown')
            return type_node.get('name', 'unknown')
        elif node_type == 'ArrayTypeName':
            base_type = self._get_type_name(type_node.get('baseType', {}))
            return f"{base_type}[]"
        elif node_type == 'Mapping':
            key_type = self._get_type_name(type_node.get('keyType', {}))
            value_type = self._get_type_name(type_node.get('valueType', {}))
            return f"mapping({key_type} => {value_type})"
        else:
            return type_node.get('typeString', 'unknown')

    def process_directory(self, source_dir: str, output_dir: str):
         Path(output_dir).mkdir(parents=True, exist_ok=True)

        sol_files = list(Path(source_dir).glob('**/*.sol'))
        print(f"Found {len(sol_files)} Solidity files")

        success_count = 0
        error_count = 0

        for i, sol_file in enumerate(sol_files):
            print(f"\n[{i + 1}/{len(sol_files)}] Processing {sol_file.name}...")
            try:
                ast = self.build_ast_from_file(str(sol_file))

                if ast:
                    output_file = Path(output_dir) / f"{sol_file.stem}_ast.json"

                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(ast, f, indent=2, ensure_ascii=False)

                    print(f"✓ Saved AST to {output_file}")
                    success_count += 1
                else:
                    print(f"✗ Failed to build AST for {sol_file}")
                    error_count += 1

            except Exception as e:
                print(f"✗ Error processing {sol_file}: {e}")
                error_count += 1

        print(f"\n{'=' * 50}")
        print(f"Processing completed!")
        print(f"Success: {success_count}")
        print(f"Errors: {error_count}")

        if self.error_log:
            print(f"\nError Report:")
            print("-" * 50)
            for error in self.error_log[:20]:  # نمایش 20 خطای اول
                print(f"\nFile: {error['file']}")
                print(f"Version: {error['version']}")
                print(f"Error: {error['error'][:200]}...")

            with open(Path(output_dir) / "error_report.json", 'w') as f:
                json.dump(self.error_log, f, indent=2)
                print(f"\nDetailed error report saved to: {Path(output_dir) / 'error_report.json'}")


 if __name__ == "__main__":
    builder = ImprovedSolidityASTBuilder()
    builder.process_directory("smartcontract", "contract_ast")
