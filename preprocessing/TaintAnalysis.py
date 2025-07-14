import json
import os
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import networkx as nx


class RiskLevel(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RiskFactor(Enum):
    # Risk increasing factors
    CRITICAL_ENTROPY_SOURCE = "Critical entropy source (blockhash/difficulty)"
    WEAK_ENTROPY_SOURCE = "Weak entropy source (timestamp/blocknumber)"
    GAMBLING_CONTEXT = "Gambling/lottery context detected"
    FINANCIAL_IMPACT = "Direct financial impact"
    DIRECT_DEPENDENCY = "Direct path (≤2 nodes)"
    MANIPULABLE_TIMEFRAME = "Short time window (<15 seconds)"
    PREDICTABLE_HASH = "Hash with all predictable inputs"
    COMBINED_WEAK_SOURCES = "Multiple weak sources combined"
    
    # Risk mitigating factors
    ENTROPY_MIXING = "Proper entropy mixing detected"
    SUFFICIENT_TIME_CONSTRAINT = "Long time window constraint"
    ADMIN_ONLY_EXECUTION = "Admin-only access control"
    RESTRICTED_ACCESS = "Role-based access control"
    USER_ENTROPY_MIXED = "User input mixed with entropy"
    COMPLEX_COMPUTATION = "Complex intermediate computations"


@dataclass
class TaintedPath:
     source_node: str
    sink_node: str
    path_nodes: List[str]  # All nodes in order
    path_edges: List[Dict[str, str]]  # Edge details
    risk_level: RiskLevel
    risk_factors: List[RiskFactor] = field(default_factory=list)
    mitigating_factors: List[RiskFactor] = field(default_factory=list)
    source_type: str = ""
    sink_type: str = ""
    path_length: int = 0
    contains_loop: bool = False
    
    def to_dict(self):
        return {
            "source": self.source_node,
            "sink": self.sink_node,
            "path": self.path_nodes,
            "edges": self.path_edges,
            "risk_level": self.risk_level.value,
            "risk_factors": [f.value for f in self.risk_factors],
            "mitigating_factors": [f.value for f in self.mitigating_factors],
            "source_type": self.source_type,
            "sink_type": self.sink_type,
            "path_length": self.path_length,
            "contains_loop": self.contains_loop
        }


class TaintAnalyzer:
     
    def __init__(self, contract_name: str, graph_path: str = "contract_ast"):
        self.contract_name = contract_name
        self.graph_path = graph_path
        
        # Graph data
        self.nodes = {}
        self.edges = []
        self.graph = nx.DiGraph()
        
        # Analysis results
        self.tainted_nodes = defaultdict(set)  # node -> set of sources that taint it
        self.tainted_paths = []
        
        # Statistics
        self.stats = {
            "total_sources": 0,
            "total_sinks": 0,
            "tainted_sinks": 0,
            "total_paths": 0,
            "high_risk_paths": 0,
            "medium_risk_paths": 0,
            "low_risk_paths": 0
        }
        
    def analyze(self) -> bool:
         print(f"\n{'='*80}")
        print(f" TAINT ANALYSIS FOR: {self.contract_name}")
        print('='*80)
        
        # Step 1: Load semantic graph
        if not self._load_semantic_graph():
            return False
            
        # Step 2: Build NetworkX graph
        self._build_networkx_graph()
        
        # Step 3: Perform taint propagation
        self._propagate_taint()
        
        # Step 4: Extract all tainted paths
        self._extract_tainted_paths()
        
        # Step 5: Assess risk for each path
        self._assess_path_risks()
        
        # Step 6: Save results
        self._save_results()
        
        # Step 7: Display summary
        self._display_summary()
        
        return True
    
    def _load_semantic_graph(self) -> bool:
         graph_file = os.path.join(self.graph_path, f"{self.contract_name}_semantic_graph.json")
        
        if not os.path.exists(graph_file):
            print(f" Semantic graph not found: {graph_file}")
            return False
            
        with open(graph_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # Convert nodes list to dict
        for node in data['nodes']:
            self.nodes[node['id']] = node
            
        self.edges = data['edges']
        
        # Count sources and sinks
        for node in self.nodes.values():
            if node.get('is_source'):
                self.stats['total_sources'] += 1
            if node.get('is_sink'):
                self.stats['total_sinks'] += 1
                
        print(f"  Loaded graph: {len(self.nodes)} nodes, {len(self.edges)} edges")
        print(f"   Sources: {self.stats['total_sources']}, Sinks: {self.stats['total_sinks']}")
        
        return True
    
    def _build_networkx_graph(self):
         # Add nodes
        for node_id, node_data in self.nodes.items():
            self.graph.add_node(node_id, **node_data)
            
        # Add edges
        for edge in self.edges:
            self.graph.add_edge(
                edge['source'], 
                edge['target'],
                type=edge.get('type', 'control_flow'),
                var=edge.get('var', '')
            )
            
    def _propagate_taint(self):
         print("\nPropagating taint from sources...")
        
         source_nodes = [n_id for n_id, n_data in self.nodes.items() 
                       if n_data.get('is_source')]
        
        for source_id in source_nodes:
             visited = set()
            queue = deque([source_id])
            self.tainted_nodes[source_id].add(source_id)
            
            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                    
                visited.add(current)
                
                 current_node = self.nodes[current]
                
                 for successor in self.graph.successors(current):
                    if self._should_propagate_taint(current, successor, source_id):
                        self.tainted_nodes[successor].add(source_id)
                        queue.append(successor)
                        
         for node_id, node_data in self.nodes.items():
            if node_data.get('is_sink') and self.tainted_nodes[node_id]:
                self.stats['tainted_sinks'] += 1
                
        print(f" Taint propagation complete: {self.stats['tainted_sinks']} sinks tainted")
        
    def _should_propagate_taint(self, from_node: str, to_node: str, source: str) -> bool:
         edge_data = self.graph.get_edge_data(from_node, to_node)
        if not edge_data:
            return False
            
        edge_type = edge_data.get('type', 'control_flow')
        
         if edge_type == 'control_flow':
            return True
            
 
        if edge_type == 'data_dependency':
             var = edge_data.get('var', '')
            from_node_data = self.nodes[from_node]
            
             if var in from_node_data.get('defined_vars', []):
                return True
                
        return True   
        
    def _extract_tainted_paths(self):
         print("\nExtracting tainted paths...")
        
        source_nodes = [n_id for n_id, n_data in self.nodes.items() 
                       if n_data.get('is_source')]
        
        for source_id in source_nodes:
            source_type = self.nodes[source_id].get('sources', ['unknown'])[0]
            
             tainted_sinks = [
                n_id for n_id, tainters in self.tainted_nodes.items()
                if source_id in tainters and self.nodes[n_id].get('is_sink')
            ]
            
            for sink_id in tainted_sinks:
                sink_type = self.nodes[sink_id].get('sinks', ['unknown'])[0]
                
                 try:
                    paths = list(nx.all_simple_paths(
                        self.graph, 
                        source_id, 
                        sink_id,
                        cutoff=15  # Max path length to prevent explosion
                    ))
                    
                    for path in paths:
                         path_edges = []
                        for i in range(len(path) - 1):
                            edge_data = self.graph.get_edge_data(path[i], path[i+1])
                            path_edges.append({
                                'from': path[i],
                                'to': path[i+1],
                                'type': edge_data.get('type', 'control_flow')
                            })
                            
                        tainted_path = TaintedPath(
                            source_node=source_id,
                            sink_node=sink_id,
                            path_nodes=path,
                            path_edges=path_edges,
                            risk_level=RiskLevel.MEDIUM,  # Default
                            source_type=source_type,
                            sink_type=sink_type,
                            path_length=len(path)
                        )
                        
                        self.tainted_paths.append(tainted_path)
                        
                except nx.NetworkXNoPath:
                    # No path exists - shouldn't happen if taint propagation is correct
                    pass
                    
        self.stats['total_paths'] = len(self.tainted_paths)
        print(f"  Found {self.stats['total_paths']} tainted paths")
        
    def _assess_path_risks(self):
         print("\nAssessing path risks...")
        
        for path in self.tainted_paths:
            self._assess_single_path(path)
            
             if path.risk_level == RiskLevel.HIGH:
                self.stats['high_risk_paths'] += 1
            elif path.risk_level == RiskLevel.MEDIUM:
                self.stats['medium_risk_paths'] += 1
            else:
                self.stats['low_risk_paths'] += 1
                
    def _assess_single_path(self, path: TaintedPath):
         risk_factors = []
        mitigating_factors = []
        
         if path.source_type in ['blockhash', 'difficulty', 'prevrandao']:
            risk_factors.append(RiskFactor.CRITICAL_ENTROPY_SOURCE)
        elif path.source_type in ['timestamp', 'blocknumber']:
            risk_factors.append(RiskFactor.WEAK_ENTROPY_SOURCE)
            
         if path.sink_type == 'randomGeneration':
             if self._has_gambling_context(path):
                risk_factors.append(RiskFactor.GAMBLING_CONTEXT)
                
             if self._has_financial_impact(path):
                risk_factors.append(RiskFactor.FINANCIAL_IMPACT)
                
         if path.path_length <= 3:
            risk_factors.append(RiskFactor.DIRECT_DEPENDENCY)
        elif path.path_length > 7:
            mitigating_factors.append(RiskFactor.COMPLEX_COMPUTATION)
            
         if self._has_mixing_operations(path):
            mitigating_factors.append(RiskFactor.ENTROPY_MIXING)
            
         access_control = self._check_access_control(path)
        if access_control == 'admin':
            mitigating_factors.append(RiskFactor.ADMIN_ONLY_EXECUTION)
        elif access_control == 'role':
            mitigating_factors.append(RiskFactor.RESTRICTED_ACCESS)
            
         time_constraint = self._check_time_constraints(path)
        if time_constraint == 'short':
            risk_factors.append(RiskFactor.MANIPULABLE_TIMEFRAME)
        elif time_constraint == 'long':
            mitigating_factors.append(RiskFactor.SUFFICIENT_TIME_CONSTRAINT)
            
         path.risk_factors = risk_factors
        path.mitigating_factors = mitigating_factors
        
         path.risk_level = self._determine_risk_level(risk_factors, mitigating_factors)
        
    def _has_gambling_context(self, path: TaintedPath) -> bool:
         gambling_patterns = [
            'lottery', 'winner', 'random', 'bet', 'gambl',
            'prize', 'jackpot', 'luck', 'dice', 'coin'
        ]
        
        for node_id in path.path_nodes:
            node = self.nodes[node_id]
            code = node.get('code_snippet', '').lower()
            label = node.get('label', '').lower()
            
            if any(pattern in code or pattern in label for pattern in gambling_patterns):
                return True
                
        return False
        
    def _has_financial_impact(self, path: TaintedPath) -> bool:
         if path.sink_type == 'valueTransfer':
            return True
            
         for node_id in path.path_nodes:
            node = self.nodes[node_id]
            if node.get('type') in ['transfer', 'send']:
                return True
            if 'transfer' in node.get('label', '').lower():
                return True
                
        return False
        
    def _has_mixing_operations(self, path: TaintedPath) -> bool:
         for node_id in path.path_nodes:
            node = self.nodes[node_id]
            node_type = node.get('type', '')
            
             if node_type in ['keccak', 'sha256', 'sha3']:
                 if len(node.get('used_vars', [])) > 2:
                    return True
                    
        return False
        
    def _check_access_control(self, path: TaintedPath) -> str:
         for node_id in path.path_nodes:
            node = self.nodes[node_id]
            code = node.get('code_snippet', '').lower()
            
            if 'onlyowner' in code or 'msg.sender == owner' in code:
                return 'admin'
            elif 'hasrole' in code or 'role' in code:
                return 'role'
                
        return 'none'
        
    def _check_time_constraints(self, path: TaintedPath) -> str:
         for node_id in path.path_nodes:
            node = self.nodes[node_id]
            code = node.get('code_snippet', '')
            
             if 'block.timestamp' in code or 'now' in code:
                 if '15' in code or '< 30' in code:
                    return 'short'
                elif '>' in code and any(t in code for t in ['days', 'hours', 'weeks']):
                    return 'long'
                    
        return 'none'
        
    def _determine_risk_level(self, risk_factors: List[RiskFactor], 
                            mitigating_factors: List[RiskFactor]) -> RiskLevel:
         
         if (RiskFactor.CRITICAL_ENTROPY_SOURCE in risk_factors and 
            RiskFactor.GAMBLING_CONTEXT in risk_factors):
            return RiskLevel.HIGH
            
        if (RiskFactor.DIRECT_DEPENDENCY in risk_factors and 
            RiskFactor.FINANCIAL_IMPACT in risk_factors):
            return RiskLevel.HIGH
            
        if (RiskFactor.PREDICTABLE_HASH in risk_factors and 
            RiskFactor.MANIPULABLE_TIMEFRAME in risk_factors):
            return RiskLevel.HIGH
            
         if len(risk_factors) == 0:
            return RiskLevel.LOW
            
        if (len(mitigating_factors) > len(risk_factors) and 
            RiskFactor.ADMIN_ONLY_EXECUTION in mitigating_factors):
            return RiskLevel.LOW
            
        if (RiskFactor.WEAK_ENTROPY_SOURCE in risk_factors and 
            RiskFactor.USER_ENTROPY_MIXED in mitigating_factors and 
            len(risk_factors) <= 1):
            return RiskLevel.LOW
            
         return RiskLevel.MEDIUM
        
    def _save_results(self):
         results = {
            "contract": self.contract_name,
            "statistics": self.stats,
            "paths": [path.to_dict() for path in self.tainted_paths],
            "summary": {
                "total_paths": len(self.tainted_paths),
                "risk_distribution": {
                    "HIGH": self.stats['high_risk_paths'],
                    "MEDIUM": self.stats['medium_risk_paths'],
                    "LOW": self.stats['low_risk_paths']
                }
            }
        }
        
        output_file = os.path.join(self.graph_path, 
                                 f"{self.contract_name}_taint_analysis.json")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
            
        print(f"\n Results saved to: {output_file}")
        
    def _display_summary(self):
         print("\n" + "="*80)
        print(" ANALYSIS SUMMARY")
        print("="*80)
        
        print(f"\nPath Statistics:")
        print(f"  Total Paths Found: {self.stats['total_paths']}")
        print(f"  High Risk:   {self.stats['high_risk_paths']} paths")
        print(f"  Medium Risk: {self.stats['medium_risk_paths']} paths")
        print(f"  Low Risk:    {self.stats['low_risk_paths']} paths")
        
        print(f"\n Coverage:")
        print(f"  Sources: {self.stats['total_sources']}")
        print(f"  Sinks: {self.stats['total_sinks']}")
        print(f"  Tainted Sinks: {self.stats['tainted_sinks']}")
        
         high_risk_paths = [p for p in self.tainted_paths if p.risk_level == RiskLevel.HIGH]
        if high_risk_paths:
            print(f"\n Sample High-Risk Paths:")
            for path in high_risk_paths[:3]:
                print(f"\n  Path: {path.source_node} → {path.sink_node}")
                print(f"  Source Type: {path.source_type}")
                print(f"  Sink Type: {path.sink_type}")
                print(f"  Length: {path.path_length} nodes")
                print(f"  Risk Factors: {[f.value for f in path.risk_factors]}")
                if path.mitigating_factors:
                    print(f"  Mitigating: {[f.value for f in path.mitigating_factors]}")


def analyze_contract(contract_name: str):
     analyzer = TaintAnalyzer(contract_name)
    return analyzer.analyze()


def analyze_all_contracts(graph_path: str = "contract_ast"):
     print("\nStarting Taint Analysis for All Contracts...")
    
     graph_files = [f for f in os.listdir(graph_path) 
                   if f.endswith("_semantic_graph.json")]
    
    print(f"Found {len(graph_files)} contracts to analyze")
    
    successful = 0
    failed = 0
    
    for graph_file in graph_files:
        contract_name = graph_file.replace("_semantic_graph.json", "")
        
        try:
            if analyze_contract(contract_name):
                successful += 1
            else:
                failed += 1
        except Exception as e:
            print(f" Error analyzing {contract_name}: {str(e)}")
            failed += 1
            
    print(f"\n{'='*80}")
    print(f" FINAL RESULTS:")
    print(f"  Successful: {successful}")
    print(f"   Failed: {failed}")
    print(f"   Total: {len(graph_files)}")
    

if __name__ == "__main__":
      analyze_all_contracts()
