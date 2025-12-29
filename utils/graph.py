"""
ThreatTracer Graph Analyzer

Graph-based analysis for infrastructure relationship mapping and clustering.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional
import hashlib

import networkx as nx

from threattracer.core.models import (
    Indicator,
    IndicatorType,
    Relationship,
    RelationshipType,
    InfrastructureCluster,
    ThreatLevel,
    Confidence,
)


@dataclass
class GraphNode:
    """Node in the infrastructure graph"""
    id: str
    type: IndicatorType
    value: str
    attributes: dict = field(default_factory=dict)
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN


@dataclass
class GraphEdge:
    """Edge in the infrastructure graph"""
    source_id: str
    target_id: str
    relationship: RelationshipType
    weight: float = 1.0
    attributes: dict = field(default_factory=dict)


class InfrastructureGraph:
    """
    Graph representation of threat actor infrastructure.
    
    Nodes represent indicators (IPs, domains, certs, fingerprints).
    Edges represent relationships between indicators.
    """
    
    def __init__(self):
        self.graph = nx.Graph()
        self._node_lookup: dict[str, GraphNode] = {}
    
    def _make_node_id(self, indicator_type: IndicatorType, value: str) -> str:
        """Create a unique node ID"""
        return f"{indicator_type.value}:{value}"
    
    def add_node(
        self,
        indicator_type: IndicatorType,
        value: str,
        threat_level: ThreatLevel = ThreatLevel.UNKNOWN,
        **attributes
    ) -> str:
        """Add a node to the graph"""
        node_id = self._make_node_id(indicator_type, value)
        
        node = GraphNode(
            id=node_id,
            type=indicator_type,
            value=value,
            threat_level=threat_level,
            attributes=attributes,
        )
        
        self._node_lookup[node_id] = node
        self.graph.add_node(
            node_id,
            type=indicator_type.value,
            value=value,
            threat_level=threat_level.value,
            **attributes
        )
        
        return node_id
    
    def add_edge(
        self,
        source_type: IndicatorType,
        source_value: str,
        target_type: IndicatorType,
        target_value: str,
        relationship: RelationshipType,
        weight: float = 1.0,
        **attributes
    ) -> None:
        """Add an edge between two nodes"""
        source_id = self._make_node_id(source_type, source_value)
        target_id = self._make_node_id(target_type, target_value)
        
        # Ensure nodes exist
        if source_id not in self.graph:
            self.add_node(source_type, source_value)
        if target_id not in self.graph:
            self.add_node(target_type, target_value)
        
        self.graph.add_edge(
            source_id,
            target_id,
            relationship=relationship.value,
            weight=weight,
            **attributes
        )
    
    def add_relationship(self, relationship: Relationship) -> None:
        """Add a relationship to the graph"""
        self.add_edge(
            relationship.source.type,
            relationship.source.value,
            relationship.target.type,
            relationship.target.value,
            relationship.relationship_type,
        )
    
    def get_node(self, indicator_type: IndicatorType, value: str) -> Optional[GraphNode]:
        """Get a node by type and value"""
        node_id = self._make_node_id(indicator_type, value)
        return self._node_lookup.get(node_id)
    
    def get_neighbors(self, indicator_type: IndicatorType, value: str) -> list[GraphNode]:
        """Get all neighbors of a node"""
        node_id = self._make_node_id(indicator_type, value)
        if node_id not in self.graph:
            return []
        
        neighbor_ids = list(self.graph.neighbors(node_id))
        return [self._node_lookup[nid] for nid in neighbor_ids if nid in self._node_lookup]
    
    def find_path(
        self,
        source_type: IndicatorType,
        source_value: str,
        target_type: IndicatorType,
        target_value: str,
    ) -> Optional[list[GraphNode]]:
        """Find shortest path between two nodes"""
        source_id = self._make_node_id(source_type, source_value)
        target_id = self._make_node_id(target_type, target_value)
        
        try:
            path_ids = nx.shortest_path(self.graph, source_id, target_id)
            return [self._node_lookup[nid] for nid in path_ids if nid in self._node_lookup]
        except nx.NetworkXNoPath:
            return None
    
    def find_clusters(self, min_size: int = 2) -> list[InfrastructureCluster]:
        """Find connected components (clusters) in the graph"""
        clusters = []
        
        for i, component in enumerate(nx.connected_components(self.graph)):
            if len(component) < min_size:
                continue
            
            # Extract cluster members by type
            ips = []
            domains = []
            certs = []
            jarms = []
            favicons = []
            
            for node_id in component:
                node = self._node_lookup.get(node_id)
                if not node:
                    continue
                
                if node.type == IndicatorType.IP:
                    ips.append(node.value)
                elif node.type == IndicatorType.DOMAIN:
                    domains.append(node.value)
                elif node.type == IndicatorType.CERT_FINGERPRINT:
                    certs.append(node.value)
                elif node.type == IndicatorType.JARM:
                    jarms.append(node.value)
                elif node.type == IndicatorType.FAVICON_HASH:
                    favicons.append(node.value)
            
            # Determine cluster threat level
            threat_levels = [
                self._node_lookup[nid].threat_level 
                for nid in component 
                if nid in self._node_lookup
            ]
            
            if ThreatLevel.MALICIOUS in threat_levels:
                cluster_threat = ThreatLevel.MALICIOUS
            elif ThreatLevel.SUSPICIOUS in threat_levels:
                cluster_threat = ThreatLevel.SUSPICIOUS
            else:
                cluster_threat = ThreatLevel.UNKNOWN
            
            cluster = InfrastructureCluster(
                cluster_id=hashlib.md5(str(sorted(component)).encode()).hexdigest()[:8],
                ips=ips,
                domains=domains,
                certificates=certs,
                shared_jarm=jarms,
                shared_favicon=[int(f) for f in favicons if f.lstrip('-').isdigit()],
                threat_level=cluster_threat,
            )
            clusters.append(cluster)
        
        return clusters
    
    def get_central_nodes(self, top_n: int = 10) -> list[tuple[GraphNode, float]]:
        """Get the most central nodes by betweenness centrality"""
        if len(self.graph) == 0:
            return []
        
        centrality = nx.betweenness_centrality(self.graph)
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        
        results = []
        for node_id, score in sorted_nodes[:top_n]:
            if node_id in self._node_lookup:
                results.append((self._node_lookup[node_id], score))
        
        return results
    
    def get_statistics(self) -> dict:
        """Get graph statistics"""
        if len(self.graph) == 0:
            return {"nodes": 0, "edges": 0}
        
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "density": nx.density(self.graph),
            "components": nx.number_connected_components(self.graph),
            "avg_degree": sum(dict(self.graph.degree()).values()) / self.graph.number_of_nodes(),
        }
    
    def to_dict(self) -> dict:
        """Export graph to dictionary format"""
        nodes = []
        for node_id, node in self._node_lookup.items():
            nodes.append({
                "id": node_id,
                "type": node.type.value,
                "value": node.value,
                "threat_level": node.threat_level.value,
                "attributes": node.attributes,
            })
        
        edges = []
        for source, target, data in self.graph.edges(data=True):
            edges.append({
                "source": source,
                "target": target,
                "relationship": data.get("relationship"),
                "weight": data.get("weight", 1.0),
            })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "statistics": self.get_statistics(),
        }
    
    def to_cytoscape(self) -> dict:
        """Export graph to Cytoscape.js format for visualization"""
        elements = []
        
        for node_id, node in self._node_lookup.items():
            elements.append({
                "data": {
                    "id": node_id,
                    "label": node.value[:30],
                    "type": node.type.value,
                    "threat_level": node.threat_level.value,
                }
            })
        
        for source, target, data in self.graph.edges(data=True):
            elements.append({
                "data": {
                    "source": source,
                    "target": target,
                    "relationship": data.get("relationship"),
                }
            })
        
        return {"elements": elements}


def build_infrastructure_graph(
    ips: list[dict],
    relationships: list[Relationship] = None,
) -> InfrastructureGraph:
    """
    Build an infrastructure graph from enrichment data.
    
    Args:
        ips: List of enriched IP data dictionaries
        relationships: Optional list of explicit relationships
        
    Returns:
        InfrastructureGraph instance
    """
    graph = InfrastructureGraph()
    
    # Track shared attributes for implicit relationships
    jarm_to_ips: dict[str, list[str]] = defaultdict(list)
    favicon_to_ips: dict[int, list[str]] = defaultdict(list)
    asn_to_ips: dict[int, list[str]] = defaultdict(list)
    cert_to_ips: dict[str, list[str]] = defaultdict(list)
    
    # Add IP nodes and collect shared attributes
    for ip_data in ips:
        ip = ip_data.get("ip")
        if not ip:
            continue
        
        threat_level = ThreatLevel(ip_data.get("threat_level", "unknown"))
        
        graph.add_node(
            IndicatorType.IP,
            ip,
            threat_level=threat_level,
            country=ip_data.get("country"),
            asn=ip_data.get("asn"),
        )
        
        # Track JARM
        jarm = ip_data.get("jarm")
        if jarm:
            jarm_to_ips[jarm].append(ip)
            graph.add_node(IndicatorType.JARM, jarm)
            graph.add_edge(
                IndicatorType.IP, ip,
                IndicatorType.JARM, jarm,
                RelationshipType.SHARES_JARM,
            )
        
        # Track favicon
        favicon = ip_data.get("favicon_hash")
        if favicon:
            favicon_to_ips[favicon].append(ip)
            graph.add_node(IndicatorType.FAVICON_HASH, str(favicon))
            graph.add_edge(
                IndicatorType.IP, ip,
                IndicatorType.FAVICON_HASH, str(favicon),
                RelationshipType.SHARES_FAVICON,
            )
        
        # Track ASN
        asn = ip_data.get("asn")
        if asn:
            asn_to_ips[asn].append(ip)
        
        # Track domains
        for domain in ip_data.get("domains", []):
            graph.add_node(IndicatorType.DOMAIN, domain)
            graph.add_edge(
                IndicatorType.IP, ip,
                IndicatorType.DOMAIN, domain,
                RelationshipType.RESOLVES_TO,
            )
    
    # Add explicit relationships
    if relationships:
        for rel in relationships:
            graph.add_relationship(rel)
    
    return graph
