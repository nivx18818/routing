####################################################
# LSrouter.py
# Name:
# HUID:
#####################################################

from router import Router
from packet import Packet
import json
import heapq

class LSrouter(Router):
    """Link state routing protocol implementation.

    Add your own class fields and initialization code (e.g. to create forwarding table
    data structures). See the `Router` base class for docstrings of the methods to
    override.
    """

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)
        self.heartbeat_time = heartbeat_time
        self.last_time = 0

        self.lsdb = {}  # lsdb: {router_addr: {neighbor_addr: cost, ...}}
        self.sequence_numbers = {}  # sequence_numbers: {router_addr: latest_sequence_number}
        self.my_links = {}  # my_links: {neighbor_addr: cost} - This router's direct links
        self.forwarding_table = {}  # forwarding_table: {destination_addr: output_port}
        self.seq = 0  # seq: This router's own sequence number for its LSPs
        self.port_to_neighbor = {}  # port_to_neighbor: {port: neighbor_addr}

        self.sequence_numbers[self.addr] = self.seq
        self.lsdb[self.addr] = {}

    def flood_lsp(self, packet, incoming_port):
        """Floods an LSP to all neighbors except the one it arrived on."""
        for p, _ in self.links.items(): # self.links is {port: LinkObject}
            if p != incoming_port:
                self.send(p, packet)  # Forward the original packet. Its src_addr is the LSP originator.

    def broadcast_link_state(self):
        """Broadcasts this router's current link state to all neighbors."""
        self.seq += 1
        self.sequence_numbers[self.addr] = self.seq

        self.lsdb[self.addr] = self.my_links.copy() # Update own entry in LSDB

        lsp_content_data = {
            "seq": self.seq,
            "links": self.my_links
        }
        lsp_content_json = json.dumps(lsp_content_data)

        for port, neighbor_addr in self.port_to_neighbor.items():
            # Create a new packet for the LSP
            # Packet source is self.addr. Destination is the neighbor.
            pkt = Packet(Packet.ROUTING, self.addr, neighbor_addr, lsp_content_json)
            self.send(port, pkt)

        self.compute_paths() # Recompute paths after own link state changes

    def compute_paths(self):
        """Compute shortest paths using Dijkstra's algorithm on self.lsdb."""
        dist = {self.addr: 0}  # Distance from self.addr
        prev = {self.addr: None}  # Previous hop to reach a node

        pq = [(0, self.addr)]  # Priority queue: (cost, node)

        while pq:
            d, u = heapq.heappop(pq)

            if d > dist.get(u, float('inf')):
                continue # Already found a shorter path to u

            if u not in self.lsdb:
                continue

            for v, cost_uv in self.lsdb[u].items():
                if dist.get(u, float('inf')) + cost_uv < dist.get(v, float('inf')):
                    dist[v] = dist[u] + cost_uv
                    prev[v] = u
                    heapq.heappush(pq, (dist[v], v))

        # Reconstruct forwarding table
        new_forwarding_table = {}
        for dest_node in dist:
            if dest_node == self.addr or dist[dest_node] == float('inf'):
                continue # Skip self or unreachable nodes

            # Trace back to find the first hop from self.addr to dest_node
            curr = dest_node
            while prev.get(curr) is not None and prev[curr] != self.addr:
                curr = prev[curr]

            # Now, 'curr' is the first hop neighbor (or dest_node if directly connected)
            # Find the port connected to this first hop 'curr'
            port_to_next_hop = None
            for p, neighbor_addr_lookup in self.port_to_neighbor.items():
                if neighbor_addr_lookup == curr:
                    port_to_next_hop = p
                    break

            if port_to_next_hop is not None:
                new_forwarding_table[dest_node] = port_to_next_hop

        self.forwarding_table = new_forwarding_table

    def handle_packet(self, port, packet):
        """Process incoming packet."""
        if packet.is_traceroute:
            if packet.dst_addr == self.addr:
                # Packet has reached its destination
                return
            if packet.dst_addr in self.forwarding_table:
                out_port = self.forwarding_table[packet.dst_addr]
                self.send(out_port, packet)
        else:
            try:
                lsp_data = json.loads(packet.content)
                lsp_origin = packet.src_addr  # The router that originated this LSP
                lsp_seq = lsp_data['seq']
                lsp_links = lsp_data['links']
            except (json.JSONDecodeError, KeyError, TypeError):
                # Invalid LSP format
                return

            if lsp_origin == self.addr:
                # Ignore LSPs from self that were flooded back
                return

            # Update if LSP is from a new origin or has a higher sequence number
            if lsp_origin not in self.sequence_numbers or lsp_seq > self.sequence_numbers[lsp_origin]:
                self.sequence_numbers[lsp_origin] = lsp_seq
                self.lsdb[lsp_origin] = lsp_links.copy() # Store a copy of the links

                self.compute_paths()  # Recompute forwarding table
                self.flood_lsp(packet, port) # Flood LSP to other neighbors

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        self.my_links[endpoint] = cost
        self.port_to_neighbor[port] = endpoint
        self.broadcast_link_state()

    def handle_remove_link(self, port):
        """Handle removed link."""
        if port in self.port_to_neighbor:
            neighbor = self.port_to_neighbor.pop(port)
            if neighbor in self.my_links:
                self.my_links.pop(neighbor)
        self.broadcast_link_state()

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.broadcast_link_state()

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        links_repr = {}
        for p, neighbor_addr in self.port_to_neighbor.items():
            cost = self.my_links.get(neighbor_addr, float('inf')) # Get cost from my_links
            links_repr[p] = (neighbor_addr, cost)
        return (
            f"LSrouter(addr={self.addr}, seq={self.seq}\n"
            f"  links(direct)={links_repr}\n"
            f"  my_links(LSP_payload)={self.my_links}\n"
            f"  lsdb={self.lsdb}\n"
            f"  sequence_numbers={self.sequence_numbers}\n"
            f"  forwarding_table={self.forwarding_table})"
        )
