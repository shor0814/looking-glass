# Looking Glass Feature Roadmap

This document outlines common features found in looking glass applications that could be added to enhance functionality.

## Currently Implemented Features

- ✅ Ping (IPv4/IPv6)
- ✅ Traceroute (IPv4/IPv6)
- ✅ BGP Route Lookup
- ✅ AS Path Regex Search
- ✅ AS Number Lookup
- ✅ MTR (My Traceroute) - partially implemented

## Recommended Features to Add

### 1. Network Diagnostic Tools

#### Speed Tests
- **File Download Speed Test** (Your Request)
  - Download test files of various sizes (1MB, 10MB, 100MB, 1GB)
  - Measure download speed, latency, and throughput
  - Support for IPv4 and IPv6
  - Multiple test servers/locations
  - Real-time progress display
  - Results: Download speed (Mbps/Gbps), latency, packet loss

- **Bandwidth Test**
  - Upload speed test
  - Bidirectional bandwidth test
  - Jitter measurement
  - Packet loss statistics

#### Advanced Network Tools
- **MTR (My Traceroute)** - Full Implementation
  - Continuous traceroute with statistics
  - Packet loss per hop
  - Latency statistics per hop
  - Real-time updates

- **Path MTU Discovery**
  - Find maximum transmission unit (MTU) to destination
  - Useful for troubleshooting fragmentation issues

- **Reverse Traceroute**
  - Traceroute from destination back to source
  - Useful for asymmetric routing analysis

### 2. BGP and Routing Information

#### Enhanced BGP Queries
- **BGP Summary**
  - Show all BGP neighbors
  - Neighbor status (up/down)
  - AS numbers of peers
  - Prefix counts per neighbor
  - Uptime statistics

- **BGP Neighbor Details**
  - Detailed information about specific BGP neighbor
  - Session state, capabilities, timers
  - Received/advertised prefixes
  - Route refresh capability

- **BGP Community Lookup**
  - Search routes by BGP community
  - Filter by well-known communities (no-export, no-advertise, etc.)
  - Custom community search

- **BGP Large Community Support**
  - Search by large communities (32-bit ASN + 32-bit value)
  - Display large communities in route output

- **Route Server Queries**
  - Query route server for specific ASN
  - View routes from route server perspective
  - Compare routes across multiple route servers

- **ROA (Route Origin Authorization) Check**
  - Validate route origin against RPKI
  - Show RPKI validation status (Valid/Invalid/NotFound)

#### Route Information
- **Route Details**
  - Detailed route information (next-hop, AS path, communities)
  - Route attributes (MED, local preference, etc.)
  - Multiple paths for same prefix

- **Longest Prefix Match**
  - Find most specific route for an IP address
  - Show all matching routes

- **Route Count Statistics**
  - Total routes in routing table
  - Routes per protocol (BGP, OSPF, static, etc.)
  - Routes per ASN

### 3. DNS and Network Information

- **DNS Lookup**
  - Forward DNS (A, AAAA, MX, TXT, NS, CNAME records)
  - Reverse DNS (PTR records)
  - DNS over IPv6
  - Multiple DNS server selection

- **WHOIS Lookup**
  - IP address WHOIS
  - ASN WHOIS
  - Domain WHOIS
  - RIR information (ARIN, RIPE, APNIC, etc.)

- **IP Geolocation**
  - Geographic location of IP addresses
  - ISP information
  - City, country, coordinates

### 4. Network Statistics and Monitoring

- **Interface Statistics**
  - Interface utilization (in/out bytes, packets)
  - Error counters
  - Interface status (up/down)
  - Link speed and duplex

- **Traffic Statistics**
  - Top talkers (source/destination)
  - Protocol distribution
  - Traffic graphs (if data collection enabled)

- **System Information**
  - Router model/version
  - Uptime
  - CPU/Memory utilization
  - Temperature (if available)

### 5. Peering Information

- **PeeringDB Integration**
  - Display peering information from PeeringDB
  - Show peering locations
  - Display peering policies
  - Contact information for peering

- **IXP (Internet Exchange Point) Information**
  - List of connected IXPs
  - IXP member information
  - Peering LAN information

### 6. Security and Filtering

- **Route Filtering Information**
  - Show route filters (import/export policies)
  - Display prefix lists
  - Show AS path filters

- **Blackhole/Null Route Check**
  - Check if IP is blackholed
  - Display blackhole communities

### 7. Advanced Features

- **Historical Data**
  - Store and display historical route information
  - Track route changes over time
  - BGP session history

- **API Access**
  - RESTful API for programmatic access
  - JSON responses for all queries
  - API key authentication
  - Rate limiting

- **Batch Operations**
  - Test multiple destinations at once
  - Bulk BGP lookups
  - Compare routes across multiple routers

- **Export Results**
  - Export results as text, JSON, CSV
  - Shareable links for results
  - Email results

- **Comparison Tools**
  - Compare routes between routers
  - Compare BGP tables
  - Path comparison

### 8. User Experience Enhancements

- **Interactive Maps**
  - Visual traceroute with map
  - Geographic route visualization
  - AS path visualization

- **Graphs and Charts**
  - Latency graphs
  - Packet loss graphs
  - Bandwidth utilization charts

- **Mobile-Friendly Interface**
  - Responsive design improvements
  - Touch-friendly controls
  - Mobile-optimized speed tests

- **Dark Mode**
  - Already implemented (color-mode.js)
  - Ensure all new features support it

### 9. Multi-Datacenter Features (Already Implemented!)

- ✅ Datacenter selection
- ✅ Router selection per datacenter
- **Potential Enhancements:**
  - Compare routes across datacenters
  - Latency comparison between datacenters
  - Route diversity analysis

## Implementation Priority Recommendations

### High Priority (Most Commonly Requested)
1. **File Download Speed Test** (Your Request)
2. **BGP Summary** - Show all BGP neighbors
3. **DNS Lookup** - Forward and reverse DNS
4. **MTR Full Implementation** - Complete the MTR feature
5. **Route Details** - Enhanced route information

### Medium Priority
6. **WHOIS Lookup** - IP and ASN information
7. **BGP Community Lookup** - Community-based route search
8. **Interface Statistics** - Network interface information
9. **PeeringDB Integration** - Peering information
10. **API Access** - RESTful API for automation

### Low Priority (Nice to Have)
11. **Historical Data** - Route change tracking
12. **Interactive Maps** - Visual route visualization
13. **Batch Operations** - Multiple queries at once
14. **ROA/RPKI Validation** - Security validation

## Technical Considerations

### For Speed Tests
- Need test files hosted on web server
- Consider using existing speed test libraries (e.g., librespeed, speedtest-cli)
- May need separate endpoint for file downloads
- Consider bandwidth limits to prevent abuse

### For DNS/WHOIS
- Can use PHP's built-in functions (gethostbyname, dns_get_record)
- May need external APIs for WHOIS (whoisxmlapi.com, ipwhois.io)
- Consider caching to reduce API costs

### For BGP Summary
- Router-specific commands needed
- May need to parse tabular output
- Consider caching for frequently accessed data

### For API Access
- Need authentication mechanism
- Rate limiting essential
- JSON response format
- Versioning strategy

## Notes

- Some features may require router-specific implementations
- Consider security implications of each feature
- Rate limiting and abuse prevention important
- Some features may require external services/APIs
- Consider performance impact of new features
