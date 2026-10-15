import { useState, useEffect, useCallback, useMemo } from 'react'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import {
  Search, Globe, Server, Shield, ChevronRight, ChevronLeft,
  Loader2, AlertTriangle, Database, ShieldAlert, MessageSquare,
  MapPin, Building2, Wifi, Bug, Tag, Clock, Filter, SlidersHorizontal,
  X, Check, Sparkles, Terminal, ChevronDown, ChevronUp, Plus
} from 'lucide-react'
import '../SearchPage.css'

const API_BASE = 'http://localhost:8000/api'

// Comprehensive Shodan Search Filter Catalog (43 Filters across 7 Categories)
const SEARCH_FILTER_CATEGORIES = [
  {
    id: 'network',
    title: 'General & Network',
    icon: 'Wifi',
    description: 'IP addresses, CIDR subnets, autonomous systems, open ports, and hostnames',
    filters: [
      { name: 'all', desc: 'Searches across searchable banner fields', example: 'all:OpenSSH' },
      { name: 'ip', desc: 'Matches a specific IP address', example: 'ip:103.125.155.37' },
      { name: 'net', desc: 'Matches an IP address or CIDR network range', example: 'net:103.125.155.0/24' },
      { name: 'port', desc: 'Matches an open port number', example: 'port:22' },
      { name: 'asn', desc: 'Matches an Autonomous System Number (ASN)', example: 'asn:AS212317' },
      { name: 'org', desc: 'Matches the organization associated with an IP', example: 'org:"Hetzner Online"' },
      { name: 'isp', desc: 'Matches the Internet Service Provider', example: 'isp:"Akamai Connected Cloud"' },
      { name: 'hostname', desc: 'Matches a hostname associated with a device', example: 'hostname:your-server.de' },
      { name: 'has_ipv6', desc: 'Filters records based on IPv6 metadata availability', example: 'has_ipv6:true' },
    ]
  },
  {
    id: 'geo',
    title: 'Geographic',
    icon: 'MapPin',
    description: 'Physical geolocation, countries, states, and regions',
    filters: [
      { name: 'country', desc: 'Matches a two-letter country code or country name', example: 'country:IN' },
      { name: 'city', desc: 'Matches the city associated with a device', example: 'city:"Portland"' },
      { name: 'state', desc: 'Matches the state or province associated with a device', example: 'state:California' },
      { name: 'region', desc: 'Matches a geographic region when indexed', example: 'region:"us-nj"' },
    ]
  },
  {
    id: 'software',
    title: 'Software & Device',
    icon: 'Server',
    description: 'Operating systems, application products, CPEs, and banner hashes',
    filters: [
      { name: 'product', desc: 'Matches an identified software product or service', example: 'product:openssh' },
      { name: 'version', desc: 'Matches a detected software version', example: 'version:1.16.1' },
      { name: 'os', desc: 'Matches the detected operating system', example: 'os:linux' },
      { name: 'cpe', desc: 'Matches a Common Platform Enumeration identifier', example: 'cpe:openssh' },
      { name: 'tag', desc: 'Matches a Shodan-assigned tag', example: 'tag:database' },
      { name: 'hash', desc: 'Matches a banner hash', example: 'hash:12345' },
    ]
  },
  {
    id: 'security',
    title: 'Vulnerability & Security',
    icon: 'Shield',
    description: 'Vulnerability CVE identifiers, SSL existence, and screenshots',
    filters: [
      { name: 'vuln', desc: 'Matches a specific vulnerability identifier (CVE)', example: 'vuln:CVE-2026-60002' },
      { name: 'has_vuln', desc: 'Filters records based on presence of vulnerability metadata', example: 'has_vuln:true' },
      { name: 'has_ssl', desc: 'Filters records based on SSL/TLS metadata availability', example: 'has_ssl:true' },
      { name: 'has_screenshot', desc: 'Filters records with screenshot metadata', example: 'has_screenshot:true' },
    ]
  },
  {
    id: 'http',
    title: 'HTTP & Web-Server',
    icon: 'Globe',
    description: 'Web technologies, HTTP status codes, titles, WAFs, and web hashes',
    filters: [
      { name: 'http.component', desc: 'Matches detected web technologies or components', example: 'http.component:nginx' },
      { name: 'http.component_category', desc: 'Matches the category of a detected web technology', example: 'http.component_category:"Web servers"' },
      { name: 'http.favicon.hash', desc: 'Matches a website favicon hash', example: 'http.favicon.hash:12345' },
      { name: 'http.html_hash', desc: 'Matches the hash of HTTP HTML content', example: 'http.html_hash:12345' },
      { name: 'http.robots_hash', desc: 'Matches the hash of robots.txt content', example: 'http.robots_hash:12345' },
      { name: 'http.securitytxt', desc: 'Matches security.txt-related metadata', example: 'http.securitytxt:contact' },
      { name: 'http.status', desc: 'Matches an HTTP response status code', example: 'http.status:200' },
      { name: 'http.title', desc: 'Matches text in an HTTP page title', example: 'http.title:"Apache2 Debian"' },
      { name: 'http.waf', desc: 'Matches detected web application firewall metadata', example: 'http.waf:cloudflare' },
      { name: 'title', desc: 'Matches a title field where supported by the indexed data', example: 'title:"Dashboard"' },
    ]
  },
  {
    id: 'ssl',
    title: 'SSL/TLS & Certificate',
    icon: 'Lock',
    description: 'TLS versions, subject/issuer CN, fingerprints, and JA3/JARM',
    filters: [
      { name: 'ssl', desc: 'Matches SSL/TLS-related banner information', example: 'ssl:"Let\'s Encrypt"' },
      { name: 'ssl.alpn', desc: 'Matches the negotiated application protocol metadata', example: 'ssl.alpn:h2' },
      { name: 'ssl.cert.fingerprint', desc: 'Matches a certificate fingerprint', example: 'ssl.cert.fingerprint:fb:77' },
      { name: 'ssl.cert.issuer.cn', desc: 'Matches the certificate issuer\'s common name', example: 'ssl.cert.issuer.cn:"R3"' },
      { name: 'ssl.cert.serial', desc: 'Matches the certificate serial number', example: 'ssl.cert.serial:12345' },
      { name: 'ssl.cert.subject.cn', desc: 'Matches the certificate subject\'s common name', example: 'ssl.cert.subject.cn:"*.netart.com"' },
      { name: 'ssl.ja3s', desc: 'Matches a JA3S TLS server fingerprint', example: 'ssl.ja3s:12345' },
      { name: 'ssl.jarm', desc: 'Matches a JARM TLS fingerprint', example: 'ssl.jarm:12345' },
      { name: 'ssl.version', desc: 'Matches SSL/TLS version metadata', example: 'ssl.version:TLSv1.2' },
    ]
  },
  {
    id: 'ssh',
    title: 'SSH',
    icon: 'Terminal',
    description: 'Secure Shell fingerprints and host-key configurations',
    filters: [
      { name: 'ssh.fingerprint', desc: 'Matches an SSH host-key fingerprint', example: 'ssh.fingerprint:fb:77:af:03' },
    ]
  }
]

const QUICK_PRESETS = [
  { label: 'Port 22 (SSH)', query: 'port:22' },
  { label: 'Port 80 (HTTP)', query: 'port:80' },
  { label: 'Port 443 (HTTPS)', query: 'port:443' },
  { label: 'Known Vulnerabilities', query: 'has_vuln:true' },
  { label: 'SSL Enabled', query: 'has_ssl:true' },
  { label: 'OpenSSH Servers', query: 'product:openssh' },
  { label: 'India Hosts', query: 'country:IN' },
  { label: 'US Hosts', query: 'country:US' },
]

function formatDate(val) {
  if (!val) return ''
  try {
    const d = new Date(val)
    if (isNaN(d.getTime())) return String(val)
    return d.toLocaleDateString()
  } catch {
    return String(val)
  }
}

export default function SearchPage() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()

  const [query, setQuery] = useState(searchParams.get('q') || '')
  const [inputValue, setInputValue] = useState(searchParams.get('q') || '')
  const [page, setPage] = useState(parseInt(searchParams.get('page') || '1'))
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [stats, setStats] = useState(null)
  const [showFilterGuide, setShowFilterGuide] = useState(false)
  const [activeCategoryTab, setActiveCategoryTab] = useState('network')

  // Fetch stats on mount
  useEffect(() => {
    fetch(`${API_BASE}/stats`)
      .then(r => r.json())
      .then(setStats)
      .catch(() => {})
  }, [])

  // Search when query or page changes
  const doSearch = useCallback(async (q, p) => {
    if (!q.trim()) {
      setResults(null)
      return
    }
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(`${API_BASE}/search?q=${encodeURIComponent(q)}&page=${p}`)
      if (!res.ok) throw new Error(`Server error: ${res.status}`)
      const data = await res.json()
      setResults(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (query) {
      doSearch(query, page)
    }
  }, [query, page, doSearch])

  // Synchronize state when browser Back / Forward navigation occurs
  useEffect(() => {
    const qFromUrl = searchParams.get('q') || ''
    const pFromUrl = Math.max(1, parseInt(searchParams.get('page') || '1', 10) || 1)
    if (qFromUrl !== query) {
      setQuery(qFromUrl)
      setInputValue(qFromUrl)
    }
    if (pFromUrl !== page) {
      setPage(pFromUrl)
    }
    if (!qFromUrl) {
      setResults(null)
    }
  }, [searchParams])

  // Close filter catalog on Escape key
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && showFilterGuide) {
        setShowFilterGuide(false)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [showFilterGuide])

  const handleSearch = (e) => {
    if (e) e.preventDefault()
    const trimmed = inputValue.trim()
    if (!trimmed) return
    setPage(1)
    setQuery(trimmed)
    setSearchParams({ q: trimmed, page: '1' })
    doSearch(trimmed, 1)
  }

  const handleFacetClick = (filterType, value) => {
    const formattedVal = String(value).includes(' ') ? `"${value}"` : value
    const token = `${filterType}:${formattedVal}`
    if (inputValue.includes(token)) return

    // If an existing filter token of the same key exists, replace it
    const escapedType = filterType.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const typeRegex = new RegExp(`(-?${escapedType}):("([^"]+)"|(\\S+))`, 'i')
    let newQ
    if (typeRegex.test(inputValue)) {
      newQ = inputValue.replace(typeRegex, token).trim()
    } else {
      newQ = inputValue.trim() ? `${inputValue.trim()} ${token}` : token
    }

    setInputValue(newQ)
    setPage(1)
    setQuery(newQ)
    setSearchParams({ q: newQ, page: '1' })
    doSearch(newQ, 1)
  }

  const handlePageChange = (newPage) => {
    setPage(newPage)
    setSearchParams({ q: query, page: String(newPage) })
    window.scrollTo(0, 0)
  }

  const handleApplyFilter = (filterSyntax, executeNow = false) => {
    let newQ = inputValue.trim()
    if (newQ.length > 0 && !newQ.includes(filterSyntax)) {
      newQ = `${newQ} ${filterSyntax}`
    } else if (newQ.length === 0) {
      newQ = filterSyntax
    }
    setInputValue(newQ)
    if (executeNow) {
      setPage(1)
      setQuery(newQ)
      setSearchParams({ q: newQ, page: '1' })
      doSearch(newQ, 1)
    }
  }

  const handleRemoveFilter = (filterToken) => {
    const escaped = filterToken.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const regex = new RegExp(`\\s*${escaped}\\s*`, 'g')
    const newQ = inputValue.replace(regex, ' ').trim()
    setInputValue(newQ)
    setPage(1)
    setQuery(newQ)
    if (newQ) {
      setSearchParams({ q: newQ, page: '1' })
      doSearch(newQ, 1)
    } else {
      setResults(null)
      setSearchParams({})
    }
  }

  // Parse active filter tokens from inputValue
  const activeFilterTokens = useMemo(() => {
    if (!inputValue) return []
    const tokens = []
    const pattern = /(-?[a-zA-Z0-9_.]+):("([^"]+)"|(\S+))/g
    let match
    while ((match = pattern.exec(inputValue)) !== null) {
      tokens.push({
        raw: match[0],
        key: match[1],
        val: match[3] !== undefined ? match[3] : match[4]
      })
    }
    return tokens
  }, [inputValue])

  const totalPages = results ? Math.ceil(results.total / results.per_page) : 0
  const activeCategory = SEARCH_FILTER_CATEGORIES.find(c => c.id === activeCategoryTab) || SEARCH_FILTER_CATEGORIES[0]

  return (
    <div className="search-page">
      {/* Top Navigation */}
      <nav className="search-nav">
        <div className="search-nav-left">
          <Link to="/" className="nav-brand">
            <ShieldAlert size={22} />
            <span>CTI Agent</span>
          </Link>
        </div>
        <div className="search-nav-links">
          <Link to="/" className="nav-link">
            <MessageSquare size={16} />
            <span>Chat</span>
          </Link>
          <Link to="/search" className="nav-link active">
            <Search size={16} />
            <span>Search</span>
          </Link>
        </div>
      </nav>

      {/* Hero Header */}
      {!results && !loading && (
        <div className="search-hero">
          <div className="search-hero-glow" />
          <h1 className="search-hero-title">
            <Database size={36} className="hero-icon" />
            CTI Shodan Engine
          </h1>
          <p className="search-hero-subtitle">
            Search your local threat intelligence database across 43 Shodan-style network, security, and banner filters
          </p>
          {stats && (
            <div className="search-hero-stats">
              <div className="hero-stat">
                <Server size={18} />
                <span className="stat-number">{stats.total_hosts?.toLocaleString() || 0}</span>
                <span className="stat-label">Hosts</span>
              </div>
              <div className="hero-stat">
                <Shield size={18} />
                <span className="stat-number">{stats.total_scans?.toLocaleString() || 0}</span>
                <span className="stat-label">Scans</span>
              </div>
              <div className="hero-stat">
                <Bug size={18} />
                <span className="stat-number">{stats.total_cves?.toLocaleString() || 0}</span>
                <span className="stat-label">CVEs</span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Search Bar Container */}
      <div className={`search-bar-container ${results || loading ? 'compact' : ''}`}>
        <form onSubmit={handleSearch} className="search-form">
          <div className="search-input-wrapper">
            <Search size={18} className="search-icon" />
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder='Search by: port:22, country:IN, net:103.125.155.0/24, vuln:CVE-2026-60002, has_ssl:true'
              className="search-input"
              autoFocus
            />
            {inputValue && (
              <button
                type="button"
                onClick={() => { setInputValue(''); setQuery(''); setResults(null); setSearchParams({}) }}
                style={{ background: 'none', border: 'none', color: 'rgba(224, 224, 232, 0.4)', cursor: 'pointer', padding: 6 }}
                title="Clear input"
              >
                <X size={16} />
              </button>
            )}
            <button type="submit" className="search-submit-btn" disabled={loading} title="Run search">
              {loading ? <Loader2 size={18} className="spin" /> : <ChevronRight size={18} />}
            </button>
          </div>
        </form>

        {/* Action Controls & Filter Guide Toggle */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 10, flexWrap: 'wrap', gap: 8 }}>
          {/* Quick Presets */}
          <div className="quick-presets-bar">
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'rgba(224, 224, 232, 0.4)', letterSpacing: 0.4 }}>
              Presets:
            </span>
            {QUICK_PRESETS.map((p, i) => (
              <button
                key={i}
                type="button"
                className="quick-preset-chip"
                onClick={() => handleApplyFilter(p.query, true)}
              >
                {p.label}
              </button>
            ))}
          </div>

          {/* Toggle Filter Guide */}
          <button
            type="button"
            className="filter-guide-toggle-btn"
            onClick={() => setShowFilterGuide(!showFilterGuide)}
          >
            <SlidersHorizontal size={13} />
            <span>Filter Catalog ({SEARCH_FILTER_CATEGORIES.reduce((acc, c) => acc + c.filters.length, 0)} Filters)</span>
            {showFilterGuide ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          </button>
        </div>

        {/* Active Filter Chips */}
        {activeFilterTokens.length > 0 && (
          <div className="active-filters-bar">
            <span className="active-filters-label">Active Filters:</span>
            {activeFilterTokens.map((t, idx) => (
              <span key={idx} className="active-filter-chip">
                <span className="chip-key">{t.key}:</span>
                <span className="chip-val">{t.val}</span>
                <button
                  type="button"
                  onClick={() => handleRemoveFilter(t.raw)}
                  title={`Remove ${t.key} filter`}
                >
                  <X size={12} />
                </button>
              </span>
            ))}
            <button
              type="button"
              className="active-filters-clear-btn"
              onClick={() => { setInputValue(''); setQuery(''); setResults(null); setSearchParams({}) }}
            >
              Clear all
            </button>
          </div>
        )}

        {/* Interactive Filter Guide Dropdown Panel */}
        {showFilterGuide && (
          <div className="filter-guide-panel">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              {/* Category Tabs */}
              <div className="filter-guide-categories-bar" style={{ margin: 0, flex: 1 }}>
                {SEARCH_FILTER_CATEGORIES.map(cat => (
                  <button
                    key={cat.id}
                    type="button"
                    className={`filter-category-pill ${activeCategoryTab === cat.id ? 'active' : ''}`}
                    onClick={() => setActiveCategoryTab(cat.id)}
                  >
                    <span>{cat.title}</span>
                    <span className="badge-count">{cat.filters.length}</span>
                  </button>
                ))}
              </div>
              <button
                type="button"
                onClick={() => setShowFilterGuide(false)}
                style={{ background: 'none', border: 'none', color: 'rgba(224, 224, 232, 0.4)', cursor: 'pointer', padding: 6, display: 'flex', alignItems: 'center' }}
                title="Close catalog (Esc)"
              >
                <X size={16} />
              </button>
            </div>

            {/* Category Description */}
            <div style={{ fontSize: 12.5, color: 'rgba(224, 224, 232, 0.55)', marginBottom: 12 }}>
              {activeCategory.description}
            </div>

            {/* Filter Cards Grid */}
            <div className="filter-cards-grid">
              {activeCategory.filters.map((f, i) => (
                <div key={i} className="filter-card-item">
                  <div className="filter-card-top">
                    <span className="filter-name-tag">{f.name}:</span>
                    <button
                      type="button"
                      className="filter-action-btn"
                      onClick={() => handleApplyFilter(f.example, false)}
                      title="Append to search bar"
                    >
                      <Plus size={12} /> Add
                    </button>
                  </div>
                  <div className="filter-desc-text">{f.desc}</div>
                  <div className="filter-example-bar">
                    <span className="filter-example-code">{f.example}</span>
                    <button
                      type="button"
                      className="filter-action-btn"
                      style={{ color: '#86efac' }}
                      onClick={() => handleApplyFilter(f.example, true)}
                      title="Run this query now"
                    >
                      Search
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="search-error">
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Results Area */}
      {(results || loading) && (
        <div className="search-results-layout">
          {/* Results list */}
          <div className="search-results-main">
            {loading && (
              <div className="search-loading">
                <Loader2 size={32} className="spin" />
                <span>Searching local threat intelligence database...</span>
              </div>
            )}

            {results && !loading && (
              <>
                <div className="results-header">
                  <span className="results-count">
                    {results.total.toLocaleString()} host{results.total !== 1 ? 's' : ''} found
                  </span>
                  <span className="results-page-info">
                    Page {results.page} of {Math.max(totalPages, 1)}
                  </span>
                </div>

                {results.results.length === 0 && (
                  <div className="no-results">
                    <Search size={48} />
                    <h3>No matching hosts found</h3>
                    <p>Try adjusting your query syntax or check the Filter Catalog above</p>
                  </div>
                )}

                <div className="results-list">
                  {results.results.map((host) => (
                    <div
                      key={host.ip}
                      className="result-card"
                      onClick={() => navigate(`/ip/${encodeURIComponent(host.ip)}`)}
                    >
                      <div className="result-card-header">
                        <div className="result-ip">
                          <Globe size={16} />
                          <span>{host.ip}</span>
                        </div>
                        <div className="result-badges">
                          {host.port_count > 0 && (
                            <span
                              className="result-badge port-badge"
                              onClick={(e) => {
                                e.stopPropagation()
                                navigate(`/ip/${encodeURIComponent(host.ip)}?tab=all`)
                              }}
                              title="View host ports"
                            >
                              <Wifi size={12} />
                              {host.port_count} port{host.port_count !== 1 ? 's' : ''}
                            </span>
                          )}
                          {host.cve_count > 0 && (
                            <span
                              className="result-badge cve-badge"
                              onClick={(e) => {
                                e.stopPropagation()
                                navigate(`/ip/${encodeURIComponent(host.ip)}?tab=vulns`)
                              }}
                              title="Jump directly to host vulnerabilities"
                            >
                              <Bug size={12} />
                              {host.cve_count} CVE{host.cve_count !== 1 ? 's' : ''}
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="result-card-meta">
                        {host.country && (
                          <span className="meta-item">
                            <MapPin size={13} />
                            {host.country}{host.city ? `, ${host.city}` : ''}
                          </span>
                        )}
                        {host.organization && (
                          <span className="meta-item">
                            <Building2 size={13} />
                            {host.organization}
                          </span>
                        )}
                        {host.os && (
                          <span className="meta-item">
                            <Server size={13} />
                            {host.os}
                          </span>
                        )}
                        {host.asn && (
                          <span className="meta-item">
                            <Tag size={13} />
                            {host.asn}
                          </span>
                        )}
                        {host.last_updated && formatDate(host.last_updated) && (
                          <span className="meta-item">
                            <Clock size={13} />
                            {formatDate(host.last_updated)}
                          </span>
                        )}
                      </div>

                      {host.open_ports && host.open_ports.length > 0 && (
                        <div className="result-card-ports">
                          {host.open_ports.slice(0, 8).map((p, i) => (
                            <span
                              key={i}
                              className="port-chip"
                              onClick={(e) => {
                                e.stopPropagation()
                                handleFacetClick('port', String(p.port_number))
                              }}
                              title={`Filter search by port:${p.port_number}`}
                            >
                              {p.port_number}
                              {p.service && <span className="port-service">/{p.service}</span>}
                            </span>
                          ))}
                          {host.open_ports.length > 8 && (
                            <span className="port-chip more">+{host.open_ports.length - 8} more</span>
                          )}
                        </div>
                      )}

                      <div className="result-card-arrow">
                        <ChevronRight size={18} />
                      </div>
                    </div>
                  ))}
                </div>

                {/* Pagination */}
                {totalPages > 1 && (
                  <div className="search-pagination">
                    <button
                      className="page-btn"
                      disabled={page <= 1}
                      onClick={() => handlePageChange(page - 1)}
                    >
                      <ChevronLeft size={16} /> Previous
                    </button>
                    <div className="page-numbers">
                      {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
                        let pageNum
                        if (totalPages <= 7) {
                          pageNum = i + 1
                        } else if (page <= 4) {
                          pageNum = i + 1
                        } else if (page >= totalPages - 3) {
                          pageNum = totalPages - 6 + i
                        } else {
                          pageNum = page - 3 + i
                        }
                        return (
                          <button
                            key={pageNum}
                            className={`page-num ${pageNum === page ? 'active' : ''}`}
                            onClick={() => handlePageChange(pageNum)}
                          >
                            {pageNum}
                          </button>
                        )
                      })}
                    </div>
                    <button
                      className="page-btn"
                      disabled={page >= totalPages}
                      onClick={() => handlePageChange(page + 1)}
                    >
                      Next <ChevronRight size={16} />
                    </button>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Facets Sidebar */}
          {results && results.facets && !loading && (
            <aside className="search-facets">
              {results.facets.countries?.length > 0 && (
                <div className="facet-group">
                  <h3 className="facet-title">
                    <MapPin size={14} />
                    Top Countries
                  </h3>
                  <div className="facet-list">
                    {results.facets.countries.map((f, i) => (
                      <button
                        key={i}
                        className="facet-item"
                        onClick={() => handleFacetClick('country', f.name)}
                      >
                        <span className="facet-name">{f.name}</span>
                        <span className="facet-count">{f.count}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {results.facets.ports?.length > 0 && (
                <div className="facet-group">
                  <h3 className="facet-title">
                    <Wifi size={14} />
                    Top Ports
                  </h3>
                  <div className="facet-list">
                    {results.facets.ports.map((f, i) => (
                      <button
                        key={i}
                        className="facet-item"
                        onClick={() => handleFacetClick('port', f.name)}
                      >
                        <span className="facet-name">{f.name}</span>
                        <span className="facet-count">{f.count}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {results.facets.orgs?.length > 0 && (
                <div className="facet-group">
                  <h3 className="facet-title">
                    <Building2 size={14} />
                    Top Organizations
                  </h3>
                  <div className="facet-list">
                    {results.facets.orgs.map((f, i) => (
                      <button
                        key={i}
                        className="facet-item"
                        onClick={() => handleFacetClick('org', f.name)}
                      >
                        <span className="facet-name">{f.name}</span>
                        <span className="facet-count">{f.count}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </aside>
          )}
        </div>
      )}
    </div>
  )
}
