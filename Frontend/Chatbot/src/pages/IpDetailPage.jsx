import { useState, useEffect } from 'react'
import { useParams, Link, useNavigate, useSearchParams } from 'react-router-dom'
import {
  Globe, Server, Shield, ChevronRight, ChevronDown, Loader2, AlertTriangle,
  ShieldAlert, MessageSquare, Search, MapPin, Building2, Wifi,
  Bug, Tag, Clock, ArrowLeft, ExternalLink, Database, Cpu,
  Lock, Network, Activity, Terminal, Copy, Check, Flame, Radar,
  Layers, Radio, CheckCircle2, XCircle, Info, Calendar, Hash,
  Cloud, FileText, CornerDownRight, Key, ShieldCheck
} from 'lucide-react'
import '../SearchPage.css'

const API_BASE = 'http://localhost:8000/api'

function formatHostnames(host) {
  const val = host?.Hostnames || host?.hostnames || host?.Domains || host?.domains
  if (!val) return null
  if (Array.isArray(val)) {
    const list = val.map(item => {
      if (!item) return ''
      if (typeof item === 'object') return item.name || item.hostname || JSON.stringify(item)
      return String(item)
    }).filter(Boolean)
    return list.length > 0 ? list.join(', ') : null
  }
  if (typeof val === 'object') return val.name || val.hostname || JSON.stringify(val)
  return String(val)
}

function formatDate(val, includeTime = false) {
  if (!val) return ''
  try {
    const d = new Date(val)
    if (isNaN(d.getTime())) return String(val)
    return includeTime ? d.toLocaleString() : d.toLocaleDateString()
  } catch {
    return String(val)
  }
}

export default function IpDetailPage() {
  const { ip } = useParams()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const initialTab = searchParams.get('tab') || 'all'

  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // Navigation tab state synchronized with URL search params
  const [activeTab, setActiveTabState] = useState(initialTab)
  const [vulnSeverityFilter, setVulnSeverityFilter] = useState('all')

  const setActiveTab = (tab) => {
    setActiveTabState(tab)
    if (tab === 'all') {
      const nextParams = new URLSearchParams(searchParams)
      nextParams.delete('tab')
      setSearchParams(nextParams, { replace: true })
    } else {
      const nextParams = new URLSearchParams(searchParams)
      nextParams.set('tab', tab)
      setSearchParams(nextParams, { replace: true })
    }
  }

  useEffect(() => {
    const t = searchParams.get('tab') || 'all'
    if (t !== activeTab) {
      setActiveTabState(t)
    }
  }, [searchParams])

  useEffect(() => {
    document.title = ip ? `${ip} | Host Intelligence — CTI Agent` : 'Host Details — CTI Agent'
  }, [ip])

  // Expansion state
  const [expandedPorts, setExpandedPorts] = useState({})
  const [expandedScripts, setExpandedScripts] = useState({})
  const [expandedScans, setExpandedScans] = useState({})
  const [copiedIp, setCopiedIp] = useState(false)
  const [copiedCmd, setCopiedCmd] = useState(false)

  useEffect(() => {
    setLoading(true)
    setError(null)
    fetch(`${API_BASE}/search/ip/${encodeURIComponent(ip)}`)
      .then(r => {
        if (!r.ok) throw new Error(`Server error: ${r.status}`)
        return r.json()
      })
      .then(res => {
        if (!res.found) {
          setError('IP not found in database')
        } else {
          setData(res.data)
          // Default expand first port if any
          const initialPortState = {}
          const shodanPorts = res.data.latest_shodan?.ports || []
          const nmapPorts = res.data.latest_nmap?.ports || []
          if (shodanPorts.length > 0) initialPortState[`shodan-${shodanPorts[0].port_number}`] = true
          if (nmapPorts.length > 0) initialPortState[`nmap-${nmapPorts[0].port_number}`] = true
          setExpandedPorts(initialPortState)
          if (res.data.scans?.length > 0) {
            setExpandedScans({ 0: true })
          }
        }
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [ip])

  const handleBack = () => {
    if (window.history.length > 2) {
      navigate(-1)
    } else {
      navigate('/search')
    }
  }

  const copyToClipboard = (text, type = 'ip') => {
    if (!text) return
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(String(text)).then(() => {
        if (type === 'ip') {
          setCopiedIp(true)
          setTimeout(() => setCopiedIp(false), 2000)
        } else if (type === 'cmd') {
          setCopiedCmd(true)
          setTimeout(() => setCopiedCmd(false), 2000)
        }
      }).catch(() => {})
    }
  }

  const togglePort = (key) => {
    setExpandedPorts(prev => ({ ...prev, [key]: !prev[key] }))
  }

  const toggleScript = (key) => {
    setExpandedScripts(prev => ({ ...prev, [key]: !prev[key] }))
  }

  const toggleScan = (idx) => {
    setExpandedScans(prev => ({ ...prev, [idx]: !prev[idx] }))
  }

  if (loading) {
    return (
      <div className="search-page">
        <Nav />
        <div className="detail-loading">
          <Loader2 size={40} className="spin" />
          <span>Loading complete host intelligence from database...</span>
        </div>
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="search-page">
        <Nav />
        <div className="detail-error">
          <AlertTriangle size={40} />
          <h2>{error || 'Host intelligence not available'}</h2>
          <div style={{ display: 'flex', gap: 12, marginTop: 12 }}>
            <button onClick={handleBack} className="back-btn-large">
              <ArrowLeft size={16} /> Go Back
            </button>
            <Link to="/search" className="back-btn-large" style={{ textDecoration: 'none' }}>
              <Search size={16} /> Search Engine
            </Link>
          </div>
        </div>
      </div>
    )
  }

  const { host = {}, scans = [], latest_shodan = null, latest_nmap = null, all_cves = [], scan_count = 0 } = data || {}

  // Calculate severity metrics
  const severityCounts = {
    critical: all_cves.filter(c => (c.cvss || 0) >= 9.0).length,
    high: all_cves.filter(c => (c.cvss || 0) >= 7.0 && (c.cvss || 0) < 9.0).length,
    medium: all_cves.filter(c => (c.cvss || 0) >= 4.0 && (c.cvss || 0) < 7.0).length,
    low: all_cves.filter(c => (c.cvss || 0) < 4.0).length,
  }

  const filteredCves = all_cves.filter(cve => {
    if (vulnSeverityFilter === 'all') return true
    const s = getCveSeverity(cve.cvss)
    return s === vulnSeverityFilter
  })

  // Extract raw details
  const shodanRaw = latest_shodan?.raw_data || {}
  const shodanGeneral = shodanRaw.general_info || {}
  const shodanTimeline = shodanRaw.timeline || {}
  const shodanSecurity = shodanRaw.security_contact || {}
  const shodanTech = latest_shodan?.technologies || []

  const nmapRaw = latest_nmap?.raw_data || {}
  const nmapGeneral = nmapRaw.general_info || {}
  const nmapScanInfo = nmapRaw.scan_info || latest_nmap?.metadata?.scan_info || {}
  const nmapUptime = nmapRaw.uptime || latest_nmap?.metadata?.uptime || {}
  const nmapOsMatches = nmapRaw.os_detection || latest_nmap?.metadata?.os_detection || []
  const nmapTcpSeq = nmapRaw.tcp_sequence || latest_nmap?.metadata?.tcp_sequence || null
  const nmapTraceroute = nmapRaw.traceroute || latest_nmap?.metadata?.traceroute || null
  const nmapHostscripts = nmapRaw.hostscripts || latest_nmap?.metadata?.hostscripts || null
  const nmapDuration = nmapRaw.scan_duration_seconds || latest_nmap?.metadata?.scan_duration_seconds

  // Extended DB Intelligence fields
  const nmapFirewall = nmapRaw.firewall_detection || latest_nmap?.metadata?.firewall_detection || null
  const nmapGeolocation = nmapRaw.geolocation || latest_nmap?.metadata?.geolocation || null
  const nmapWhois = nmapRaw.whois || latest_nmap?.metadata?.whois || null
  const nmapSshInfo = nmapRaw.ssh_info || latest_nmap?.metadata?.ssh_info || null
  const nmapDnsInfo = nmapRaw.dns_info || latest_nmap?.metadata?.dns_info || null
  const nmapSmbInfo = nmapRaw.smb_info || latest_nmap?.metadata?.smb_info || null
  const nmapIpProtocols = nmapRaw.ip_protocols || latest_nmap?.metadata?.ip_protocols || []

  return (
    <div className="search-page">
      <Nav />

      <div className="detail-container">
        {/* Back and Breadcrumb */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <button onClick={handleBack} className="detail-back-btn" style={{ margin: 0 }}>
            <ArrowLeft size={16} /> Back to Search
          </button>
          <div style={{ fontSize: 12, color: 'rgba(224, 224, 232, 0.4)', fontFamily: 'JetBrains Mono, monospace' }}>
            <span>Search</span> / <span>Host</span> / <span style={{ color: '#a5b4fc' }}>{host.ip}</span>
          </div>
        </div>

        {/* ══════════════════════════════════════════════════════════════════
            HERO CARD: Comprehensive Host Overview
            ══════════════════════════════════════════════════════════════════ */}
        <div className="host-header-card">
          <div className="host-header-top">
            <div className="host-ip-display">
              <Globe size={30} />
              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                  <h1>{host.ip}</h1>
                  <button
                    onClick={() => copyToClipboard(host.ip, 'ip')}
                    className="copy-icon-btn"
                    title="Copy IP Address"
                  >
                    {copiedIp ? <Check size={13} color="#86efac" /> : <Copy size={13} />}
                    {copiedIp ? 'Copied' : 'Copy'}
                  </button>
                </div>
                {/* PTR Hostname or Domains under IP */}
                {formatHostnames(host) && (
                  <div className="hostnames-badge-bar">
                    <span className="hostnames-badge-label">PTR / Domains:</span>
                    <span className="hostnames-badge-text" title={formatHostnames(host)}>
                      {formatHostnames(host)}
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Source Status Badges */}
            <div className="host-header-badges">
              <span className={`header-badge ${latest_shodan ? 'shodan-badge-active' : 'source-inactive'}`}
                    style={{ background: latest_shodan ? 'rgba(249, 115, 22, 0.12)' : 'rgba(255, 255, 255, 0.04)', color: latest_shodan ? '#fb923c' : 'rgba(224, 224, 232, 0.4)', border: '1px solid ' + (latest_shodan ? 'rgba(249, 115, 22, 0.25)' : 'rgba(255, 255, 255, 0.06)') }}>
                <Flame size={14} />
                {latest_shodan ? 'Shodan Indexed' : 'No Shodan'}
              </span>
              <span className={`header-badge ${latest_nmap ? 'nmap-badge-active' : 'source-inactive'}`}
                    style={{ background: latest_nmap ? 'rgba(6, 182, 212, 0.12)' : 'rgba(255, 255, 255, 0.04)', color: latest_nmap ? '#22d3ee' : 'rgba(224, 224, 232, 0.4)', border: '1px solid ' + (latest_nmap ? 'rgba(6, 182, 212, 0.25)' : 'rgba(255, 255, 255, 0.06)') }}>
                <Radar size={14} />
                {latest_nmap ? 'Nmap Scanned' : 'No Nmap'}
              </span>
              <span className="header-badge scans-badge">
                <Database size={14} />
                {scan_count} scan{scan_count !== 1 ? 's' : ''}
              </span>
              {all_cves.length > 0 && (
                <span className="header-badge cves-badge">
                  <Bug size={14} />
                  {all_cves.length} CVE{all_cves.length !== 1 ? 's' : ''}
                </span>
              )}
            </div>
          </div>

          {/* Complete Host Properties Grid */}
          <div className="detail-prop-grid">
            {(host.country || host.City || host.Country) && (
              <div className="detail-prop-card">
                <MapPin size={16} />
                <div className="prop-content">
                  <span className="prop-label">Location</span>
                  <span className="prop-value">
                    {[host.city || host.City, host.country || host.Country].filter(Boolean).join(', ')}
                  </span>
                </div>
              </div>
            )}

            {(nmapGeolocation?.latitude || nmapGeolocation?.postal_code || nmapGeolocation?.region) && (
              <div className="detail-prop-card">
                <MapPin size={16} />
                <div className="prop-content">
                  <span className="prop-label">Coordinates & Postal</span>
                  <span className="prop-value mono">
                    {[
                      nmapGeolocation.latitude && nmapGeolocation.longitude ? `${nmapGeolocation.latitude}, ${nmapGeolocation.longitude}` : null,
                      nmapGeolocation.postal_code ? `Postal: ${nmapGeolocation.postal_code}` : null,
                      nmapGeolocation.region ? `Region: ${nmapGeolocation.region}` : null
                    ].filter(Boolean).join(' • ')}
                  </span>
                </div>
              </div>
            )}

            {(host.organization || host.Organization) && (
              <div className="detail-prop-card">
                <Building2 size={16} />
                <div className="prop-content">
                  <span className="prop-label">Organization</span>
                  <span className="prop-value">{host.organization || host.Organization}</span>
                </div>
              </div>
            )}

            {(host.isp || host.ISP) && (
              <div className="detail-prop-card">
                <Network size={16} />
                <div className="prop-content">
                  <span className="prop-label">ISP / Carrier</span>
                  <span className="prop-value">{host.isp || host.ISP}</span>
                </div>
              </div>
            )}

            {(host.asn || host.ASN) && (
              <div className="detail-prop-card">
                <Hash size={16} />
                <div className="prop-content">
                  <span className="prop-label">ASN</span>
                  <span className="prop-value mono">{host.asn || host.ASN}</span>
                </div>
              </div>
            )}

            {(host.os || host.OS) && (
              <div className="detail-prop-card">
                <Cpu size={16} />
                <div className="prop-content">
                  <span className="prop-label">Operating System</span>
                  <span className="prop-value">{host.os || host.OS}</span>
                </div>
              </div>
            )}

            {(host['Cloud Provider'] || host['Cloud Service'] || host['Cloud Region']) && (
              <div className="detail-prop-card">
                <Cloud size={16} />
                <div className="prop-content">
                  <span className="prop-label">Cloud Environment</span>
                  <span className="prop-value">
                    {[host['Cloud Provider'], host['Cloud Service'], host['Cloud Region']].filter(Boolean).join(' • ')}
                  </span>
                </div>
              </div>
            )}

            {(host.host_state || nmapGeneral.host_state) && (
              <div className="detail-prop-card">
                <Activity size={16} />
                <div className="prop-content">
                  <span className="prop-label">Host Status</span>
                  <span className="prop-value" style={{ color: (host.host_state || nmapGeneral.host_state) === 'up' ? '#86efac' : '#fca5a5' }}>
                    {(host.host_state || nmapGeneral.host_state).toUpperCase()}
                    {(host.host_reason || nmapGeneral.host_reason) ? ` (${host.host_reason || nmapGeneral.host_reason})` : ''}
                  </span>
                </div>
              </div>
            )}

            {(host.mac_address || nmapGeneral.mac_address) && (
              <div className="detail-prop-card">
                <Radio size={16} />
                <div className="prop-content">
                  <span className="prop-label">MAC Address</span>
                  <span className="prop-value mono">
                    {host.mac_address || nmapGeneral.mac_address}
                    {(host.mac_vendor || nmapGeneral.mac_vendor) ? ` (${host.mac_vendor || nmapGeneral.mac_vendor})` : ''}
                  </span>
                </div>
              </div>
            )}

            {host.last_updated && formatDate(host.last_updated, true) && (
              <div className="detail-prop-card">
                <Clock size={16} />
                <div className="prop-content">
                  <span className="prop-label">Last Database Update</span>
                  <span className="prop-value">{formatDate(host.last_updated, true)}</span>
                </div>
              </div>
            )}
          </div>

          {/* Tags */}
          {host.tags && Array.isArray(host.tags) && host.tags.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', paddingTop: 12, borderTop: '1px solid rgba(255, 255, 255, 0.04)' }}>
              <Tag size={13} style={{ color: 'rgba(224, 224, 232, 0.4)' }} />
              <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'rgba(224, 224, 232, 0.4)' }}>Tags:</span>
              {host.tags.map((t, idx) => (
                <span key={idx} className="facet-item-tag" style={{ background: 'rgba(108, 99, 255, 0.1)', border: '1px solid rgba(108, 99, 255, 0.2)', padding: '2px 8px', borderRadius: 6, fontSize: 11.5, color: '#a5b4fc' }}>
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* ══════════════════════════════════════════════════════════════════
            SECTION SWITCHER TABS
            ══════════════════════════════════════════════════════════════════ */}
        <div className="section-tabs-bar">
          <button
            className={`section-tab-btn ${activeTab === 'all' ? 'active' : ''}`}
            onClick={() => setActiveTab('all')}
          >
            <Layers size={15} />
            <span>All Sections</span>
          </button>

          <button
            className={`section-tab-btn shodan-tab ${activeTab === 'shodan' ? 'active' : ''}`}
            onClick={() => setActiveTab('shodan')}
          >
            <Flame size={15} />
            <span>Shodan Intelligence</span>
            {latest_shodan?.ports?.length > 0 && (
              <span className="tab-badge">{latest_shodan.ports.length} ports</span>
            )}
          </button>

          <button
            className={`section-tab-btn nmap-tab ${activeTab === 'nmap' ? 'active' : ''}`}
            onClick={() => setActiveTab('nmap')}
          >
            <Radar size={15} />
            <span>Nmap Live Scan</span>
            {latest_nmap?.ports?.length > 0 && (
              <span className="tab-badge">{latest_nmap.ports.length} ports</span>
            )}
          </button>

          <button
            className={`section-tab-btn ${activeTab === 'vulns' ? 'active' : ''}`}
            onClick={() => setActiveTab('vulns')}
          >
            <Bug size={15} />
            <span>Vulnerabilities</span>
            <span className="tab-badge" style={{ background: all_cves.length > 0 ? 'rgba(239, 68, 68, 0.2)' : undefined, color: all_cves.length > 0 ? '#fca5a5' : undefined }}>
              {all_cves.length}
            </span>
          </button>

          <button
            className={`section-tab-btn ${activeTab === 'timeline' ? 'active' : ''}`}
            onClick={() => setActiveTab('timeline')}
          >
            <Clock size={15} />
            <span>Historical Scans</span>
            <span className="tab-badge">{scans.length}</span>
          </button>
        </div>

        {/* ══════════════════════════════════════════════════════════════════
            SECTION 1: SHODAN INTELLIGENCE
            ══════════════════════════════════════════════════════════════════ */}
        {(activeTab === 'all' || activeTab === 'shodan') && (
          <div className="source-section-card shodan-section">
            <div className="source-header">
              <div className="source-title-group">
                <div className="source-icon-wrap shodan">
                  <Flame size={22} />
                </div>
                <div className="source-title-text">
                  <h2>Shodan Intelligence Engine</h2>
                  <p>Passive internet scanner reconnaissance & banner analysis</p>
                </div>
              </div>

              {latest_shodan ? (
                <div className="source-meta-pills">
                  {latest_shodan.source_last_seen && (
                    <span className="source-meta-pill highlight">
                      <Calendar size={13} />
                      Last Seen: {latest_shodan.source_last_seen}
                    </span>
                  )}
                  {latest_shodan.scraped_at && (
                    <span className="source-meta-pill">
                      <Clock size={13} />
                      Scraped: {formatDate(latest_shodan.scraped_at)}
                    </span>
                  )}
                  {shodanTimeline.history_url && (
                    <a
                      href={shodanTimeline.history_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="source-meta-pill"
                      style={{ textDecoration: 'none', color: '#fb923c' }}
                    >
                      <ExternalLink size={13} /> Shodan History
                    </a>
                  )}
                </div>
              ) : null}
            </div>

            {!latest_shodan ? (
              <div className="empty-source-card">
                <div className="empty-source-icon">
                  <Flame size={26} />
                </div>
                <h3>No Shodan Intelligence Found</h3>
                <p>
                  This host has not been scanned via Engine 1 (Shodan) yet. You can run Engine 1 in the chat to query Shodan banners, domains, and technologies for this IP.
                </p>
              </div>
            ) : (
              <>
                {/* Security Contact info if present */}
                {Object.keys(shodanSecurity).length > 0 && (
                  <div className="sub-card" style={{ borderColor: 'rgba(249, 115, 22, 0.2)' }}>
                    <div className="sub-card-title">
                      <div className="sub-card-title-left">
                        <Shield size={16} color="#fb923c" />
                        <span>Security Contact & Responsible Disclosure</span>
                      </div>
                    </div>
                    <div className="detail-prop-grid" style={{ marginBottom: 0 }}>
                      {Object.entries(shodanSecurity).map(([k, v]) => (
                        <div key={k} className="detail-prop-card">
                          <div className="prop-content">
                            <span className="prop-label">{k}</span>
                            <span className="prop-value mono">{String(v)}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Web Technologies Group */}
                {shodanTech.length > 0 && (
                  <div className="sub-card">
                    <div className="sub-card-title">
                      <div className="sub-card-title-left">
                        <Cpu size={16} />
                        <span>Detected Web Technologies ({shodanTech.length})</span>
                      </div>
                    </div>
                    <div className="tech-chips">
                      {shodanTech.map((t, ti) => (
                        <span key={ti} className="tech-chip">
                          <strong>{t.name}</strong>
                          {t.version && <span className="tech-version">v{t.version}</span>}
                          {t.category && <span className="tech-category">{t.category}</span>}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Shodan Open Ports & Banners */}
                <div>
                  <h3 className="section-title" style={{ fontSize: 15, marginBottom: 14 }}>
                    <Wifi size={17} color="#fb923c" />
                    Open Ports & Services ({latest_shodan.ports?.length || 0})
                  </h3>

                  {latest_shodan.ports?.length === 0 ? (
                    <div style={{ color: 'rgba(224, 224, 232, 0.5)', fontSize: 13, fontStyle: 'italic', padding: 12 }}>
                      No open ports recorded by Shodan.
                    </div>
                  ) : (
                    <div className="port-cards-container">
                      {latest_shodan.ports.map((port, pi) => {
                        const portKey = `shodan-${port.port_number}`
                        const isExpanded = expandedPorts[portKey]
                        const portTimestamp = shodanTimeline.port_timestamps?.[String(port.port_number)] || port.timestamp

                        return (
                          <div key={pi} className="port-card">
                            <div className="port-card-header" onClick={() => togglePort(portKey)}>
                              <div className="port-card-left">
                                <span className="port-num-badge">{port.port_number}</span>
                                <span className="port-proto-badge">{port.protocol || 'tcp'}</span>
                                <div className="port-service-info">
                                  <span className="port-service-name">{port.service || 'Unknown Service'}</span>
                                  {port.version && <span className="port-version-tag">{port.version}</span>}
                                </div>
                                {port.http_title && (
                                  <span className="port-title" style={{ color: '#a5b4fc', fontSize: 12.5 }} title={port.http_title}>
                                    "{port.http_title}"
                                  </span>
                                )}
                              </div>

                              <div className="port-card-right">
                                {portTimestamp && (
                                  <span style={{ fontSize: 11.5, color: 'rgba(224, 224, 232, 0.4)' }}>
                                    {String(portTimestamp).split('T')[0]}
                                  </span>
                                )}
                                {port.vulnerabilities?.length > 0 && (
                                  <span className="port-cves-count-badge">
                                    <Bug size={12} />
                                    {port.vulnerabilities.length} CVEs
                                  </span>
                                )}
                                <ChevronRight size={16} className={`scan-chevron ${isExpanded ? 'rotated' : ''}`} />
                              </div>
                            </div>

                            {isExpanded && (
                              <div className="port-card-body">
                                {/* Vulnerabilities on this port */}
                                {port.vulnerabilities?.length > 0 && (
                                  <div>
                                    <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'rgba(224, 224, 232, 0.5)', marginBottom: 8, letterSpacing: 0.5 }}>
                                      Associated Port Vulnerabilities
                                    </div>
                                    <div className="cve-grid">
                                      {port.vulnerabilities.map((v, vi) => (
                                        <Link
                                          key={vi}
                                          to={`/cve/${v.cve_id}`}
                                          className={`cve-chip ${getCveSeverityClass(v.cvss)}`}
                                          title={v.cvss_vector ? `${v.cve_id} — ${v.cvss_vector}` : v.cve_id}
                                        >
                                          <span className="cve-id">{v.cve_id}</span>
                                          {v.cvss != null && <span className="cve-score">{Number(v.cvss).toFixed(1)}</span>}
                                        </Link>
                                      ))}
                                    </div>
                                  </div>
                                )}

                                {/* Raw Banner */}
                                {port.banner && (
                                  <div className="banner-viewer">
                                    <div className="banner-viewer-header">
                                      <span>Service Banner / Header</span>
                                      <button
                                        onClick={(e) => {
                                          e.stopPropagation()
                                          copyToClipboard(port.banner, 'cmd')
                                        }}
                                        className="copy-icon-btn"
                                      >
                                        <Copy size={11} /> Copy Banner
                                      </button>
                                    </div>
                                    <pre className="banner-pre">{port.banner}</pre>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            SECTION 2: NMAP LIVE SCAN
            ══════════════════════════════════════════════════════════════════ */}
        {(activeTab === 'all' || activeTab === 'nmap') && (
          <div className="source-section-card nmap-section">
            <div className="source-header">
              <div className="source-title-group">
                <div className="source-icon-wrap nmap">
                  <Radar size={22} />
                </div>
                <div className="source-title-text">
                  <h2>Nmap Live Scanner & NSE Engine</h2>
                  <p>Active port probing, service versioning & security script enumeration</p>
                </div>
              </div>

              {latest_nmap ? (
                <div className="source-meta-pills">
                  {(host.host_state || nmapGeneral.host_state) && (
                    <span className={`source-meta-pill ${(host.host_state || nmapGeneral.host_state) === 'up' ? 'up' : 'down'}`}>
                      {(host.host_state || nmapGeneral.host_state) === 'up' ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                      Host {(host.host_state || nmapGeneral.host_state).toUpperCase()}
                    </span>
                  )}
                  {nmapDuration && (
                    <span className="source-meta-pill highlight">
                      <Clock size={13} />
                      Duration: {nmapDuration}s
                    </span>
                  )}
                  {latest_nmap.scraped_at && (
                    <span className="source-meta-pill">
                      <Calendar size={13} />
                      Scanned: {formatDate(latest_nmap.scraped_at)}
                    </span>
                  )}
                </div>
              ) : null}
            </div>

            {!latest_nmap ? (
              <div className="empty-source-card">
                <div className="empty-source-icon">
                  <Radar size={26} />
                </div>
                <h3>No Nmap Live Scan Data</h3>
                <p>
                  This host has not been scanned using Engine 2 (Nmap). Run Engine 2 in the chat to execute active port probing, NSE vulnerability scripts, and OS fingerprinting.
                </p>
              </div>
            ) : (
              <>
                {/* Execution Command Line */}
                {nmapScanInfo.command_line && (
                  <div className="sub-card">
                    <div className="sub-card-title">
                      <div className="sub-card-title-left">
                        <Terminal size={15} color="#22d3ee" />
                        <span>Execution Command Line</span>
                      </div>
                      <button
                        onClick={() => copyToClipboard(nmapScanInfo.command_line, 'cmd')}
                        className="copy-icon-btn"
                      >
                        {copiedCmd ? <Check size={12} color="#86efac" /> : <Copy size={12} />}
                        {copiedCmd ? 'Copied' : 'Copy Command'}
                      </button>
                    </div>
                    <div className="cmd-box">
                      <span className="cmd-text">{nmapScanInfo.command_line}</span>
                    </div>
                  </div>
                )}

                {/* System Metrics: Uptime & TCP Sequencing */}
                {(nmapUptime.seconds || nmapUptime.lastboot || nmapTcpSeq) && (
                  <div className="sub-card">
                    <div className="sub-card-title">
                      <div className="sub-card-title-left">
                        <Activity size={15} color="#22d3ee" />
                        <span>Host Metrics & TCP Sequencing</span>
                      </div>
                    </div>
                    <div className="detail-prop-grid" style={{ marginBottom: 0 }}>
                      {nmapUptime.lastboot && (
                        <div className="detail-prop-card">
                          <Clock size={15} />
                          <div className="prop-content">
                            <span className="prop-label">System Last Boot</span>
                            <span className="prop-value">{nmapUptime.lastboot}</span>
                          </div>
                        </div>
                      )}
                      {nmapUptime.seconds && (
                        <div className="detail-prop-card">
                          <Activity size={15} />
                          <div className="prop-content">
                            <span className="prop-label">Uptime</span>
                            <span className="prop-value">{Math.round(Number(nmapUptime.seconds) / 3600)} hours ({nmapUptime.seconds}s)</span>
                          </div>
                        </div>
                      )}
                      {nmapTcpSeq?.difficulty && (
                        <div className="detail-prop-card">
                          <Shield size={15} />
                          <div className="prop-content">
                            <span className="prop-label">TCP Sequence Difficulty</span>
                            <span className="prop-value mono">{nmapTcpSeq.difficulty}</span>
                          </div>
                        </div>
                      )}
                      {nmapTcpSeq?.class && (
                        <div className="detail-prop-card">
                          <Network size={15} />
                          <div className="prop-content">
                            <span className="prop-label">TCP Sequence Class</span>
                            <span className="prop-value">{nmapTcpSeq.class}</span>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* OS Fingerprinting */}
                {nmapOsMatches.length > 0 && (
                  <div className="sub-card">
                    <div className="sub-card-title">
                      <div className="sub-card-title-left">
                        <Cpu size={15} color="#22d3ee" />
                        <span>Nmap OS Detection Matches ({nmapOsMatches.length})</span>
                      </div>
                    </div>
                    <div className="os-detection-list">
                      {nmapOsMatches.map((osMatch, oi) => {
                        const acc = parseInt(osMatch.accuracy || '0', 10)
                        return (
                          <div key={oi} className="os-match-card">
                            <div className="os-match-header">
                              <span className="os-name">{osMatch.name}</span>
                              <span className="os-accuracy-badge">{osMatch.accuracy}% match</span>
                            </div>
                            <div className="os-accuracy-bar-track">
                              <div className="os-accuracy-bar-fill" style={{ width: `${acc}%` }} />
                            </div>
                            <div className="os-meta-row">
                              {osMatch.osfamily && <span><strong>Family:</strong> {osMatch.osfamily}</span>}
                              {osMatch.vendor && <span><strong>Vendor:</strong> {osMatch.vendor}</span>}
                              {osMatch.osgen && <span><strong>Gen:</strong> {osMatch.osgen}</span>}
                              {osMatch.cpe && (
                                <span>
                                  <strong>CPE:</strong>{' '}
                                  <code style={{ color: '#a5b4fc' }}>
                                    {Array.isArray(osMatch.cpe) ? osMatch.cpe.join(', ') : String(osMatch.cpe)}
                                  </code>
                                </span>
                              )}
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}

                {/* Traceroute Route */}
                {nmapTraceroute?.hops && nmapTraceroute.hops.length > 0 && (
                  <div className="sub-card">
                    <div className="sub-card-title">
                      <div className="sub-card-title-left">
                        <CornerDownRight size={15} color="#22d3ee" />
                        <span>Traceroute Network Hops ({nmapTraceroute.hops.length})</span>
                      </div>
                    </div>
                    <div className="hops-table-wrapper" style={{ overflowX: 'auto' }}>
                      <table className="hops-table">
                        <thead>
                          <tr>
                            <th>TTL</th>
                            <th>RTT</th>
                            <th>IP Address</th>
                            <th>Hostname</th>
                          </tr>
                        </thead>
                        <tbody>
                          {nmapTraceroute.hops.map((hop, hi) => (
                            <tr key={hi}>
                              <td style={{ color: '#22d3ee', fontWeight: 700 }}>{hop.ttl}</td>
                              <td>{hop.rtt ? `${hop.rtt} ms` : '—'}</td>
                              <td>{hop.ip || '—'}</td>
                              <td>{hop.host || '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Hostscripts */}
                {nmapHostscripts && Object.keys(nmapHostscripts).length > 0 && (
                  <div className="sub-card">
                    <div className="sub-card-title">
                      <div className="sub-card-title-left">
                        <FileText size={15} color="#22d3ee" />
                        <span>Host-Level Script Outputs</span>
                      </div>
                    </div>
                    <div className="scripts-container">
                      {Object.entries(nmapHostscripts).map(([sName, sOut]) => (
                        <div key={sName} className="script-box">
                          <div className="script-box-header">
                            <span className="script-box-name">{sName}</span>
                          </div>
                          <pre className="script-pre">{typeof sOut === 'string' ? sOut : JSON.stringify(sOut, null, 2)}</pre>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 1. Firewall & Filtering Analysis (Phase 6 ACK scan) */}
                {nmapFirewall && (
                  <div className="sub-card" style={{ borderColor: nmapFirewall.likely_firewalled ? 'rgba(239, 68, 68, 0.3)' : 'rgba(34, 211, 238, 0.2)' }}>
                    <div className="sub-card-title">
                      <div className="sub-card-title-left">
                        <Shield size={16} color={nmapFirewall.likely_firewalled ? '#f87171' : '#22d3ee'} />
                        <span>Firewall & Stateful Packet Filtering Analysis</span>
                      </div>
                      <span className={`source-meta-pill ${nmapFirewall.likely_firewalled ? 'highlight' : ''}`} style={{ margin: 0 }}>
                        {nmapFirewall.likely_firewalled ? 'Likely Firewalled' : 'Unfiltered / Responsive'}
                      </span>
                    </div>
                    <div className="detail-prop-grid" style={{ marginBottom: nmapFirewall.ack_scan_results ? 14 : 0 }}>
                      <div className="detail-prop-card">
                        <ShieldAlert size={15} />
                        <div className="prop-content">
                          <span className="prop-label">Filtered Ports Detected</span>
                          <span className="prop-value">{nmapFirewall.filtered_ports_count ?? '0'} ports</span>
                        </div>
                      </div>
                      <div className="detail-prop-card">
                        <Activity size={15} />
                        <div className="prop-content">
                          <span className="prop-label">Firewall Posture</span>
                          <span className="prop-value" style={{ color: nmapFirewall.likely_firewalled ? '#fca5a5' : '#86efac' }}>
                            {nmapFirewall.likely_firewalled ? 'Active Packet Filtering' : 'Permissive / Open Ingress'}
                          </span>
                        </div>
                      </div>
                    </div>
                    {nmapFirewall.ack_scan_results && Object.keys(nmapFirewall.ack_scan_results).length > 0 && (
                      <div style={{ marginTop: 10 }}>
                        <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'rgba(224, 224, 232, 0.45)', display: 'block', marginBottom: 8, letterSpacing: 0.5 }}>
                          ACK Probe Responses by Port:
                        </span>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                          {Object.entries(nmapFirewall.ack_scan_results).map(([pk, pstate]) => (
                            <span key={pk} className="facet-item-tag" style={{
                              background: pstate === 'filtered' ? 'rgba(239, 68, 68, 0.12)' : 'rgba(34, 197, 94, 0.12)',
                              border: `1px solid ${pstate === 'filtered' ? 'rgba(239, 68, 68, 0.25)' : 'rgba(34, 197, 94, 0.25)'}`,
                              color: pstate === 'filtered' ? '#fca5a5' : '#86efac',
                              fontSize: 11.5,
                              padding: '2px 8px',
                              borderRadius: 6
                            }}>
                              {pk}: {pstate}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* 2. DNS Reconnaissance & Subdomain Enumeration */}
                {nmapDnsInfo && (
                  <div className="sub-card">
                    <div className="sub-card-title">
                      <div className="sub-card-title-left">
                        <Network size={16} color="#22d3ee" />
                        <span>DNS Reconnaissance & Domain Intelligence</span>
                      </div>
                    </div>
                    <div className="detail-prop-grid" style={{ marginBottom: nmapDnsInfo.brute_subdomains ? 14 : 0 }}>
                      {nmapDnsInfo.reverse_dns && (
                        <div className="detail-prop-card">
                          <Globe size={15} />
                          <div className="prop-content">
                            <span className="prop-label">Reverse DNS (PTR)</span>
                            <span className="prop-value mono">{String(nmapDnsInfo.reverse_dns)}</span>
                          </div>
                        </div>
                      )}
                      {nmapDnsInfo.recursion && (
                        <div className="detail-prop-card">
                          <Activity size={15} />
                          <div className="prop-content">
                            <span className="prop-label">DNS Recursion</span>
                            <span className="prop-value" style={{ textTransform: 'capitalize' }}>{String(nmapDnsInfo.recursion)}</span>
                          </div>
                        </div>
                      )}
                      {nmapDnsInfo.zone_transfer && (
                        <div className="detail-prop-card">
                          <ShieldAlert size={15} />
                          <div className="prop-content">
                            <span className="prop-label">Zone Transfer (AXFR)</span>
                            <span className="prop-value mono" style={{ fontSize: 11.5 }}>{String(nmapDnsInfo.zone_transfer)}</span>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Brute subdomains */}
                    {nmapDnsInfo.brute_subdomains && nmapDnsInfo.brute_subdomains.length > 0 && (
                      <div style={{ marginTop: 12 }}>
                        <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'rgba(224, 224, 232, 0.45)', display: 'block', marginBottom: 8, letterSpacing: 0.5 }}>
                          Enumerated Subdomains ({nmapDnsInfo.brute_subdomains.length}):
                        </span>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, maxHeight: 180, overflowY: 'auto' }}>
                          {nmapDnsInfo.brute_subdomains.map((sub, subi) => (
                            <span key={subi} className="tech-chip" style={{ fontSize: 12 }}>
                              <strong>{sub.subdomain || sub.name || String(sub)}</strong>
                              {sub.ip && <span className="tech-version">{sub.ip}</span>}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* 3. SSH Protocol, Keys & Cryptographic Algorithms */}
                {nmapSshInfo && (
                  <div className="sub-card">
                    <div className="sub-card-title">
                      <div className="sub-card-title-left">
                        <Terminal size={16} color="#22d3ee" />
                        <span>SSH Protocol, Host Keys & Cryptographic Algorithms</span>
                      </div>
                    </div>

                    {/* Host Keys Table */}
                    {nmapSshInfo.host_keys && nmapSshInfo.host_keys.length > 0 && (
                      <div style={{ marginBottom: 14 }}>
                        <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'rgba(224, 224, 232, 0.45)', display: 'block', marginBottom: 6, letterSpacing: 0.5 }}>
                          Discovered SSH Host Keys:
                        </span>
                        <div className="hops-table-wrapper" style={{ overflowX: 'auto' }}>
                          <table className="hops-table">
                            <thead>
                              <tr>
                                <th>Key Type</th>
                                <th>Key Length</th>
                                <th>Key Fingerprint</th>
                              </tr>
                            </thead>
                            <tbody>
                              {nmapSshInfo.host_keys.map((hk, hki) => (
                                <tr key={hki}>
                                  <td style={{ color: '#22d3ee', fontWeight: 600 }}>{hk.type || 'SSH'}</td>
                                  <td>{hk.bits ? `${hk.bits} bits` : '—'}</td>
                                  <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, wordBreak: 'break-all' }}>{hk.fingerprint || hk.key || '—'}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {/* Auth Methods */}
                    {nmapSshInfo.auth_methods && (
                      <div style={{ marginBottom: 14 }}>
                        <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'rgba(224, 224, 232, 0.45)', display: 'block', marginBottom: 6, letterSpacing: 0.5 }}>
                          Allowed Authentication Methods:
                        </span>
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                          {(Array.isArray(nmapSshInfo.auth_methods) ? nmapSshInfo.auth_methods : [nmapSshInfo.auth_methods]).map((am, ami) => (
                            <span key={ami} className="tech-chip" style={{ fontSize: 12 }}>
                              <Key size={12} style={{ display: 'inline', marginRight: 4 }} />
                              {String(am)}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Algorithms Breakdown */}
                    {nmapSshInfo.algorithms && typeof nmapSshInfo.algorithms === 'object' && (
                      <div>
                        <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'rgba(224, 224, 232, 0.45)', display: 'block', marginBottom: 6, letterSpacing: 0.5 }}>
                          Supported SSH2 Cryptographic Ciphers & KEX:
                        </span>
                        <div className="detail-prop-grid" style={{ marginBottom: 0 }}>
                          {Object.entries(nmapSshInfo.algorithms).map(([algoType, algoList]) => (
                            <div key={algoType} className="detail-prop-card" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
                              <span className="prop-label" style={{ textTransform: 'capitalize' }}>{algoType.replace(/_/g, ' ')}</span>
                              <span className="prop-value mono" style={{ fontSize: 11.5, wordBreak: 'break-all', marginTop: 4 }}>
                                {Array.isArray(algoList) ? algoList.slice(0, 4).join(', ') + (algoList.length > 4 ? ` (+${algoList.length - 4} more)` : '') : String(algoList)}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* 4. SMB & Active Directory Discovery */}
                {nmapSmbInfo && (
                  <div className="sub-card">
                    <div className="sub-card-title">
                      <div className="sub-card-title-left">
                        <Building2 size={16} color="#22d3ee" />
                        <span>SMB & Active Directory Windows Domain Discovery</span>
                      </div>
                    </div>
                    <div className="detail-prop-grid" style={{ marginBottom: 0 }}>
                      {nmapSmbInfo.computer_name && (
                        <div className="detail-prop-card">
                          <Server size={15} />
                          <div className="prop-content">
                            <span className="prop-label">Computer Name</span>
                            <span className="prop-value mono">{nmapSmbInfo.computer_name}</span>
                          </div>
                        </div>
                      )}
                      {nmapSmbInfo.domain_name && (
                        <div className="detail-prop-card">
                          <Network size={15} />
                          <div className="prop-content">
                            <span className="prop-label">Domain Name</span>
                            <span className="prop-value mono">{nmapSmbInfo.domain_name}</span>
                          </div>
                        </div>
                      )}
                      {nmapSmbInfo.forest_name && (
                        <div className="detail-prop-card">
                          <Layers size={15} />
                          <div className="prop-content">
                            <span className="prop-label">Forest</span>
                            <span className="prop-value mono">{nmapSmbInfo.forest_name}</span>
                          </div>
                        </div>
                      )}
                      {nmapSmbInfo.workgroup && (
                        <div className="detail-prop-card">
                          <Building2 size={15} />
                          <div className="prop-content">
                            <span className="prop-label">Workgroup</span>
                            <span className="prop-value mono">{nmapSmbInfo.workgroup}</span>
                          </div>
                        </div>
                      )}
                      {nmapSmbInfo.os && (
                        <div className="detail-prop-card">
                          <Cpu size={15} />
                          <div className="prop-content">
                            <span className="prop-label">Exact OS Build</span>
                            <span className="prop-value">{nmapSmbInfo.os}</span>
                          </div>
                        </div>
                      )}
                      {nmapSmbInfo.system_time && (
                        <div className="detail-prop-card">
                          <Clock size={15} />
                          <div className="prop-content">
                            <span className="prop-label">Target System Time</span>
                            <span className="prop-value mono" style={{ fontSize: 12 }}>{nmapSmbInfo.system_time}</span>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* 5. Layer-3 / Layer-4 IP Protocols Scan */}
                {nmapIpProtocols && nmapIpProtocols.length > 0 && (
                  <div className="sub-card">
                    <div className="sub-card-title">
                      <div className="sub-card-title-left">
                        <Layers size={16} color="#22d3ee" />
                        <span>Discovered IP Layer Protocols ({nmapIpProtocols.length})</span>
                      </div>
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                      {nmapIpProtocols.map((proto, pidx) => (
                        <span key={pidx} className="tech-chip" style={{ fontSize: 12 }}>
                          <strong style={{ textTransform: 'uppercase' }}>{proto.protocol || proto.name || String(proto)}</strong>
                          {proto.number != null && <span className="tech-version">Proto #{proto.number}</span>}
                          {proto.state && <span className="tech-category">{proto.state}</span>}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* 6. Whois Registration Records */}
                {nmapWhois && (
                  <div className="sub-card">
                    <div className="sub-card-title">
                      <div className="sub-card-title-left">
                        <FileText size={16} color="#22d3ee" />
                        <span>Network & Autonomous System Whois Record</span>
                      </div>
                    </div>
                    <pre className="script-pre" style={{ maxHeight: 250, overflowY: 'auto' }}>
                      {typeof nmapWhois === 'string' ? nmapWhois : JSON.stringify(nmapWhois, null, 2)}
                    </pre>
                  </div>
                )}
                <div>
                  <h3 className="section-title" style={{ fontSize: 15, marginBottom: 14 }}>
                    <Server size={17} color="#22d3ee" />
                    Probed Ports, Services & NSE Scripts ({latest_nmap.ports?.length || 0})
                  </h3>

                  {latest_nmap.ports?.length === 0 ? (
                    <div style={{ color: 'rgba(224, 224, 232, 0.5)', fontSize: 13, fontStyle: 'italic', padding: 12 }}>
                      No open ports detected by Nmap scan.
                    </div>
                  ) : (
                    <div className="port-cards-container">
                      {latest_nmap.ports.map((port, pi) => {
                        const portKey = `nmap-${port.port_number}`
                        const isExpanded = expandedPorts[portKey]
                        const portExtra = port.extra || {}
                        const portScripts = portExtra.scripts || {}
                        const scriptKeys = Object.keys(portScripts)

                        return (
                          <div key={pi} className="port-card">
                            <div className="port-card-header" onClick={() => togglePort(portKey)}>
                              <div className="port-card-left">
                                <span className="port-num-badge" style={{ color: '#22d3ee', background: 'rgba(6, 182, 212, 0.12)', borderColor: 'rgba(6, 182, 212, 0.25)' }}>
                                  {port.port_number}
                                </span>
                                <span className="port-proto-badge">{port.protocol || 'tcp'}</span>
                                <span className={`port-state-badge ${port.state || 'open'}`}>
                                  {port.state || 'open'}
                                </span>
                                <div className="port-service-info">
                                  <span className="port-service-name">
                                    {portExtra.product || port.service || 'Unknown'}
                                  </span>
                                  {(port.version || portExtra.service_version) && (
                                    <span className="port-version-tag">
                                      {port.version || portExtra.service_version}
                                    </span>
                                  )}
                                  {portExtra.extra_info && (
                                    <span style={{ fontSize: 12, color: 'rgba(224, 224, 232, 0.45)' }}>
                                      ({portExtra.extra_info})
                                    </span>
                                  )}
                                </div>
                              </div>

                              <div className="port-card-right">
                                {scriptKeys.length > 0 && (
                                  <span className="source-meta-pill" style={{ fontSize: 11, padding: '2px 8px' }}>
                                    <Terminal size={11} /> {scriptKeys.length} scripts
                                  </span>
                                )}
                                {port.vulnerabilities?.length > 0 && (
                                  <span className="port-cves-count-badge">
                                    <Bug size={12} />
                                    {port.vulnerabilities.length} CVEs
                                  </span>
                                )}
                                <ChevronRight size={16} className={`scan-chevron ${isExpanded ? 'rotated' : ''}`} />
                              </div>
                            </div>

                             {isExpanded && (
                              <div className="port-card-body">
                                {/* Port Extra Details */}
                                {(portExtra.cpe || portExtra.reason || portExtra.conf) && (
                                  <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', fontSize: 12, color: 'rgba(224, 224, 232, 0.6)' }}>
                                    {portExtra.reason && <span><strong>Reason:</strong> {portExtra.reason}</span>}
                                    {portExtra.conf && <span><strong>Match Confidence:</strong> {portExtra.conf}/10</span>}
                                    {portExtra.cpe && (
                                      <span>
                                        <strong>CPE:</strong>{' '}
                                        <code style={{ color: '#a5b4fc' }}>
                                          {Array.isArray(portExtra.cpe) ? portExtra.cpe.join(', ') : String(portExtra.cpe)}
                                        </code>
                                      </span>
                                    )}
                                  </div>
                                )}

                                {/* SSL/TLS Certificate Inspection */}
                                {portExtra.ssl_certificate && (
                                  <div className="sub-card" style={{ background: 'rgba(255, 255, 255, 0.02)', marginTop: 12, marginBottom: 12 }}>
                                    <div className="sub-card-title" style={{ fontSize: 13, marginBottom: 10 }}>
                                      <div className="sub-card-title-left">
                                        <Lock size={14} color="#a5b4fc" />
                                        <span>SSL / TLS Certificate Inspection</span>
                                      </div>
                                      {portExtra.ssl_certificate.validity?.expired && (
                                        <span className="source-meta-pill highlight" style={{ fontSize: 11, padding: '2px 8px', margin: 0 }}>
                                          EXPIRED
                                        </span>
                                      )}
                                    </div>
                                    <div className="detail-prop-grid" style={{ marginBottom: 8 }}>
                                      {portExtra.ssl_certificate.subject?.common_name && (
                                        <div className="detail-prop-card">
                                          <Globe size={14} />
                                          <div className="prop-content">
                                            <span className="prop-label">Subject CN</span>
                                            <span className="prop-value mono">{portExtra.ssl_certificate.subject.common_name}</span>
                                          </div>
                                        </div>
                                      )}
                                      {portExtra.ssl_certificate.issuer?.common_name && (
                                        <div className="detail-prop-card">
                                          <Shield size={14} />
                                          <div className="prop-content">
                                            <span className="prop-label">Issuer</span>
                                            <span className="prop-value">{portExtra.ssl_certificate.issuer.common_name}</span>
                                          </div>
                                        </div>
                                      )}
                                      {portExtra.ssl_certificate.validity && (
                                        <div className="detail-prop-card">
                                          <Clock size={14} />
                                          <div className="prop-content">
                                            <span className="prop-label">Validity Period</span>
                                            <span className="prop-value mono" style={{ fontSize: 11.5 }}>
                                              {portExtra.ssl_certificate.validity.not_before} to {portExtra.ssl_certificate.validity.not_after}
                                            </span>
                                          </div>
                                        </div>
                                      )}
                                      {portExtra.ssl_certificate.public_key && (
                                        <div className="detail-prop-card">
                                          <Cpu size={14} />
                                          <div className="prop-content">
                                            <span className="prop-label">Public Key</span>
                                            <span className="prop-value mono">
                                              {portExtra.ssl_certificate.public_key.algorithm} ({portExtra.ssl_certificate.public_key.bits} bits)
                                            </span>
                                          </div>
                                        </div>
                                      )}
                                    </div>
                                    {portExtra.ssl_certificate.subject_alternative_names && portExtra.ssl_certificate.subject_alternative_names.length > 0 && (
                                      <div style={{ marginTop: 8, fontSize: 12 }}>
                                        <span style={{ color: 'rgba(224, 224, 232, 0.45)', fontWeight: 600 }}>SAN Domains: </span>
                                        <span style={{ color: '#a5b4fc', fontFamily: 'JetBrains Mono, monospace' }}>
                                          {portExtra.ssl_certificate.subject_alternative_names.join(', ')}
                                        </span>
                                      </div>
                                    )}
                                    {portExtra.ssl_certificate.sha1 && (
                                      <div style={{ marginTop: 6, fontSize: 11, color: 'rgba(224, 224, 232, 0.4)', fontFamily: 'JetBrains Mono, monospace' }}>
                                        SHA-1: {portExtra.ssl_certificate.sha1}
                                      </div>
                                    )}
                                  </div>
                                )}

                                {/* Defensive HTTP Security Headers Audit */}
                                {portExtra.http_security_headers && (
                                  <div className="sub-card" style={{ background: 'rgba(255, 255, 255, 0.02)', marginTop: 12, marginBottom: 12 }}>
                                    <div className="sub-card-title" style={{ fontSize: 13, marginBottom: 10 }}>
                                      <div className="sub-card-title-left">
                                        <ShieldCheck size={14} color="#86efac" />
                                        <span>HTTP Defensive Security Headers Audit</span>
                                      </div>
                                    </div>
                                    {portExtra.http_security_headers.headers && Object.keys(portExtra.http_security_headers.headers).length > 0 && (
                                      <div className="detail-prop-grid" style={{ marginBottom: 8 }}>
                                        {Object.entries(portExtra.http_security_headers.headers).map(([hName, hVal]) => (
                                          <div key={hName} className="detail-prop-card">
                                            <CheckCircle2 size={14} color="#86efac" />
                                            <div className="prop-content">
                                              <span className="prop-label" style={{ textTransform: 'uppercase' }}>{hName}</span>
                                              <span className="prop-value mono" style={{ fontSize: 11.5 }} title={String(hVal)}>{String(hVal)}</span>
                                            </div>
                                          </div>
                                        ))}
                                      </div>
                                    )}
                                    {portExtra.http_security_headers.missing_recommended && portExtra.http_security_headers.missing_recommended.length > 0 && (
                                      <div style={{ marginTop: 8, fontSize: 12 }}>
                                        <span style={{ color: '#fca5a5', fontWeight: 600 }}>Missing Recommended Headers: </span>
                                        <span style={{ color: 'rgba(224, 224, 232, 0.65)' }}>
                                          {portExtra.http_security_headers.missing_recommended.join(', ')}
                                        </span>
                                      </div>
                                    )}
                                  </div>
                                )}

                                {/* Associated Vulnerabilities */}
                                {port.vulnerabilities?.length > 0 && (
                                  <div>
                                    <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'rgba(224, 224, 232, 0.5)', marginBottom: 8, letterSpacing: 0.5 }}>
                                      Discovered CVEs on Port {port.port_number}
                                    </div>
                                    <div className="cve-grid">
                                      {port.vulnerabilities.map((v, vi) => (
                                        <Link
                                          key={vi}
                                          to={`/cve/${v.cve_id}`}
                                          className={`cve-chip ${getCveSeverityClass(v.cvss)}`}
                                          title={v.cvss_vector ? `${v.cve_id} — ${v.cvss_vector}` : v.cve_id}
                                        >
                                          <span className="cve-id">{v.cve_id}</span>
                                          {v.cvss != null && <span className="cve-score">{Number(v.cvss).toFixed(1)}</span>}
                                        </Link>
                                      ))}
                                    </div>
                                  </div>
                                )}

                                {/* NSE Scripts Viewer */}
                                {scriptKeys.length > 0 && (
                                  <div>
                                    <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'rgba(224, 224, 232, 0.5)', marginBottom: 8, letterSpacing: 0.5 }}>
                                      NSE Script Outputs ({scriptKeys.length})
                                    </div>
                                    <div className="scripts-container">
                                      {scriptKeys.map((sName) => {
                                        const scriptKey = `${portKey}-${sName}`
                                        const sOutput = portScripts[sName]
                                        const isScriptOpen = expandedScripts[scriptKey] !== false // Default open
                                        return (
                                          <div key={sName} className="script-box">
                                            <div
                                              className="script-box-header"
                                              style={{ cursor: 'pointer' }}
                                              onClick={() => toggleScript(scriptKey)}
                                            >
                                              <span className="script-box-name">
                                                <Terminal size={13} />
                                                {sName}
                                              </span>
                                              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                <button
                                                  onClick={(e) => {
                                                    e.stopPropagation()
                                                    copyToClipboard(typeof sOutput === 'string' ? sOutput : JSON.stringify(sOutput, null, 2), 'cmd')
                                                  }}
                                                  className="copy-icon-btn"
                                                >
                                                  <Copy size={11} /> Copy Output
                                                </button>
                                                <ChevronDown size={14} style={{ color: 'rgba(224, 224, 232, 0.4)', transform: isScriptOpen ? 'rotate(0deg)' : 'rotate(-90deg)', transition: 'transform 0.2s' }} />
                                              </div>
                                            </div>
                                            {isScriptOpen && (
                                              <pre className="script-pre">
                                                {typeof sOutput === 'string' ? sOutput : JSON.stringify(sOutput, null, 2)}
                                              </pre>
                                            )}
                                          </div>
                                        )
                                      })}
                                    </div>
                                  </div>
                                )}

                                {/* Raw Banner if present */}
                                {port.banner && (
                                  <div className="banner-viewer">
                                    <div className="banner-viewer-header">
                                      <span>Service Banner</span>
                                    </div>
                                    <pre className="banner-pre">{port.banner}</pre>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            SECTION 3: ALL VULNERABILITIES (AGGREGATED & FILTERABLE)
            ══════════════════════════════════════════════════════════════════ */}
        {(activeTab === 'all' || activeTab === 'vulns') && (
          <div className="source-section-card vuln-section">
            <div className="source-header">
              <div className="source-title-group">
                <div className="source-icon-wrap" style={{ background: 'rgba(239, 68, 68, 0.15)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.25)' }}>
                  <Bug size={22} />
                </div>
                <div className="source-title-text">
                  <h2>Host Vulnerability Intelligence</h2>
                  <p>All CVEs identified across Shodan banners and Nmap active vulnerability scripts</p>
                </div>
              </div>

              <div className="source-meta-pills">
                <span className="source-meta-pill highlight">
                  Total: {all_cves.length} CVEs
                </span>
              </div>
            </div>

            {all_cves.length === 0 ? (
              <div className="empty-source-card">
                <div className="empty-source-icon" style={{ color: '#86efac' }}>
                  <CheckCircle2 size={26} />
                </div>
                <h3>No Known Vulnerabilities Found</h3>
                <p>
                  No CVE records were identified on the discovered ports of this host in the local database.
                </p>
              </div>
            ) : (
              <>
                {/* Severity Breakdown Bar */}
                <div className="vuln-severity-bar">
                  <div
                    className={`vuln-severity-pill critical ${vulnSeverityFilter === 'critical' ? 'active' : ''}`}
                    onClick={() => setVulnSeverityFilter(vulnSeverityFilter === 'critical' ? 'all' : 'critical')}
                  >
                    <span className="vuln-pill-label">Critical (9.0+)</span>
                    <span className="vuln-pill-count">{severityCounts.critical}</span>
                  </div>

                  <div
                    className={`vuln-severity-pill high ${vulnSeverityFilter === 'high' ? 'active' : ''}`}
                    onClick={() => setVulnSeverityFilter(vulnSeverityFilter === 'high' ? 'all' : 'high')}
                  >
                    <span className="vuln-pill-label">High (7.0 - 8.9)</span>
                    <span className="vuln-pill-count">{severityCounts.high}</span>
                  </div>

                  <div
                    className={`vuln-severity-pill medium ${vulnSeverityFilter === 'medium' ? 'active' : ''}`}
                    onClick={() => setVulnSeverityFilter(vulnSeverityFilter === 'medium' ? 'all' : 'medium')}
                  >
                    <span className="vuln-pill-label">Medium (4.0 - 6.9)</span>
                    <span className="vuln-pill-count">{severityCounts.medium}</span>
                  </div>

                  <div
                    className={`vuln-severity-pill low ${vulnSeverityFilter === 'low' ? 'active' : ''}`}
                    onClick={() => setVulnSeverityFilter(vulnSeverityFilter === 'low' ? 'all' : 'low')}
                  >
                    <span className="vuln-pill-label">Low (&lt; 4.0)</span>
                    <span className="vuln-pill-count">{severityCounts.low}</span>
                  </div>
                </div>

                {/* Filter info indicator */}
                {vulnSeverityFilter !== 'all' && (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, fontSize: 13, color: 'rgba(224, 224, 232, 0.6)' }}>
                    <span>Showing <strong>{filteredCves.length}</strong> {vulnSeverityFilter.toUpperCase()} vulnerabilities</span>
                    <button
                      onClick={() => setVulnSeverityFilter('all')}
                      style={{ background: 'none', border: 'none', color: '#6c63ff', cursor: 'pointer', fontSize: 12, textDecoration: 'underline' }}
                    >
                      Clear filter
                    </button>
                  </div>
                )}

                {/* Detailed CVE List */}
                <div className="vulns-list">
                  {filteredCves.map((cve) => (
                    <Link
                      key={cve.cve_id}
                      to={`/cve/${cve.cve_id}`}
                      className="vuln-card-item"
                    >
                      <div className="vuln-card-left">
                        <span className={`cve-chip ${getCveSeverityClass(cve.cvss)}`} style={{ margin: 0 }}>
                          <span className="cve-id">{cve.cve_id}</span>
                          {cve.cvss != null && <span className="cve-score">{Number(cve.cvss).toFixed(1)}</span>}
                        </span>

                        {cve.summary && (
                          <span className="vuln-summary-snippet" title={cve.summary}>
                            {cve.summary}
                          </span>
                        )}
                      </div>

                      <div className="vuln-card-right">
                        {cve.cvss_vector && (
                          <span style={{
                            fontSize: 11,
                            fontFamily: 'JetBrains Mono, monospace',
                            color: 'rgba(165, 180, 252, 0.85)',
                            background: 'rgba(108, 99, 255, 0.08)',
                            border: '1px solid rgba(108, 99, 255, 0.2)',
                            padding: '2px 8px',
                            borderRadius: 6
                          }}>
                            {cve.cvss_vector}
                          </span>
                        )}

                        {/* Sources */}
                        {cve.sources?.map((src) => (
                          <span key={src} className={`vuln-source-tag ${src}`}>
                            {src}
                          </span>
                        ))}

                        {/* Ports */}
                        {cve.ports?.map((p) => (
                          <span key={p} className="vuln-port-tag">
                            {p}
                          </span>
                        ))}

                        <ChevronRight size={15} style={{ color: 'rgba(224, 224, 232, 0.3)' }} />
                      </div>
                    </Link>
                  ))}
                </div>
              </>
            )}
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            SECTION 4: SCAN TIMELINE
            ══════════════════════════════════════════════════════════════════ */}
        {(activeTab === 'all' || activeTab === 'timeline') && (
          <div className="section-card">
            <h2 className="section-title">
              <Clock size={20} />
              Historical Scan Snapshots ({scans.length})
            </h2>
            <div className="scan-timeline">
              {scans.map((scan, idx) => (
                <div key={idx} className="scan-entry">
                  <button
                    className={`scan-entry-header ${expandedScans[idx] ? 'expanded' : ''}`}
                    onClick={() => toggleScan(idx)}
                  >
                    <div className="scan-entry-left">
                      <span className={`scan-source ${scan.source}`}>
                        {scan.source === 'shodan' ? <Flame size={12} style={{ display: 'inline', marginRight: 4 }} /> : <Radar size={12} style={{ display: 'inline', marginRight: 4 }} />}
                        {scan.source}
                      </span>
                      <span className="scan-date">
                        {formatDate(scan.scraped_at, true) || 'Unknown date'}
                      </span>
                    </div>
                    <div className="scan-entry-right">
                      <span className="scan-port-count">{scan.ports?.length || 0} ports</span>
                      <ChevronRight size={16} className={`scan-chevron ${expandedScans[idx] ? 'rotated' : ''}`} />
                    </div>
                  </button>

                  {expandedScans[idx] && (
                    <div className="scan-entry-body">
                      {/* Port table */}
                      {scan.ports && scan.ports.length > 0 && (
                        <div className="scan-ports-section">
                          <h4 className="subsection-title">
                            <Wifi size={14} /> Recorded Ports
                          </h4>
                          <div className="port-table-wrapper">
                            <table className="port-table">
                              <thead>
                                <tr>
                                  <th>Port</th>
                                  <th>Protocol</th>
                                  <th>State</th>
                                  <th>Service</th>
                                  <th>Version</th>
                                  <th>Timestamp</th>
                                  <th>CVEs</th>
                                </tr>
                              </thead>
                              <tbody>
                                {scan.ports.map((port, pi) => {
                                  const portTs = port.timestamp || scan.metadata?.timeline?.port_timestamps?.[String(port.port_number)]
                                  return (
                                    <tr key={pi}>
                                      <td className="port-number">{port.port_number}</td>
                                      <td>{port.protocol || 'tcp'}</td>
                                      <td>{port.state || 'open'}</td>
                                      <td>{port.service || '—'}</td>
                                      <td className="port-version">{port.version || '—'}</td>
                                      <td style={{ fontSize: 12, color: 'rgba(224, 224, 232, 0.5)', fontFamily: 'JetBrains Mono, monospace' }}>
                                        {portTs ? String(portTs).split('T')[0] : '—'}
                                      </td>
                                      <td>
                                        {port.vulnerabilities?.length > 0 ? (
                                          <div className="port-cves">
                                            {port.vulnerabilities.map((v, vi) => (
                                              <Link
                                                key={vi}
                                                to={`/cve/${v.cve_id}`}
                                                className={`cve-mini-chip ${getCveSeverityClass(v.cvss)}`}
                                                onClick={(e) => e.stopPropagation()}
                                              >
                                                {v.cve_id}
                                              </Link>
                                            ))}
                                          </div>
                                        ) : '—'}
                                      </td>
                                    </tr>
                                  )
                                })}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function getCveSeverity(cvss) {
  if (cvss == null) return 'unknown'
  if (cvss >= 9.0) return 'critical'
  if (cvss >= 7.0) return 'high'
  if (cvss >= 4.0) return 'medium'
  return 'low'
}

function getCveSeverityClass(cvss) {
  return getCveSeverity(cvss)
}

function Nav() {
  return (
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
  )
}
