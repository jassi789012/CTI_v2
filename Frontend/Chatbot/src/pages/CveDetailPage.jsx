import { useState, useEffect } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import {
  Shield, Loader2, AlertTriangle, ShieldAlert, MessageSquare, Search,
  ArrowLeft, Bug, ExternalLink, Clock, Tag, Target, Crosshair,
  Lock, Activity, BookOpen, Zap, Layers, CheckCircle2,
  AlertCircle, Copy, Check, Terminal, Sparkles, Filter, ChevronDown, ChevronRight,
  Globe, Server
} from 'lucide-react'
import '../SearchPage.css'

const API_BASE = 'http://localhost:8000/api'

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

export default function CveDetailPage() {
  const { cveId } = useParams()
  const navigate = useNavigate()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [copiedVector, setCopiedVector] = useState(false)
  const [copiedCommand, setCopiedCommand] = useState(false)
  const [productSearch, setProductSearch] = useState('')
  const [showRawJson, setShowRawJson] = useState(false)

  useEffect(() => {
    setLoading(true)
    setError(null)
    const normalizedId = (cveId || '').trim().toUpperCase()
    fetch(`${API_BASE}/search/cve/${encodeURIComponent(normalizedId)}`)
      .then(r => {
        if (!r.ok) throw new Error(`Server error: ${r.status}`)
        return r.json()
      })
      .then(res => {
        if (!res.found || !res.data) {
          setError(`CVE ${normalizedId} was not found in the local database.`)
        } else {
          setData(res.data)
        }
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [cveId])

  useEffect(() => {
    document.title = cveId ? `${cveId} | Vulnerability Intelligence — CTI Agent` : 'CVE Intelligence — CTI Agent'
  }, [cveId])

  const handleBack = () => {
    if (window.history.length > 2) {
      navigate(-1)
    } else {
      navigate('/search?q=has_vuln:true')
    }
  }

  const copyToClipboard = (text, setCopiedState) => {
    if (!text) return
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(String(text)).then(() => {
        setCopiedState(true)
        setTimeout(() => setCopiedState(false), 2000)
      }).catch(() => {})
    }
  }

  if (loading) {
    return (
      <div className="search-page">
        <Nav />
        <div className="detail-loading">
          <Loader2 size={40} className="spin" />
          <span>Loading vulnerability intelligence...</span>
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
          <h2>{error || 'Vulnerability not found'}</h2>
          <p style={{ color: 'rgba(224, 224, 232, 0.5)', maxWidth: 450, textAlign: 'center', fontSize: 14 }}>
            This CVE has not been recorded in local scans or fetched via the CVE Mapper engine yet.
          </p>
          <div style={{ display: 'flex', gap: 12, marginTop: 12 }}>
            <button onClick={handleBack} className="back-btn-large">
              <ArrowLeft size={16} /> Go Back
            </button>
            <a
              href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`}
              target="_blank"
              rel="noopener noreferrer"
              className="back-btn-large"
              style={{ textDecoration: 'none', background: 'rgba(108, 99, 255, 0.1)', borderColor: 'rgba(108, 99, 255, 0.3)' }}
            >
              <ExternalLink size={16} /> Check NIST NVD
            </a>
          </div>
        </div>
      </div>
    )
  }

  const baseScoreNum = data.base_score != null ? Number(data.base_score) : null
  const severityClass = getSeverityClass(baseScoreNum)
  const analysis = data.analysis || null

  // Clean MITRE mappings
  const rawMitre = analysis?.mitre_mappings || []
  const validMitreMappings = rawMitre.filter(
    m => (m.tactic_id || m.tactic_name || m.technique_id || m.technique_name)
  )

  // Clean walkthrough
  const rawWalkthrough = analysis?.vulnerability_walkthrough || []
  const validWalkthrough = Array.isArray(rawWalkthrough)
    ? rawWalkthrough.filter(step => typeof step === 'string' && step.trim().length > 0 && !step.startsWith('Step 1: ...'))
    : []

  // Clean mitigations & detection
  const rawMitigations = analysis?.mitigations || []
  const validMitigations = Array.isArray(rawMitigations)
    ? rawMitigations.filter(m => typeof m === 'string' && m.trim().length > 0)
    : []

  const rawDetection = analysis?.detection_recommendations || []
  const validDetection = Array.isArray(rawDetection)
    ? rawDetection.filter(d => typeof d === 'string' && d.trim().length > 0)
    : []

  // Exploitation details
  const exploitationInfo = analysis?.exploitation_info || null
  const knownExploited = exploitationInfo?.known_exploited
  const exploitAvailable = exploitationInfo?.exploit_available
  const exploitSources = Array.isArray(exploitationInfo?.exploit_sources) ? exploitationInfo.exploit_sources : []

  // Affected local assets in local DB
  const affectedHosts = data.affected_hosts || []

  // Filter affected products
  const products = data.affected_products || []
  const filteredProducts = productSearch.trim()
    ? products.filter(p => {
        if (!p) return false
        if (typeof p === 'string') return p.toLowerCase().includes(productSearch.toLowerCase())
        return (
          (p.vendor || '').toLowerCase().includes(productSearch.toLowerCase()) ||
          (p.product || '').toLowerCase().includes(productSearch.toLowerCase()) ||
          (p.version || '').toLowerCase().includes(productSearch.toLowerCase()) ||
          (p.affected_platform || '').toLowerCase().includes(productSearch.toLowerCase())
        )
      })
    : products

  // Combined references (NVD + OSINT sources)
  const nvdRefs = data.reference_urls || []
  const osintRefs = analysis?.chatgpt_references || []
  const allReferences = [...nvdRefs]
  osintRefs.forEach(cr => {
    if (cr && cr.url && !allReferences.some(r => (typeof r === 'string' ? r : r.url) === cr.url)) {
      allReferences.push({ url: cr.url, tags: [cr.source || 'OSINT Source'] })
    }
  })

  // CWE link
  const cweNum = data.cwe_id ? data.cwe_id.replace(/^CWE-/i, '') : null

  return (
    <div className="search-page">
      <Nav />

      <div className="detail-container">
        {/* Navigation Breadcrumb */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <button onClick={handleBack} className="detail-back-btn" style={{ margin: 0 }}>
            <ArrowLeft size={16} /> Back
          </button>
          <div style={{ fontSize: 12, color: 'rgba(224, 224, 232, 0.45)', fontFamily: 'JetBrains Mono, monospace' }}>
            <Link to="/" style={{ color: 'inherit', textDecoration: 'none' }} className="breadcrumb-link">Threat Intel</Link> / <Link to="/search?q=has_vuln:true" style={{ color: 'inherit', textDecoration: 'none' }} className="breadcrumb-link">Vulnerabilities</Link> / <span style={{ color: '#f87171' }}>{data.cve_id}</span>
          </div>
        </div>

        {/* Scan-only Fallback Banner */}
        {data.from_scans_only && (
          <div style={{
            display: 'flex', alignItems: 'flex-start', gap: 14,
            padding: '16px 20px', borderRadius: 14, marginBottom: 20,
            background: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.25)',
            color: '#fde047', fontSize: 13.5
          }}>
            <AlertCircle size={20} style={{ flexShrink: 0, marginTop: 2, color: '#f59e0b' }} />
            <div style={{ lineHeight: 1.6 }}>
              <strong>Discovered via Active Network Scanning:</strong> This vulnerability was identified by security scanners on your network. It has not yet been processed by the automated NIST NVD & AI CVE Mapper engine. Run the CVE Mapper command below to fetch full CVSS metrics, MITRE ATT&CK mapping, and the technical walkthrough.
            </div>
          </div>
        )}

        {/* CVE Header Card */}
        <div className="cve-header-card">
          <div className="cve-header-top">
            <div className="cve-id-display">
              <Shield size={32} color={severityClass === 'critical' ? '#ef4444' : severityClass === 'high' ? '#f97316' : severityClass === 'medium' ? '#f59e0b' : '#6c63ff'} />
              <div>
                <h1>{data.cve_id}</h1>
                {analysis?.title ? (
                  <div style={{ fontSize: 15, color: '#cbd5e1', marginTop: 4, fontWeight: 600 }}>
                    {analysis.title}
                  </div>
                ) : (
                  <div style={{ fontSize: 12, color: 'rgba(224, 224, 232, 0.45)', marginTop: 2 }}>
                    NIST Common Vulnerabilities and Exposures
                  </div>
                )}
              </div>
            </div>

            <div className="cve-severity-display">
              <span className={`severity-badge ${severityClass}`}>
                {baseScoreNum != null && !isNaN(baseScoreNum) ? baseScoreNum.toFixed(1) : 'N/A'}
              </span>
              <span className={`severity-label ${severityClass}`}>
                {data.severity || 'Unknown'}
              </span>
            </div>
          </div>

          {/* Description */}
          {data.description && (
            <div className="cve-description" style={{ marginTop: 16 }}>
              <p style={{ lineHeight: 1.7, color: 'rgba(224, 224, 232, 0.85)', fontSize: 14.5 }}>
                {data.description}
              </p>
            </div>
          )}

          {/* CVSS Details Metrics Grid */}
          <div className="cvss-details-grid">
            {data.cvss_version && (
              <div className="cvss-item">
                <Shield size={14} />
                <span className="cvss-label">CVSS Version</span>
                <span className="cvss-value">v{data.cvss_version}</span>
              </div>
            )}
            {data.attack_vector && (
              <div className="cvss-item">
                <Target size={14} />
                <span className="cvss-label">Attack Vector</span>
                <span className="cvss-value">{data.attack_vector}</span>
              </div>
            )}
            {data.attack_complexity && (
              <div className="cvss-item">
                <Layers size={14} />
                <span className="cvss-label">Complexity</span>
                <span className="cvss-value">{data.attack_complexity}</span>
              </div>
            )}
            {data.privileges_required && (
              <div className="cvss-item">
                <Lock size={14} />
                <span className="cvss-label">Privileges</span>
                <span className="cvss-value">{data.privileges_required}</span>
              </div>
            )}
            {data.user_interaction && (
              <div className="cvss-item">
                <Crosshair size={14} />
                <span className="cvss-label">User Interaction</span>
                <span className="cvss-value">{data.user_interaction}</span>
              </div>
            )}
            {data.scope && (
              <div className="cvss-item">
                <Layers size={14} />
                <span className="cvss-label">Scope</span>
                <span className="cvss-value">{data.scope}</span>
              </div>
            )}
            {data.confidentiality_impact && (
              <div className="cvss-item">
                <Lock size={14} />
                <span className="cvss-label">Confidentiality</span>
                <span className={`cvss-value impact-${(data.confidentiality_impact || '').toLowerCase()}`}>
                  {data.confidentiality_impact}
                </span>
              </div>
            )}
            {data.integrity_impact && (
              <div className="cvss-item">
                <Shield size={14} />
                <span className="cvss-label">Integrity</span>
                <span className={`cvss-value impact-${(data.integrity_impact || '').toLowerCase()}`}>
                  {data.integrity_impact}
                </span>
              </div>
            )}
            {data.availability_impact && (
              <div className="cvss-item">
                <Activity size={14} />
                <span className="cvss-label">Availability</span>
                <span className={`cvss-value impact-${(data.availability_impact || '').toLowerCase()}`}>
                  {data.availability_impact}
                </span>
              </div>
            )}
            {data.published_date && (
              <div className="cvss-item">
                <Clock size={14} />
                <span className="cvss-label">Published</span>
                <span className="cvss-value">{String(data.published_date).split('T')[0]}</span>
              </div>
            )}
            {data.last_modified_date && (
              <div className="cvss-item">
                <Clock size={14} />
                <span className="cvss-label">Modified</span>
                <span className="cvss-value">{String(data.last_modified_date).split('T')[0]}</span>
              </div>
            )}
            {data.fetched_at && (
              <div className="cvss-item">
                <Clock size={14} />
                <span className="cvss-label">NVD Synced</span>
                <span className="cvss-value">{formatDate(data.fetched_at, true) || String(data.fetched_at).split('T')[0]}</span>
              </div>
            )}
          </div>

          {/* CVSS Vector String Bar */}
          {data.cvss_vector && (
            <div className="cvss-vector-bar" style={{ marginTop: 14, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, overflow: 'hidden' }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: 'rgba(224, 224, 232, 0.4)', flexShrink: 0 }}>CVSS VECTOR:</span>
                <code style={{ color: '#a5b4fc', fontFamily: 'JetBrains Mono, monospace', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {data.cvss_vector}
                </code>
              </div>
              <button
                onClick={() => copyToClipboard(data.cvss_vector, setCopiedVector)}
                style={{
                  background: 'none', border: 'none', color: copiedVector ? '#86efac' : 'rgba(224, 224, 232, 0.4)',
                  cursor: 'pointer', padding: 4, display: 'flex', alignItems: 'center', gap: 4, fontSize: 11
                }}
                title="Copy vector string"
              >
                {copiedVector ? <Check size={14} /> : <Copy size={14} />}
                <span>{copiedVector ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          )}
        </div>

        {/* Affected Local Assets & Infrastructure */}
        <div className="section-card" style={{ borderColor: affectedHosts.length > 0 ? 'rgba(239, 68, 68, 0.35)' : 'rgba(255, 255, 255, 0.06)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14, flexWrap: 'wrap', gap: 10 }}>
            <h2 className="section-title" style={{ margin: 0 }}>
              <Server size={18} color={affectedHosts.length > 0 ? '#ef4444' : '#6c63ff'} />
              Affected Local Assets & Scanned Hosts
              {affectedHosts.length > 0 && (
                <span className="source-meta-pill highlight" style={{ marginLeft: 10, fontSize: 11, padding: '2px 8px' }}>
                  {affectedHosts.length} Host{affectedHosts.length !== 1 ? 's' : ''} Vulnerable
                </span>
              )}
            </h2>
            {affectedHosts.length === 0 && (
              <span style={{ fontSize: 12, color: '#86efac', display: 'flex', alignItems: 'center', gap: 6 }}>
                <CheckCircle2 size={14} /> No local assets affected
              </span>
            )}
          </div>

          {affectedHosts.length > 0 ? (
            <div className="hops-table-wrapper" style={{ overflowX: 'auto' }}>
              <table className="hops-table">
                <thead>
                  <tr>
                    <th>Host IP Address</th>
                    <th>Vulnerable Port</th>
                    <th>Detection Engine</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {affectedHosts.map((h, hi) => (
                    <tr key={hi}>
                      <td>
                        <Link
                          to={`/ip/${encodeURIComponent(h.ip)}`}
                          style={{ color: '#22d3ee', fontWeight: 700, textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 6 }}
                          title="Open host intelligence"
                        >
                          <Globe size={14} />
                          {h.ip}
                        </Link>
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12.5, color: '#e0e0e8' }}>
                        {h.port}
                      </td>
                      <td>
                        <span className={`vuln-source-tag ${h.source || 'scan'}`} style={{ textTransform: 'capitalize' }}>
                          {h.source || 'Scanners'}
                        </span>
                      </td>
                      <td>
                        <Link
                          to={`/ip/${encodeURIComponent(h.ip)}?tab=vulns`}
                          className="copy-icon-btn"
                          style={{ textDecoration: 'none', display: 'inline-flex', width: 'fit-content' }}
                        >
                          View Host Intelligence →
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ color: 'rgba(224, 224, 232, 0.5)', fontSize: 13, fontStyle: 'italic', padding: '8px 0' }}>
              None of your scanned hosts currently have this vulnerability recorded in the database.
            </div>
          )}
        </div>

        {/* Weakness Type (CWE) */}
        {(data.cwe_id || data.cwe_name) && (
          <div className="section-card">
            <h2 className="section-title">
              <Tag size={18} />
              Weakness Classification (CWE)
            </h2>
            <div className="cwe-info" style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
              {data.cwe_id && (
                <a
                  href={`https://cwe.mitre.org/data/definitions/${cweNum || ''}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="cwe-id"
                  style={{
                    background: 'rgba(108, 99, 255, 0.12)', border: '1px solid rgba(108, 99, 255, 0.25)',
                    color: '#a5b4fc', padding: '5px 12px', borderRadius: 8, fontWeight: 700,
                    fontFamily: 'JetBrains Mono, monospace', textDecoration: 'none',
                    display: 'inline-flex', alignItems: 'center', gap: 6
                  }}
                >
                  {data.cwe_id}
                  <ExternalLink size={12} />
                </a>
              )}
              {data.cwe_name && (
                <span className="cwe-name" style={{ fontSize: 14.5, color: 'rgba(224, 224, 232, 0.85)', fontWeight: 500 }}>
                  {data.cwe_name}
                </span>
              )}
            </div>
          </div>
        )}

        {/* Exploitation & Threat Intelligence Section */}
        <div className="section-card">
          <h2 className="section-title">
            <Zap size={18} color="#f59e0b" />
            Exploitation & Threat Intelligence
          </h2>

          {analysis ? (
            <div>
              <div className="threat-intel-grid">
                {/* In-the-Wild Status */}
                <div className="threat-intel-card">
                  <div className={`threat-intel-icon-box ${knownExploited === true ? 'active-threat' : knownExploited === false ? 'safe-threat' : 'neutral-threat'}`}>
                    <AlertTriangle size={20} />
                  </div>
                  <div className="threat-intel-info">
                    <span className="threat-intel-label">In-The-Wild Exploitation</span>
                    <div className="threat-intel-value">
                      {knownExploited === true ? (
                        <span className="threat-badge danger">Active in the Wild</span>
                      ) : knownExploited === false ? (
                        <span className="threat-badge success">No Known Exploits in Wild</span>
                      ) : (
                        <span className="threat-badge neutral">Not Reported</span>
                      )}
                    </div>
                  </div>
                </div>

                {/* PoC / Exploit Availability */}
                <div className="threat-intel-card">
                  <div className={`threat-intel-icon-box ${exploitAvailable === true ? 'warning-threat' : exploitAvailable === false ? 'safe-threat' : 'neutral-threat'}`}>
                    <Zap size={20} />
                  </div>
                  <div className="threat-intel-info">
                    <span className="threat-intel-label">Public Exploit / PoC</span>
                    <div className="threat-intel-value">
                      {exploitAvailable === true ? (
                        <span className="threat-badge warning">PoC / Exploit Available</span>
                      ) : exploitAvailable === false ? (
                        <span className="threat-badge success">No Public Exploit</span>
                      ) : (
                        <span className="threat-badge neutral">Unknown</span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Timestamp */}
                <div className="threat-intel-card">
                  <div className="threat-intel-icon-box neutral-threat">
                    <Clock size={20} />
                  </div>
                  <div className="threat-intel-info">
                    <span className="threat-intel-label">Intelligence Analyzed</span>
                    <div className="threat-intel-value" style={{ fontSize: 13, color: 'rgba(224, 224, 232, 0.7)', fontWeight: 500 }}>
                      {analysis.analyzed_at ? String(analysis.analyzed_at).split('T')[0] : 'Enriched by CVE Mapper'}
                    </div>
                  </div>
                </div>
              </div>

              {/* Exploit Sources */}
              {exploitSources.length > 0 && (
                <div style={{ marginTop: 14, padding: '12px 16px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                  <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'rgba(224, 224, 232, 0.45)', letterSpacing: 0.5, display: 'block', marginBottom: 8 }}>
                    Known Exploit References & Sources ({exploitSources.length})
                  </span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                    {exploitSources.map((src, i) => (
                      <span key={i} style={{ padding: '4px 10px', borderRadius: 6, background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.25)', color: '#fde047', fontSize: 12, fontFamily: 'JetBrains Mono, monospace' }}>
                        {typeof src === 'object' ? JSON.stringify(src) : String(src)}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="pending-enrichment-card">
              <div className="pending-card-top">
                <Sparkles size={20} color="#f59e0b" />
                <h3>Exploitation Threat Intelligence — Pending AI Enrichment</h3>
              </div>
              <p className="pending-card-desc">
                Real-time active exploitation tracking, CISA KEV presence, and weaponized exploit availability are derived by enriching NVD entries through the CVE Mapper engine.
              </p>
              <div className="pending-command-bar">
                <span>Run mapper to populate:</span>
                <code>python Backend/cve_maper/cve_mapper.py {data.cve_id}</code>
              </div>
            </div>
          )}
        </div>

        {/* MITRE ATT&CK Mappings Section */}
        <div className="section-card">
          <h2 className="section-title">
            <Target size={18} color="#ec4899" />
            MITRE ATT&CK Matrix Mapping {validMitreMappings.length > 0 && `(${validMitreMappings.length})`}
          </h2>

          {validMitreMappings.length > 0 ? (
            <div className="mitre-cards-list">
              {validMitreMappings.map((m, i) => (
                <div key={i} className="mitre-card-item">
                  <div className="mitre-card-header">
                    <div className="mitre-tags-group">
                      {/* Tactic Pill */}
                      <span className="mitre-pill-tactic">
                        {m.tactic_id && <span className="mitre-id-code">{m.tactic_id}</span>}
                        <span>{m.tactic_name || 'Tactic'}</span>
                      </span>

                      {/* Technique Pill with MITRE Link */}
                      {m.technique_id ? (
                        <a
                          href={`https://attack.mitre.org/techniques/${m.technique_id.replace(/\./g, '/')}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="mitre-pill-technique"
                          title="View technique on MITRE ATT&CK"
                        >
                          <span className="mitre-id-code">{m.technique_id}</span>
                          <span>{m.technique_name || 'Technique'}</span>
                          <ExternalLink size={12} />
                        </a>
                      ) : (
                        <span className="mitre-pill-technique" style={{ textDecoration: 'none' }}>
                          <span>{m.technique_name || 'Technique'}</span>
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Justification Box */}
                  {m.justification && (
                    <div className="mitre-justification-box">
                      <span className="mitre-justification-label">Adversary TTP Justification</span>
                      {m.justification}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="pending-enrichment-card">
              <div className="pending-card-top">
                <Target size={20} color="#ec4899" />
                <h3>MITRE ATT&CK Mapping — Pending AI Analysis</h3>
              </div>
              <p className="pending-card-desc">
                Adversary tactics and techniques (TTPs) with technical justifications are mapped when this CVE is processed by the CVE Mapper automation engine.
              </p>
              <div className="pending-command-bar">
                <span>Map this vulnerability to ATT&CK:</span>
                <code>python Backend/cve_maper/cve_mapper.py {data.cve_id}</code>
              </div>
            </div>
          )}
        </div>

        {/* Technical Vulnerability Walkthrough Section */}
        <div className="section-card">
          <h2 className="section-title">
            <BookOpen size={18} color="#a5b4fc" />
            Technical Vulnerability Walkthrough {validWalkthrough.length > 0 && `(${validWalkthrough.length} Steps)`}
          </h2>

          {validWalkthrough.length > 0 ? (
            <div className="walkthrough-steps-list">
              {validWalkthrough.map((step, idx) => {
                // If the step contains "Step X: Title - Description", parse it nicely
                const match = step.match(/^Step\s+(\d+)[:\-]\s*(.*)$/i)
                const stepNum = match ? match[1] : String(idx + 1).padStart(2, '0')
                const stepText = match ? match[2] : step

                return (
                  <div key={idx} className="walkthrough-step-card">
                    <div className="walkthrough-step-num">{stepNum}</div>
                    <div className="walkthrough-step-body">
                      {stepText}
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="pending-enrichment-card">
              <div className="pending-card-top">
                <BookOpen size={20} color="#a5b4fc" />
                <h3>Technical Walkthrough — Pending AI Analysis</h3>
              </div>
              <p className="pending-card-desc">
                Step-by-step technical vulnerability walkthroughs detail the exact sequence from precondition to payload delivery and impact. Walkthrough data is generated via the CVE Mapper engine.
              </p>
              <div className="pending-command-bar">
                <span>Generate technical walkthrough:</span>
                <code>python Backend/cve_maper/cve_mapper.py {data.cve_id}</code>
              </div>
            </div>
          )}
        </div>

        {/* Actionable Mitigations */}
        {validMitigations.length > 0 && (
          <div className="section-card">
            <h2 className="section-title">
              <Shield size={18} color="#10b981" />
              Actionable Mitigations ({validMitigations.length})
            </h2>
            <div className="mitigations-checklist">
              {validMitigations.map((item, i) => (
                <div key={i} className="mitigation-item-card">
                  <CheckCircle2 size={18} />
                  <div>{item}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Detection & Threat Hunting Recommendations */}
        {validDetection.length > 0 && (
          <div className="section-card">
            <h2 className="section-title">
              <Crosshair size={18} color="#38bdf8" />
              Detection & Threat Hunting Recommendations ({validDetection.length})
            </h2>
            <div className="detection-rules-list">
              {validDetection.map((rule, i) => (
                <div key={i} className="detection-item-card">
                  <Crosshair size={18} />
                  <div>{rule}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Affected Products (NVD CPE) */}
        {products.length > 0 && (
          <div className="section-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 10 }}>
              <h2 className="section-title" style={{ margin: 0 }}>
                <Bug size={18} />
                Affected Software & Products ({products.length})
              </h2>

              {products.length > 5 && (
                <div style={{ position: 'relative', width: 240 }}>
                  <input
                    type="text"
                    placeholder="Filter products..."
                    value={productSearch}
                    onChange={(e) => setProductSearch(e.target.value)}
                    style={{
                      width: '100%', padding: '6px 12px 6px 30px', borderRadius: 8,
                      background: 'rgba(255, 255, 255, 0.03)', border: '1px solid rgba(255, 255, 255, 0.08)',
                      color: '#e0e0e8', fontSize: 12.5, outline: 'none'
                    }}
                  />
                  <Filter size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'rgba(224, 224, 232, 0.4)' }} />
                </div>
              )}
            </div>

            <div className="products-table-wrapper" style={{ maxHeight: 380, overflowY: 'auto' }}>
              <table className="port-table">
                <thead>
                  <tr>
                    <th>Vendor</th>
                    <th>Product</th>
                    <th>Version Range</th>
                    <th>Platform</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredProducts.map((p, i) => (
                    <tr key={i}>
                      <td>{p.vendor || '—'}</td>
                      <td className="product-name" style={{ fontWeight: 600, color: '#e0e0e8' }}>{p.product || '—'}</td>
                      <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12 }}>{p.version || 'All Versions'}</td>
                      <td>{p.affected_platform || 'Any'}</td>
                    </tr>
                  ))}
                  {filteredProducts.length === 0 && (
                    <tr>
                      <td colSpan="4" style={{ textAlign: 'center', padding: '16px', color: 'rgba(224, 224, 232, 0.4)' }}>
                        No software matching "{productSearch}"
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* References & Advisories */}
        {allReferences.length > 0 && (
          <div className="section-card">
            <h2 className="section-title">
              <ExternalLink size={18} />
              Advisory & Reference Sources ({allReferences.length})
            </h2>
            <div className="references-list" style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 350, overflowY: 'auto' }}>
              {allReferences.map((refItem, i) => {
                const url = typeof refItem === 'string' ? refItem : (refItem?.url || String(refItem))
                const tags = (typeof refItem === 'object' && Array.isArray(refItem?.tags)) ? refItem.tags : []

                return (
                  <a
                    key={i}
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="reference-link"
                    style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      padding: '9px 14px', borderRadius: 8,
                      background: 'rgba(255, 255, 255, 0.02)',
                      border: '1px solid rgba(255, 255, 255, 0.05)',
                      textDecoration: 'none', color: '#a5b4fc', fontSize: 13,
                      wordBreak: 'break-all'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0, flex: 1 }}>
                      <ExternalLink size={13} style={{ flexShrink: 0, color: 'rgba(108, 99, 255, 0.6)' }} />
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{url}</span>
                    </div>
                    {tags.length > 0 && (
                      <span style={{
                        fontSize: 10.5, color: 'rgba(224, 224, 232, 0.45)',
                        background: 'rgba(255, 255, 255, 0.04)',
                        padding: '2px 8px', borderRadius: 4, flexShrink: 0, marginLeft: 10
                      }}>
                        {tags.slice(0, 2).join(', ')}
                      </span>
                    )}
                  </a>
                )
              })}
            </div>
          </div>
        )}

        {/* Collapsible Raw JSON Data for Analysts */}
        <div className="section-card" style={{ padding: 16 }}>
          <button
            onClick={() => setShowRawJson(!showRawJson)}
            style={{
              width: '100%', background: 'none', border: 'none',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              color: 'rgba(224, 224, 232, 0.5)', cursor: 'pointer', fontSize: 13,
              fontWeight: 600, padding: 0
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Terminal size={15} />
              <span>Raw Technical Payload (NVD & AI JSON)</span>
            </div>
            {showRawJson ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          </button>

          {showRawJson && (
            <div style={{ marginTop: 14 }}>
              <pre style={{
                background: 'rgba(0, 0, 0, 0.35)', border: '1px solid rgba(255, 255, 255, 0.06)',
                borderRadius: 10, padding: 16, fontSize: 11.5,
                fontFamily: 'JetBrains Mono, monospace', color: 'rgba(224, 224, 232, 0.7)',
                maxHeight: 400, overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all'
              }}>
                {JSON.stringify(data, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function getSeverityClass(score) {
  if (score == null || isNaN(score)) return 'unknown'
  if (score >= 9.0) return 'critical'
  if (score >= 7.0) return 'high'
  if (score >= 4.0) return 'medium'
  return 'low'
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
