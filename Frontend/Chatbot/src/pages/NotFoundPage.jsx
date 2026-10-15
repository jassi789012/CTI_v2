import { Link } from 'react-router-dom'
import { ShieldAlert, Search, MessageSquare, Home, ArrowLeft } from 'lucide-react'
import '../SearchPage.css'

export default function NotFoundPage() {
  return (
    <div className="search-page">
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
          <Link to="/search" className="nav-link">
            <Search size={16} />
            <span>Search</span>
          </Link>
        </div>
      </nav>

      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: 'calc(100vh - 120px)',
        padding: '40px 20px',
        textAlign: 'center'
      }}>
        <div style={{
          background: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.25)',
          padding: 24,
          borderRadius: 24,
          marginBottom: 24,
          color: '#f87171'
        }}>
          <ShieldAlert size={56} />
        </div>

        <h1 style={{
          fontSize: 32,
          fontWeight: 800,
          color: '#f8fafc',
          marginBottom: 12,
          letterSpacing: '-0.02em'
        }}>
          404 — Page Not Found
        </h1>

        <p style={{
          fontSize: 15,
          color: 'rgba(224, 224, 232, 0.6)',
          maxWidth: 480,
          lineHeight: 1.6,
          marginBottom: 32
        }}>
          The page or investigation route you requested does not exist or has been relocated.
        </p>

        <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', justifyContent: 'center' }}>
          <Link
            to="/"
            className="back-btn-large"
            style={{ textDecoration: 'none', background: 'rgba(108, 99, 255, 0.2)', borderColor: 'rgba(108, 99, 255, 0.4)' }}
          >
            <MessageSquare size={16} /> Return to AI Chat
          </Link>
          <Link
            to="/search"
            className="back-btn-large"
            style={{ textDecoration: 'none' }}
          >
            <Search size={16} /> Search Intelligence Engine
          </Link>
        </div>
      </div>
    </div>
  )
}
