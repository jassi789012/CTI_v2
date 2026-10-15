import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import './index.css'
import App from './App.jsx'
import SearchPage from './pages/SearchPage.jsx'
import IpDetailPage from './pages/IpDetailPage.jsx'
import CveDetailPage from './pages/CveDetailPage.jsx'
import NotFoundPage from './pages/NotFoundPage.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<App />} />
        <Route path="/chat" element={<App />} />
        <Route path="/search" element={<SearchPage />} />
        <Route path="/ip" element={<Navigate to="/search" replace />} />
        <Route path="/ip/:ip" element={<IpDetailPage />} />
        <Route path="/cve" element={<Navigate to="/search?q=has_vuln:true" replace />} />
        <Route path="/cve/:cveId" element={<CveDetailPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </BrowserRouter>
  </StrictMode>,
)

