'use client'

import React, { useState, useRef, useEffect } from 'react'
import {
  Bell,
  Search,
  User,
  LogOut,
  Loader2,
  ChevronDown,
  Download,
  Shield,
  CheckCheck
} from 'lucide-react'
import { useAuthStore } from '@/store/authStore'
import { useRouter } from 'next/navigation'
import { useCompanyStore } from '@/store/companyStore'
import { useLanguageStore } from '@/store/languageStore'
import { useNotificationStore } from '@/store/notificationStore'
import { usePlatformStore } from '@/store/platformStore'
import PlatformToggle from './PlatformToggle'

export default function Navbar() {
  const { currentPlatform } = usePlatformStore()
  const { user, logout } = useAuthStore()
  const { selectedCompany } = useCompanyStore()
  const { t } = useLanguageStore()
  const { notifications, unreadCount, markAsRead, markAllAsRead, clearAll } = useNotificationStore()
  const router = useRouter()

  const [searchQuery, setSearchQuery] = useState('')
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [downloadingReport, setDownloadingReport] = useState(false)
  const [reportDropdownOpen, setReportDropdownOpen] = useState(false)
  const [notifFilter, setNotifFilter] = useState<'ALL' | 'CRITICAL' | 'RANSOMWARE' | 'GDELT'>('ALL')

  const notifRef = useRef<HTMLDivElement | null>(null)
  const reportRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setNotificationsOpen(false)
      }
      if (reportRef.current && !reportRef.current.contains(e.target as Node)) {
        setReportDropdownOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleLogout = () => {
    logout()
    router.push('/login')
  }

  const handleDownloadReport = async (reportType: string) => {
    setDownloadingReport(true)
    setReportDropdownOpen(false)
    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
      const url = selectedCompany 
        ? `${API_URL}/api/reports/company/${selectedCompany.id}`
        : `${API_URL}/api/reports/${reportType}`
      
      const response = await fetch(url)
      const blob = await response.blob()
      const downloadUrl = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = downloadUrl
      link.download = selectedCompany 
        ? `${selectedCompany.name.replace(' ', '_')}_report.pdf`
        : `${reportType}_report.pdf`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(downloadUrl)
    } catch (error) {
      console.error('Error downloading report:', error)
      alert('Failed to download report. Please try again.')
    } finally {
      setDownloadingReport(false)
    }
  }

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase()
      const sectionMap: { [key: string]: string } = {
        'threat': 'threat-intelligence',
        'intelligence': 'threat-intelligence',
        'ransomware': 'ransomware',
        'attack': 'global-attacks',
        'map': 'global-attacks',
        'company': 'companies',
        'companies': 'companies',
        'alert': 'alerts',
        'news': 'updates',
        'actor': 'threat-intelligence/actors',
        'industry': 'threat-intelligence/industries',
        'domain': 'domain-analysis',
        'sentinel': 'sentinel',
        'scanner': 'sentinel',
        'dast': 'sentinel',
        'sast': 'sentinel'
      }

      let matchedPath = ''
      for (const [term, path] of Object.entries(sectionMap)) {
        if (query.includes(term)) {
          matchedPath = path
          break
        }
      }

      if (matchedPath) {
        router.push(`/${matchedPath}`)
      } else {
        router.push(`/companies`)
      }
      setSearchQuery('')
    }
  }

  const filteredNotifs = notifications.filter((n) => {
    if (notifFilter === 'CRITICAL') return n.severity === 'CRITICAL'
    if (notifFilter === 'RANSOMWARE') return n.type === 'RANSOMWARE'
    if (notifFilter === 'GDELT') return n.type === 'GDELT_NEWS'
    return true
  })

  return (
    <header
      style={{
        height: '52px',
        backgroundColor: 'rgba(8, 3, 7, 0.92)',
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        borderBottom: '1px solid rgba(239, 68, 68, 0.18)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 16px',
        position: 'sticky',
        top: 0,
        zIndex: 40,
        gap: '12px'
      }}
      className="font-hud shadow-lg"
    >
      {/* Left: Brand Status Chip */}
      <div className="flex items-center gap-2.5 flex-shrink-0">
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '3px 9px',
            borderRadius: '9999px',
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.35)',
            fontSize: '10.5px',
            fontWeight: 800,
            color: '#fda4af',
            boxShadow: '0 0 15px rgba(239, 68, 68, 0.20)',
            fontFamily: 'var(--font-mono)',
            whiteSpace: 'nowrap'
          }}
        >
          <span
            style={{
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              background: '#ef4444',
              boxShadow: '0 0 8px #ef4444',
              flexShrink: 0
            }}
            className="animate-pulse"
          />
          <span className="hidden xl:inline font-bold">
            {currentPlatform === 'HEXSTRIKE' ? 'HEXSTRIKE: AI MCP AGENTS v6.0' : 'VAJRA: CYBER THREAT MATRIX'}
          </span>
          <span className="hidden sm:inline xl:hidden font-bold">
            {currentPlatform === 'HEXSTRIKE' ? 'HEXSTRIKE AI' : 'DEFENSE ACTIVE'}
          </span>
          <span className="sm:hidden font-bold">ACTIVE</span>
        </div>

        {/* DEFCON / MODE Level Badge */}
        <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#0c050d] border border-red-500/30 text-[9.5px] font-mono font-bold text-red-300">
          <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-ping" />
          <span>{currentPlatform === 'HEXSTRIKE' ? '12+ AGENTS • 150+ TOOLS' : 'SHIELD: MAXIMUM'}</span>
        </div>
      </div>

      {/* Center: Dual Platform Interactive Switch Toggle */}
      <div className="flex items-center justify-center">
        <PlatformToggle />
      </div>

      {/* Right Controls: Search + Report + Notif + User */}
      <div className="flex items-center gap-2 sm:gap-2.5 flex-shrink-0">
        {/* Quick Search Bar */}
        <form onSubmit={handleSearch} className="relative hidden md:block">
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '3px 9px',
              borderRadius: '9999px',
              background: '#0c050d',
              border: '1px solid rgba(239, 68, 68, 0.25)',
              color: '#cbd5e1',
              width: '140px',
              height: '30px',
              transition: 'all 0.15s'
            }}
            className="lg:w-[170px] focus-within:border-red-400 focus-within:ring-2 focus-within:ring-red-500/20"
          >
            <Search size={12} color="#f87171" className="flex-shrink-0" />
            <input
              type="text"
              placeholder={t('searchPlaceholder', 'Quick Search...')}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                outline: 'none',
                color: '#ffffff',
                fontSize: '11px',
                fontWeight: 600,
                width: '100%'
              }}
            />
            <span
              style={{
                fontSize: '8.5px',
                fontFamily: 'var(--font-mono)',
                padding: '0 4px',
                borderRadius: '4px',
                background: '#190a16',
                color: '#fda4af',
                border: '1px solid rgba(239, 68, 68, 0.20)',
                flexShrink: 0
              }}
            >
              /
            </span>
          </div>
        </form>

        {/* PDF Report Dropdown */}
        <div className="relative flex-shrink-0" ref={reportRef}>
          <button
            onClick={() => setReportDropdownOpen(!reportDropdownOpen)}
            disabled={downloadingReport}
            style={{
              height: '30px',
              padding: '0 10px',
              fontSize: '10.5px',
              fontWeight: 800,
              letterSpacing: '0.3px',
              borderRadius: '9999px',
              background: 'linear-gradient(135deg, #e11d48 0%, #ef4444 50%, #f43f5e 100%)',
              border: '1px solid #f43f5e',
              color: '#ffffff',
              boxShadow: '0 0 15px rgba(239, 68, 68, 0.40)',
              display: 'flex',
              alignItems: 'center',
              gap: '5px',
              cursor: 'pointer'
            }}
            className="hover:brightness-110 transition-all disabled:opacity-50 font-black"
          >
            {downloadingReport ? <Loader2 size={12} className="animate-spin" /> : <Download size={12} />}
            <span className="hidden sm:inline">REPORT</span>
            <ChevronDown size={10} />
          </button>

          {reportDropdownOpen && (
            <div
              style={{
                position: 'absolute',
                right: 0,
                top: '100%',
                marginTop: '6px',
                width: '210px',
                backgroundColor: '#0c050d',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                borderRadius: '10px',
                boxShadow: '0 10px 30px rgba(0, 0, 0, 0.85), 0 0 20px rgba(239, 68, 68, 0.25)',
                zIndex: 50,
                overflow: 'hidden',
                padding: '4px'
              }}
            >
              <button
                onClick={() => handleDownloadReport('dashboard')}
                className="w-full text-left px-3 py-2 text-xs font-bold text-slate-200 hover:bg-red-500/20 hover:text-red-400 rounded-md flex items-center justify-between transition-colors"
              >
                <span>Full Security Audit</span>
                <span className="text-[9.5px] text-red-400 font-mono font-bold">PDF</span>
              </button>
              <button
                onClick={() => handleDownloadReport('threat-intelligence')}
                className="w-full text-left px-3 py-2 text-xs font-bold text-slate-200 hover:bg-red-500/20 hover:text-red-400 rounded-md flex items-center justify-between transition-colors"
              >
                <span>Threat Intel Brief</span>
                <span className="text-[9.5px] text-red-400 font-mono font-bold">PDF</span>
              </button>
              <button
                onClick={() => handleDownloadReport('ransomware')}
                className="w-full text-left px-3 py-2 text-xs font-bold text-slate-200 hover:bg-red-500/20 hover:text-red-400 rounded-md flex items-center justify-between transition-colors"
              >
                <span>Ransomware Report</span>
                <span className="text-[9.5px] text-red-400 font-mono font-bold">PDF</span>
              </button>
            </div>
          )}
        </div>

        {/* Notifications Bell */}
        <div className="relative flex-shrink-0" ref={notifRef}>
          <button
            onClick={() => setNotificationsOpen(!notificationsOpen)}
            style={{
              position: 'relative',
              width: '30px',
              height: '30px',
              borderRadius: '9999px',
              background: '#0c050d',
              border: '1px solid rgba(239, 68, 68, 0.25)',
              color: unreadCount > 0 ? '#ef4444' : '#cbd5e1',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer',
              transition: 'all 0.15s'
            }}
            className="hover:border-red-500/60 hover:bg-[#190a16] shadow-xs"
          >
            <Bell size={14} />
            {unreadCount > 0 && (
              <span
                style={{
                  position: 'absolute',
                  top: '-3px',
                  right: '-3px',
                  minWidth: '15px',
                  height: '15px',
                  padding: '0 3px',
                  borderRadius: '9999px',
                  background: '#ef4444',
                  color: '#ffffff',
                  fontSize: '8.5px',
                  fontWeight: 900,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 0 10px rgba(239, 68, 68, 0.6)'
                }}
              >
                {unreadCount > 99 ? '99+' : unreadCount}
              </span>
            )}
          </button>

          {notificationsOpen && (
            <div
              style={{
                position: 'absolute',
                right: 0,
                top: '100%',
                marginTop: '8px',
                width: '330px',
                backgroundColor: '#0c050d',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                borderRadius: '12px',
                boxShadow: '0 16px 40px rgba(0, 0, 0, 0.85), 0 0 20px rgba(239, 68, 68, 0.25)',
                zIndex: 50,
                overflow: 'hidden'
              }}
            >
              <div className="flex items-center justify-between p-3 border-b border-red-500/15 bg-[#120710]">
                <div className="flex items-center gap-2">
                  <Shield size={14} className="text-red-500" />
                  <span className="text-xs font-bold text-white uppercase tracking-wider font-hud">Alert Center</span>
                  {unreadCount > 0 && (
                    <span className="text-[9px] font-mono font-bold text-red-300 bg-red-950/70 border border-red-500/40 px-1.5 py-0.5 rounded-full">
                      {unreadCount} NEW
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={markAllAsRead}
                    className="text-[9px] font-mono text-slate-400 hover:text-white flex items-center gap-1 transition-colors"
                  >
                    <CheckCheck size={11} /> Mark Read
                  </button>
                  <button
                    onClick={clearAll}
                    className="text-[9px] font-mono text-slate-500 hover:text-red-400 transition-colors"
                  >
                    Clear
                  </button>
                </div>
              </div>

              {/* Filter Tabs */}
              <div className="flex border-b border-red-500/15 bg-[#090308] p-1 gap-1">
                {(['ALL', 'CRITICAL', 'RANSOMWARE', 'GDELT'] as const).map((filter) => (
                  <button
                    key={filter}
                    onClick={() => setNotifFilter(filter)}
                    className={`flex-1 py-1 text-[8.5px] font-mono font-bold rounded-full transition-colors ${
                      notifFilter === filter
                        ? 'bg-red-500/25 border border-red-500/40 text-red-300'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {filter}
                  </button>
                ))}
              </div>

              {/* Notification Items */}
              <div className="max-h-64 overflow-y-auto divide-y divide-red-500/10">
                {filteredNotifs.length === 0 ? (
                  <div className="p-6 text-center text-xs text-slate-400 font-mono">
                    No alerts found in this category
                  </div>
                ) : (
                  filteredNotifs.slice(0, 10).map((n) => (
                    <div
                      key={n.id}
                      onClick={() => markAsRead(n.id)}
                      className={`p-2.5 hover:bg-red-950/20 cursor-pointer transition-colors ${
                        !n.is_read ? 'bg-red-950/30' : ''
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex-1">
                          <div className="flex items-center gap-1.5 mb-1">
                            <span
                              className={`text-[8px] font-mono font-bold px-1.5 py-0.5 rounded-full border ${
                                n.severity === 'CRITICAL'
                                  ? 'bg-red-500/25 border-red-500/40 text-red-300'
                                  : n.severity === 'HIGH'
                                  ? 'bg-amber-500/25 border-amber-500/40 text-amber-300'
                                  : 'bg-slate-800 border-slate-700 text-slate-300'
                              }`}
                            >
                              {n.severity}
                            </span>
                            <span className="text-[10.5px] font-bold text-white truncate max-w-[180px]">
                              {n.title}
                            </span>
                          </div>
                          <p className="text-[10px] text-slate-400 line-clamp-2 leading-tight">
                            {n.message}
                          </p>
                        </div>
                        {!n.is_read && (
                          <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0 mt-1 shadow-[0_0_6px_#ef4444]" />
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>

              <div className="p-2 border-t border-red-500/15 bg-[#090308] text-center">
                <button
                  onClick={() => {
                    setNotificationsOpen(false)
                    router.push('/alerts')
                  }}
                  className="text-[9.5px] font-mono font-bold text-red-400 hover:underline"
                >
                  View All Alerts →
                </button>
              </div>
            </div>
          )}
        </div>

        {/* User Profile Avatar & Role */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            paddingLeft: '8px',
            borderLeft: '1px solid rgba(239, 68, 68, 0.20)',
            flexShrink: 0
          }}
        >
          <div
            style={{
              width: '28px',
              height: '28px',
              borderRadius: '9999px',
              background: 'rgba(239, 68, 68, 0.20)',
              border: '1px solid rgba(239, 68, 68, 0.45)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#fda4af',
              flexShrink: 0
            }}
          >
            <User size={13} />
          </div>
          <div className="hidden lg:block text-left max-w-[110px] xl:max-w-[135px]">
            <div
              style={{
                fontSize: '11px',
                fontWeight: 800,
                color: '#ffffff',
                lineHeight: 1.1,
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis'
              }}
            >
              {user?.name || 'Security Lead'}
            </div>
            <div
              style={{
                fontSize: '8px',
                fontWeight: 800,
                color: '#ef4444',
                letterSpacing: '0.6px',
                fontFamily: 'var(--font-mono)'
              }}
            >
              COMMAND OPERATOR
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="px-2.5 py-1 rounded-full bg-[#0c050d] border border-red-500/30 hover:border-red-500 hover:bg-red-950/40 text-slate-300 hover:text-white transition-all shadow-xs flex items-center space-x-1 cursor-pointer flex-shrink-0 text-[10px] font-bold font-hud tracking-wider active:scale-95 ml-1"
            title="Terminate Session / Logout"
          >
            <LogOut size={11} className="text-red-400" />
            <span className="hidden sm:inline">LOGOUT</span>
          </button>
        </div>
      </div>
    </header>
  )
}
