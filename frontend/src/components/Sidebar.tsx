'use client'

import React from 'react'
import Link from 'next/link'
import {
  LayoutDashboard,
  Building2,
  Shield,
  AlertTriangle,
  Users,
  Globe,
  Radio,
  Network,
  Activity,
  Settings,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  Crosshair,
  Zap
} from 'lucide-react'
import { usePathname } from 'next/navigation'
import { useLanguageStore } from '@/store/languageStore'
import { usePlatformStore } from '@/store/platformStore'

interface SidebarProps {
  collapsed: boolean
  setCollapsed: (collapsed: boolean) => void
  sidebarWidth?: number
  setSidebarWidth?: (width: number) => void
}

export default function Sidebar({ collapsed, setCollapsed }: SidebarProps) {
  const pathname = usePathname()
  const { t } = useLanguageStore()
  const { currentPlatform, setPlatform } = usePlatformStore()

  const navSections = [
    {
      label: 'COMMAND',
      items: [
        { id: 'dashboard', label: t('dashboard', 'Dashboard'), icon: LayoutDashboard, path: '/', color: '#ef4444' },
        { id: 'hexstrike', label: 'HexStrike AI MCP', icon: Zap, path: '/hexstrike', color: '#ef4444' },
        { id: 'companies', label: t('companyMonitor', 'Monitored Assets'), icon: Building2, path: '/companies', color: '#f43f5e' },
        { id: 'alerts', label: 'Threat Alerts', icon: AlertTriangle, path: '/alerts', color: '#ef4444' },
        { id: 'global-attacks', label: 'Attack Map', icon: Globe, path: '/global-attacks', color: '#f59e0b' },
      ]
    },
    {
      label: 'THREAT INTEL MATRIX',
      items: [
        { id: 'threat-intelligence', label: t('threatIntelligence', 'Threat Intel'), icon: Shield, path: '/threat-intelligence', color: '#ef4444' },
        { id: 'ransomware', label: t('ransomwareLive', 'Ransomware Live'), icon: ShieldAlert, path: '/ransomware', color: '#ef4444' },
        { id: 'actors', label: t('threatActors', 'APT Actors'), icon: Users, path: '/threat-intelligence/actors', color: '#f43f5e' },
        { id: 'industries', label: t('targetedIndustries', 'Target Sectors'), icon: Building2, path: '/threat-intelligence/industries', color: '#f59e0b' },
        { id: 'domain', label: t('domainPulse', 'Domain Pulse'), icon: Radio, path: '/domain-analysis', color: '#e11d48' },
      ]
    },
    {
      label: 'SOC & GOVERNANCE',
      items: [
        { id: 'soc', label: 'SOC Connect', icon: Network, path: '/soc-integration', color: '#ef4444' },
        { id: 'data-sources', label: 'Data Feeds', icon: Radio, path: '/data-sources', color: '#ef4444' },
        { id: 'executive', label: t('executiveSummary', 'Executive Brief'), icon: Activity, path: '/executive-summary', color: '#f43f5e' },
        { id: 'admin', label: t('adminCenter', 'Admin Center'), icon: Users, path: '/admin', color: '#94a3b8' },
        { id: 'settings', label: t('settings', 'Settings'), icon: Settings, path: '/settings', color: '#94a3b8' },
      ]
    }
  ]

  const isCurrentActive = (path: string) => {
    if (path === '/' && pathname === '/') return true
    if (path !== '/' && pathname.startsWith(path)) return true
    return false
  }

  return (
    <aside
      style={{
        width: collapsed ? '48px' : '200px',
        backgroundColor: '#080307',
        borderRight: '1px solid rgba(239, 68, 68, 0.18)',
        display: 'flex',
        flexDirection: 'column',
        position: 'sticky',
        top: 0,
        height: '100vh',
        zIndex: 50,
        userSelect: 'none',
        boxShadow: '10px 0 30px rgba(0, 0, 0, 0.85)',
        transition: 'width 0.2s cubic-bezier(0.4, 0, 0.2, 1)'
      }}
      className="flex-shrink-0 font-hud"
    >
      {/* Brand Header */}
      <Link
        href="/"
        prefetch={true}
        style={{
          height: '44px',
          padding: collapsed ? '0' : '0 10px',
          borderBottom: '1px solid rgba(239, 68, 68, 0.18)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: collapsed ? 'center' : 'flex-start',
          gap: '8px',
          cursor: 'pointer',
          background: '#080307',
          flexShrink: 0
        }}
      >
        <div
          style={{
            width: '26px',
            height: '26px',
            borderRadius: '7px',
            overflow: 'hidden',
            border: '1px solid #ef4444',
            boxShadow: '0 0 10px rgba(239, 68, 68, 0.4)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
            background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.25), rgba(225, 29, 72, 0.15))'
          }}
        >
          <span className="font-mono font-black text-red-400 text-[11px] tracking-tighter">
            {currentPlatform === 'HEXSTRIKE' ? '//HX//' : '//V//'}
          </span>
        </div>

        {!collapsed && (
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ fontSize: '12px', fontWeight: 900, letterSpacing: '0.6px', color: '#ffffff', lineHeight: 1.1 }}>
              {currentPlatform === 'HEXSTRIKE' ? (
                <>HEXSTRIKE <span className="text-[9px] text-red-400 font-mono font-bold">AI MCP</span></>
              ) : (
                <>VAJRA <span className="text-[9px] text-red-400 font-mono font-bold">CYBER</span></>
              )}
            </div>
            <div style={{ fontSize: '7px', fontWeight: 800, color: '#ef4444', marginTop: '1px', letterSpacing: '0.5px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
              {currentPlatform === 'HEXSTRIKE' ? 'OFFENSIVE • DEFENSE • MCP' : 'CYBER • DEFENSE • CORE'}
            </div>
          </div>
        )}
      </Link>

      {/* Navigation Sections */}
      <nav
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '6px 6px',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px'
        }}
        className="custom-scrollbar"
      >
        {navSections.map((section, sIdx) => (
          <div key={sIdx} style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
            {!collapsed && (
              <div
                style={{
                  fontSize: '8px',
                  fontWeight: 800,
                  fontFamily: 'var(--font-mono)',
                  color: '#94a3b8',
                  letterSpacing: '1px',
                  padding: '1px 6px 2px 6px',
                  textTransform: 'uppercase'
                }}
              >
                {section.label}
              </div>
            )}

            {section.items.map((item) => {
              const active = isCurrentActive(item.path)
              const Icon = item.icon
              const iconAccent = item.color || (active ? '#ef4444' : '#94a3b8')

              return (
                <Link
                  key={item.id}
                  href={item.path}
                  prefetch={true}
                  style={{
                    width: '100%',
                    height: '28px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: collapsed ? 'center' : 'flex-start',
                    gap: '7px',
                    padding: collapsed ? '0' : '0 8px',
                    borderRadius: '6px',
                    background: active
                      ? 'linear-gradient(90deg, rgba(225, 29, 72, 0.25) 0%, rgba(239, 68, 68, 0.12) 100%)'
                      : 'transparent',
                    border: active ? '1px solid rgba(239, 68, 68, 0.45)' : '1px solid transparent',
                    boxShadow: active ? '0 0 12px rgba(239, 68, 68, 0.2)' : 'none',
                    color: active ? '#ffffff' : '#cbd5e1',
                    cursor: 'pointer',
                    textAlign: 'left',
                    position: 'relative',
                    transition: 'all 0.15s ease',
                    textDecoration: 'none'
                  }}
                  onMouseEnter={(e) => {
                    if (!active) {
                      e.currentTarget.style.background = 'rgba(239, 68, 68, 0.08)'
                      e.currentTarget.style.color = '#ffffff'
                      e.currentTarget.style.borderColor = 'rgba(239, 68, 68, 0.25)'
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (!active) {
                      e.currentTarget.style.background = 'transparent'
                      e.currentTarget.style.color = '#cbd5e1'
                      e.currentTarget.style.borderColor = 'transparent'
                    }
                  }}
                  title={collapsed ? item.label : undefined}
                >
                  {/* Left Accent Bar */}
                  {active && (
                    <div
                      style={{
                        position: 'absolute',
                        left: '-2px',
                        top: '50%',
                        transform: 'translateY(-50%)',
                        width: '3px',
                        height: '14px',
                        borderRadius: '0 2px 2px 0',
                        background: '#ef4444',
                        boxShadow: '0 0 8px #ef4444'
                      }}
                    />
                  )}

                  {/* Icon */}
                  <div
                    style={{
                      width: '16px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0
                    }}
                  >
                    <Icon
                      size={13.5}
                      color={active ? '#ef4444' : iconAccent}
                      strokeWidth={active ? 2.5 : 2}
                    />
                  </div>

                  {!collapsed && (
                    <span
                      style={{
                        fontSize: '11px',
                        fontWeight: active ? 800 : 600,
                        letterSpacing: '0.2px',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis'
                      }}
                    >
                      {item.label}
                    </span>
                  )}
                </Link>
              )
            })}
          </div>
        ))}
      </nav>

      {/* Collapse Toggle Footer */}
      <div
        style={{
          padding: '6px 6px',
          borderTop: '1px solid rgba(239, 68, 68, 0.18)',
          display: 'flex',
          alignItems: 'center',
          gap: '4px',
          background: '#090308',
          flexShrink: 0
        }}
      >
        <button
          onClick={() => setCollapsed(!collapsed)}
          style={{
            flex: 1,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '5px',
            padding: '4px 0',
            borderRadius: '5px',
            backgroundColor: '#0c050d',
            border: '1px solid rgba(239, 68, 68, 0.20)',
            color: '#cbd5e1',
            fontSize: '9px',
            fontWeight: 800,
            cursor: 'pointer',
            transition: 'all 0.15s'
          }}
          className="hover:border-red-500/60 hover:text-white hover:bg-red-950/30"
          title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
        >
          {collapsed ? (
            <ChevronRight size={12} className="text-red-400" />
          ) : (
            <>
              <ChevronLeft size={12} className="text-red-400" />
              <span style={{ fontSize: '8.5px', textTransform: 'uppercase', letterSpacing: '0.8px', fontFamily: 'var(--font-mono)' }}>
                Collapse
              </span>
            </>
          )}
        </button>
      </div>
    </aside>
  )
}
