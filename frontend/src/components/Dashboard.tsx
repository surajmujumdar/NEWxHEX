'use client'

import React, { useEffect, useState } from 'react'
import Sidebar from './Sidebar'
import Navbar from './Navbar'
import TopCards from './TopCards'
import CriticalAlerts from './CriticalAlerts'
import ThreatIntelligenceSummary from './ThreatIntelligenceSummary'
import RansomwareLive from './RansomwareLive'
import AttackTrendGraph from './AttackTrendGraph'
import LiveCyberThreatNews from './LiveCyberThreatNews'
import HexStrikeCockpit from './HexStrikeCockpit'
import { usePlatformStore } from '@/store/platformStore'

export default function Dashboard() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [mounted, setMounted] = useState(false)
  const { currentPlatform } = usePlatformStore()

  useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) {
    return (
      <div className="flex min-h-screen bg-[#060205]">
        <div className="w-[208px] bg-[#080307] border-r border-red-500/20 h-screen animate-pulse" />
        <div className="flex-1 flex flex-col">
          <div className="h-[46px] bg-[#080307] border-b border-red-500/20 animate-pulse" />
          <main className="flex-1 p-4 space-y-4">
            <div className="h-48 bg-[#0c050d] border border-red-500/20 rounded-2xl animate-pulse" />
          </main>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen bg-[#060205] text-white selection:bg-red-500/30 selection:text-red-200">
      {/* Sticky Left Sidebar - Hidden when on HexStrike model */}
      {currentPlatform !== 'HEXSTRIKE' && (
        <Sidebar
          collapsed={sidebarCollapsed}
          setCollapsed={setSidebarCollapsed}
        />
      )}

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <Navbar />

        <main className={`flex-1 overflow-y-auto p-2.5 sm:p-4 mx-auto w-full ${currentPlatform === 'HEXSTRIKE' ? 'max-w-[1720px]' : 'max-w-[1520px]'} space-y-3`}>
          {currentPlatform === 'HEXSTRIKE' ? (
            /* HexStrike Scanner Platform View (Full Width without sidebar) */
            <HexStrikeCockpit />
          ) : (
            /* VAJRA Threat Intelligence Matrix View */
            <>
              {/* Top 4 Telemetry Metrics Cards */}
              <TopCards />

              {/* Recent Critical Alerts */}
              <CriticalAlerts />

              {/* Threat Intelligence Matrix & Trend Radar */}
              <ThreatIntelligenceSummary />

              {/* Ransomware Live Threat Grid */}
              <RansomwareLive />

              {/* Bottom Grid: Attack Trend Telemetry & Live Threat News */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                <AttackTrendGraph />
                <LiveCyberThreatNews />
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  )
}
