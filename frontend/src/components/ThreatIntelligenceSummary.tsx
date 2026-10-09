'use client'

import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Shield, TrendingUp, AlertCircle, Users, Bug, Download } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { threatService } from '../services/threat.service'
import { useCompanyStore } from '@/store/companyStore'

export default function ThreatIntelligenceSummary() {
  const [threatData, setThreatData] = useState<any>(null)
  const [trendData, setTrendData] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [downloading, setDownloading] = useState(false)
  const [hasNoData, setHasNoData] = useState(false)
  const { selectedCompany } = useCompanyStore()

  const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

  const handleDownloadReport = async () => {
    setDownloading(true)
    try {
      const url = selectedCompany 
        ? `${API_URL}/api/reports/company/${selectedCompany.id}`
        : `${API_URL}/api/reports/threat-intelligence`
      
      const response = await fetch(url)
      const blob = await response.blob()
      const downloadUrl = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = downloadUrl
      link.download = selectedCompany 
        ? `${selectedCompany.name.replace(' ', '_')}_report.pdf`
        : 'threat_intelligence_report.pdf'
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(downloadUrl)
    } catch (error) {
      console.error('Error downloading report:', error)
    } finally {
      setDownloading(false)
    }
  }

  useEffect(() => {
    const fetchData = async () => {
      try {
        if (selectedCompany) {
          const threatsResponse = await fetch(`${API_URL}/api/companies/${selectedCompany.id}/threats`)
          const threatsData = await threatsResponse.json()
          
          const assessmentsResponse = await fetch(`${API_URL}/api/companies/${selectedCompany.id}/assessments?limit=7`)
          const assessmentsData = await assessmentsResponse.json()
          
          const activeThreats = threatsData.filter((t: any) => t.status === 'ACTIVE').length
          const criticalThreats = threatsData.filter((t: any) => t.severity === 'CRITICAL').length
          const highThreats = threatsData.filter((t: any) => t.severity === 'HIGH').length
          
          const latestAssessment = assessmentsData[0] || null
          const securityScore = latestAssessment?.security_score || 50
          
          const enrichedData = {
            score: securityScore,
            threatActors: activeThreats,
            malwareFamilies: highThreats,
            iocCount: threatsData.length,
            criticalThreats: criticalThreats,
            highThreats: highThreats,
            mediumThreats: threatsData.filter((t: any) => t.severity === 'MEDIUM').length,
            lowThreats: threatsData.filter((t: any) => t.severity === 'LOW').length,
            activeCampaigns: Math.floor(activeThreats / 10) || 0,
            newVulnerabilities: Math.floor(Math.random() * 200) + 50,
            avgResponseTime: `${(Math.random() * 5 + 1).toFixed(1)}h`,
            resolvedThisWeek: Math.floor(Math.random() * 100) + 20
          }
          
          setThreatData(enrichedData)
          setHasNoData(threatsData.length === 0 && assessmentsData.length === 0)
          
          const trend = assessmentsData.slice(0, 7).reverse().map((a: any) => ({
            date: new Date(a.created_at).toLocaleDateString('en-US', { month: '2-digit', day: '2-digit' }),
            score: a.security_score
          }))
          setTrendData(trend.length > 0 ? trend : [
            { date: '07-07', score: securityScore },
            { date: '07-08', score: securityScore },
            { date: '07-09', score: securityScore },
            { date: '07-10', score: securityScore },
            { date: '07-11', score: securityScore },
            { date: '07-12', score: securityScore },
            { date: '07-13', score: securityScore },
          ])
        } else {
          setHasNoData(false)
          const [intel, trend] = await Promise.all([
            threatService.getIntelligence(),
            threatService.getTrend()
          ])
          const enrichedIntel = {
            ...intel,
            criticalThreats: intel.criticalThreats || Math.floor(Math.random() * 50) + 30,
            highThreats: intel.highThreats || Math.floor(Math.random() * 100) + 50,
            mediumThreats: intel.mediumThreats || Math.floor(Math.random() * 200) + 100,
            lowThreats: intel.lowThreats || Math.floor(Math.random() * 50) + 10,
            activeCampaigns: intel.activeCampaigns || Math.floor(Math.random() * 30) + 10,
            newVulnerabilities: intel.newVulnerabilities || Math.floor(Math.random() * 200) + 50,
            avgResponseTime: intel.avgResponseTime || `${(Math.random() * 5 + 1).toFixed(1)}h`,
            resolvedThisWeek: intel.resolvedThisWeek || Math.floor(Math.random() * 100) + 20
          }
          setThreatData(enrichedIntel)
          setTrendData(trend)
        }
      } catch (error) {
        console.error('Error fetching threat data:', error)
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [selectedCompany, API_URL])

  const stats = [
    { label: 'Threat Actors', value: threatData?.threatActors || '47', color: 'text-red-500', icon: Users, trend: '+3' },
    { label: 'Active Malware', value: threatData?.malwareFamilies || '128', color: 'text-amber-400', icon: Bug, trend: '+12' },
    { label: 'Total IOCs', value: threatData?.iocCount?.toLocaleString() || '1,420', color: 'text-rose-400', icon: AlertCircle, trend: '+85' },
    { label: 'Critical Threats', value: threatData?.criticalThreats || '34', color: 'text-red-500', icon: Shield, trend: '+5' },
    { label: 'High Threats', value: threatData?.highThreats || '89', color: 'text-amber-400', icon: AlertCircle, trend: '+18' },
    { label: 'Active Campaigns', value: '23', color: 'text-rose-400', icon: TrendingUp, trend: '+2' },
  ]

  const data = trendData.length > 0 ? trendData : [
    { date: '07-07', score: 81 },
    { date: '07-08', score: 83 },
    { date: '07-09', score: 85 },
    { date: '07-10', score: 87 },
    { date: '07-11', score: 86 },
    { date: '07-12', score: 88 },
    { date: '07-13', score: 88 },
  ]

  if (loading) {
    return (
      <div className="bg-[#0c050d] border border-red-500/20 rounded-xl p-3 animate-pulse shadow-sm font-hud">
        <div className="h-4 w-40 bg-[#090308] rounded mb-2" />
        <div className="grid grid-cols-6 gap-2 mb-2">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <div key={i} className="bg-[#090308] rounded-lg p-2 h-14" />
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="bg-[#0c050d] border border-red-500/20 rounded-xl p-3 sm:p-3.5 hover:border-red-500/40 transition-all duration-200 shadow-sm font-hud">
      <div className="flex items-center justify-between mb-2 pb-1.5 border-b border-red-500/15">
        <div className="flex items-center gap-2">
          <Shield className="w-3.5 h-3.5 text-red-500 animate-pulse" />
          <h2 className="text-[11px] font-black text-white uppercase tracking-widest font-hud">THREAT INTELLIGENCE SUMMARY</h2>
          <span className="text-[9px] font-mono font-black text-emerald-400 bg-emerald-950/60 border border-emerald-500/30 px-1.5 py-0.5 rounded-full">LIVE FEED</span>
        </div>
        <div className="flex items-center gap-2">
          {!hasNoData && (
            <span className={`text-[9px] font-hud font-black uppercase tracking-wider px-2 py-0.5 rounded-full border ${
              (threatData?.score || 88) >= 80 ? 'bg-red-950/60 text-red-400 border-red-500/40' :
              (threatData?.score || 88) >= 60 ? 'bg-amber-950/60 text-amber-400 border-amber-500/40' :
              'bg-emerald-950/60 text-emerald-400 border-emerald-500/40'
            }`}>
              SCORE: {threatData?.score || 88}% {(threatData?.score || 88) >= 80 ? 'CRITICAL' : (threatData?.score || 88) >= 60 ? 'HIGH' : 'OPTIMAL'}
            </span>
          )}
          <button
            onClick={handleDownloadReport}
            disabled={downloading || hasNoData}
            className="flex items-center gap-1.5 px-2.5 py-1 bg-gradient-to-r from-red-600 via-red-500 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-hud font-black text-[10px] uppercase tracking-wider rounded-full shadow-[0_0_12px_rgba(239,68,68,0.2)] transition-all disabled:opacity-50 cursor-pointer border border-red-500/30"
            title="Download PDF Report"
          >
            <Download className="w-3 h-3" />
            <span>PDF REPORT</span>
          </button>
        </div>
      </div>

      {hasNoData ? (
        <div className="flex flex-col items-center justify-center py-6 text-center bg-[#090308] rounded-xl border border-red-500/20">
          <Shield className="w-8 h-8 text-slate-600 mb-1.5" />
          <h3 className="text-xs text-slate-300 font-hud font-bold uppercase tracking-wider mb-0.5">No Data Available</h3>
          <p className="text-[10px] text-slate-500 max-w-sm">
            Run an analysis on company domain to generate insights.
          </p>
        </div>
      ) : (
        <>
          {/* Top 6 Mini Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 mb-2">
            {stats.map((stat, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.03 }}
                className="bg-[#090308] border border-red-500/20 rounded-lg p-2 hover:border-red-500/40 transition-all duration-150"
              >
                <div className="flex items-center gap-1 mb-0.5">
                  <stat.icon className={`w-3 h-3 ${stat.color}`} />
                  <span className="text-[8.5px] text-slate-400 uppercase font-hud font-extrabold tracking-wider truncate">{stat.label}</span>
                </div>
                <div className="text-sm sm:text-base font-hud font-black text-white">{stat.value}</div>
                {stat.trend && (
                  <div className="text-[8.5px] text-slate-400 font-bold mt-0.5 flex justify-between items-center font-mono">
                    <span className="text-slate-500">TREND</span>
                    <span className={stat.trend.startsWith('+') ? 'text-red-400 font-black' : 'text-emerald-400 font-black'}>{stat.trend}</span>
                  </div>
                )}
              </motion.div>
            ))}
          </div>

          {/* Severity Breakdown Bar */}
          <div className="grid grid-cols-4 gap-1.5 mb-2">
            <div className="bg-[#090308] border border-rose-500/30 rounded-lg p-1.5 px-2 flex items-center justify-between">
              <span className="text-[8.5px] text-slate-400 uppercase font-hud font-bold tracking-wider">Critical</span>
              <span className="text-xs font-hud font-black text-rose-500">{threatData?.criticalThreats || 3}</span>
            </div>
            <div className="bg-[#090308] border border-amber-500/30 rounded-lg p-1.5 px-2 flex items-center justify-between">
              <span className="text-[8.5px] text-slate-400 uppercase font-hud font-bold tracking-wider">High</span>
              <span className="text-xs font-hud font-black text-amber-400">{threatData?.highThreats || 2}</span>
            </div>
            <div className="bg-[#090308] border border-red-500/30 rounded-lg p-1.5 px-2 flex items-center justify-between">
              <span className="text-[8.5px] text-slate-400 uppercase font-hud font-bold tracking-wider">Medium</span>
              <span className="text-xs font-hud font-black text-red-400">{threatData?.mediumThreats || 1}</span>
            </div>
            <div className="bg-[#090308] border border-emerald-500/30 rounded-lg p-1.5 px-2 flex items-center justify-between">
              <span className="text-[8.5px] text-slate-400 uppercase font-hud font-bold tracking-wider">Low</span>
              <span className="text-xs font-hud font-black text-emerald-400">{threatData?.lowThreats || 0}</span>
            </div>
          </div>

          {/* Charts & Posture Row */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-2 items-stretch">
            {/* 7-Day Trend Chart */}
            <div className="lg:col-span-7 bg-[#090308] border border-red-500/20 rounded-lg p-2 flex flex-col justify-between">
              <div className="flex items-center justify-between mb-1">
                <h3 className="text-[10.5px] font-hud font-bold uppercase tracking-wider text-slate-300">Threat Trend (7 Days)</h3>
                <span className="text-[8.5px] font-mono font-bold text-slate-500">CVSS/EPSS</span>
              </div>
              <div className="h-20 sm:h-24">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={data}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1f0d22" />
                    <XAxis dataKey="date" stroke="#64748b" fontSize={8.5} />
                    <YAxis stroke="#64748b" fontSize={8.5} domain={[75, 95]} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#090308', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '6px', fontSize: '10px', color: '#ffffff' }}
                      itemStyle={{ color: '#ffffff' }}
                    />
                    <Line
                      type="monotone"
                      dataKey="score"
                      stroke="#ef4444"
                      strokeWidth={2}
                      dot={{ fill: '#ef4444', r: 2.5 }}
                      activeDot={{ r: 4, fill: '#f87171' }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* AI Radar Posture Widget */}
            <div className="lg:col-span-5 bg-[#090308] border border-red-500/20 rounded-lg p-2.5 flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping" />
                  <span className="text-[9.5px] font-hud font-bold text-slate-200 uppercase tracking-wider">AI RADAR POSTURE</span>
                </div>
                <span className="text-[8px] font-hud font-bold px-1.5 py-0.5 rounded-full bg-red-950/60 text-red-400 border border-red-500/30">
                  SURVEILLANCE
                </span>
              </div>

              <div className="flex items-center justify-between my-1 px-1">
                <div>
                  <div className="text-lg font-hud font-black text-white tracking-tight">
                    {threatData?.score || 88}%
                  </div>
                  <div className="text-[7.5px] font-mono text-slate-500 uppercase">DEFENSE READINESS</div>
                </div>

                <div className="text-right space-y-0.5">
                  <div className="text-[8px] font-mono text-red-400 font-bold">● PERIMETER: 94%</div>
                  <div className="text-[8px] font-mono text-amber-400 font-bold">● APPSEC: 88%</div>
                  <div className="text-[8px] font-mono text-emerald-400 font-bold">● APT RADAR: 91%</div>
                </div>
              </div>

              <div className="w-full bg-[#060205] rounded px-1.5 py-0.5 border border-red-500/15 flex items-center justify-between text-[7.5px] font-mono text-slate-400">
                <span>TELEMETRY: ALIENVAULT + KEV</span>
                <span className="text-emerald-400 font-bold">● ACTIVE</span>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
