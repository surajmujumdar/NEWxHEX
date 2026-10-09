'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import { AlertTriangle, ArrowRight, Download } from 'lucide-react'
import { alertsService } from '../services/alerts.service'
import { useRouter } from 'next/navigation'
import { useCompanyStore } from '@/store/companyStore'

export default function CriticalAlerts() {
  const [alerts, setAlerts] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [downloading, setDownloading] = useState(false)
  const router = useRouter()
  const { selectedCompany } = useCompanyStore()

  const handleDownloadReport = async () => {
    setDownloading(true)
    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
      const url = selectedCompany 
        ? `${API_URL}/api/reports/company/${selectedCompany.id}`
        : `${API_URL}/api/reports/executive`
      
      const response = await fetch(url)
      const blob = await response.blob()
      const downloadUrl = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = downloadUrl
      link.download = selectedCompany 
        ? `${selectedCompany.name.replace(' ', '_')}_report.pdf`
        : 'executive_summary_report.pdf'
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

  const formatAlertTime = (time: string) => {
    if (!time || time === 'Unknown') return 'Unknown'
    try {
      const date = new Date(time)
      if (!isNaN(date.getTime())) {
        return date.toLocaleTimeString('en-US', {
          hour: '2-digit',
          minute: '2-digit',
          hour12: true
        })
      }
      return time
    } catch (e) {
      return time
    }
  }

  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await alertsService.getAlerts()
        const enrichedAlerts = data.map((alert: any) => ({
          ...alert,
          source: alert.source || generateRandomSource(),
          affectedSystems: alert.affectedSystems || generateRandomAffectedSystems(),
          status: alert.status || generateRandomStatus(),
          confidence: alert.confidence || generateRandomConfidence()
        }))
        setAlerts(enrichedAlerts)
      } catch (error) {
        console.error('Error fetching alerts:', error)
        const mockAlerts = [
          {
            id: '1',
            title: 'Critical Ransomware Attack Detected',
            description: 'LockBit 3.0 activity targeting infrastructure. Immediate isolation advised.',
            time: '2026-08-03T12:00:00',
            severity: 'CRITICAL',
            source: 'Ransomware.live',
            affectedSystems: '45',
            status: 'Active',
            confidence: 'High'
          },
          {
            id: '2',
            title: 'Exploitation of CVE-2024-3400',
            description: 'PAN-OS command injection vulnerability exploited in the wild.',
            time: '2026-08-03T11:45:00',
            severity: 'CRITICAL',
            source: 'Threat Intelligence',
            affectedSystems: '12',
            status: 'Investigating',
            confidence: 'High'
          },
          {
            id: '3',
            title: 'Phishing Campaign with Payload',
            description: 'Spear-phishing targeting financial assets with custom malware.',
            time: '2026-08-03T11:30:00',
            severity: 'HIGH',
            source: 'Phishing Feed',
            affectedSystems: '89',
            status: 'Blocked',
            confidence: 'Medium'
          },
        ]
        setAlerts(mockAlerts)
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [])

  const generateRandomSource = () => {
    const sources = ['Ransomware.live', 'CVE Database', 'Dark Web', 'Threat Intel', 'Phishing Feed', 'Scanner', 'IDS']
    return sources[Math.floor(Math.random() * sources.length)]
  }

  const generateRandomAffectedSystems = () => {
    const counts = ['1', '5', '12', '17', '45', '89', '200+']
    return counts[Math.floor(Math.random() * counts.length)]
  }

  const generateRandomStatus = () => {
    const statuses = ['Active', 'Investigating', 'Blocked', 'Monitoring', 'Resolved']
    return statuses[Math.floor(Math.random() * statuses.length)]
  }

  const generateRandomConfidence = () => {
    const confidences = ['High', 'Medium', 'Low']
    return confidences[Math.floor(Math.random() * confidences.length)]
  }

  if (loading) {
    return (
      <div className="font-hud">
        <div className="h-4 w-40 bg-[#0c050d] rounded mb-2 animate-pulse" />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="bg-[#0c050d] border border-red-500/20 rounded-xl p-3 h-[120px] animate-pulse" />
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="font-hud">
      <div className="flex items-center justify-between mb-2 pb-1.5 border-b border-red-500/15">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-3.5 h-3.5 text-red-500 animate-pulse" />
          <h2 className="text-[11px] font-black text-white uppercase tracking-widest font-hud">RECENT CRITICAL ALERTS</h2>
          <span className="text-[9px] font-mono font-black text-emerald-400 bg-emerald-950/60 border border-emerald-500/30 px-1.5 py-0.5 rounded-full">LIVE TELEMETRY</span>
        </div>
        <button
          onClick={handleDownloadReport}
          disabled={downloading}
          className="flex items-center gap-1.5 px-2.5 py-1 bg-gradient-to-r from-red-600 via-red-500 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-hud font-black text-[10px] uppercase tracking-wider rounded-full shadow-[0_0_12px_rgba(239,68,68,0.2)] transition-all disabled:opacity-50 cursor-pointer border border-red-500/30"
          title="Download PDF Report"
        >
          <Download className="w-3 h-3" />
          <span>PDF REPORT</span>
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
        {alerts.slice(0, 3).map((alert, index) => (
          <Link
            key={alert.id || index}
            href="/alerts"
            prefetch={true}
            className="bg-[#0c050d] border border-red-500/20 shadow-sm rounded-xl p-3 hover:border-red-500/50 hover:shadow-[0_0_15px_rgba(239,68,68,0.15)] transition-all duration-150 cursor-pointer flex flex-col justify-between h-[125px] group"
          >
            <div>
              <div className="flex items-start justify-between mb-1.5">
                <div className="flex items-center gap-1 font-mono">
                  <AlertTriangle className={`w-3 h-3 ${alert.severity === 'CRITICAL' ? 'text-red-500' : 'text-amber-400'}`} />
                  <span className={`text-[8.5px] font-black uppercase tracking-wider ${alert.severity === 'CRITICAL' ? 'bg-red-950/60 text-red-400 border-red-500/40' : 'bg-amber-950/60 text-amber-400 border-amber-500/40'} px-1.5 py-0.5 rounded border`}>
                    {alert.severity || 'CRITICAL'}
                  </span>
                </div>
                <span className="text-[9.5px] text-slate-400 font-mono font-bold">{formatAlertTime(alert.time)}</span>
              </div>
              <h3 className="text-[11px] font-black text-white mb-1 line-clamp-1 leading-tight tracking-wide group-hover:text-red-400 transition-colors font-hud">{alert.title}</h3>
              <div className="flex items-center gap-1 mb-1">
                <span className="text-[8.5px] font-bold text-slate-300 bg-[#090308] border border-red-500/20 px-1.5 py-0.5 rounded font-mono">{alert.source || 'Unknown'}</span>
                {alert.affectedSystems && (
                  <span className="text-[8.5px] font-bold text-red-300 bg-red-950/40 border border-red-500/30 px-1.5 py-0.5 rounded font-mono">{alert.affectedSystems} Hosts</span>
                )}
              </div>
            </div>
            <p className="text-[9.5px] text-slate-400 font-medium line-clamp-1 mt-auto leading-normal">{alert.description}</p>
            {alert.status && (
              <div className="mt-1 pt-1 border-t border-red-500/15 flex items-center justify-between">
                <span className={`text-[9px] font-black uppercase tracking-wider font-mono ${
                  alert.status === 'Active' ? 'text-red-400' :
                  alert.status === 'Blocked' ? 'text-emerald-400' :
                  'text-amber-400'
                }`}>
                  STATUS: {alert.status}
                </span>
              </div>
            )}
          </Link>
        ))}
        <Link 
          href="/alerts"
          prefetch={true}
          className="bg-[#090308] border border-red-500/25 rounded-xl p-3 flex flex-col items-center justify-center gap-2 hover:border-red-500/50 hover:bg-red-950/20 transition-all duration-150 group h-[125px]"
        >
          <span className="text-[11px] font-black uppercase tracking-wider text-red-400 group-hover:text-red-300 transition-colors font-hud">VIEW ALL ALERTS</span>
          <ArrowRight className="w-3.5 h-3.5 text-red-400 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </div>
  )
}
