'use client'

import { useEffect, useState } from 'react'
import { ArrowRight, RefreshCw, TrendingUp, Globe, Shield, AlertTriangle, Activity, Building2 } from 'lucide-react'
import { dashboardService } from '../services/dashboard.service'
import { ransomwareService } from '../services/ransomware.service'
import { useRouter } from 'next/navigation'
import { useCompanyStore } from '@/store/companyStore'
import { useLanguageStore } from '@/store/languageStore'

export default function TopCards() {
  const router = useRouter()
  const { companies, fetchCompanies } = useCompanyStore()
  const { t } = useLanguageStore()
  const [summary, setSummary] = useState<any>({
    total_attacks: 12847,
    active_threat_actors: 395,
    critical_attacks: 45,
    last_updated: new Date().toISOString()
  })
  const [isUpdating, setIsUpdating] = useState(false)

  useEffect(() => {
    let isMounted = true

    const fetchData = async () => {
      try {
        setIsUpdating(true)
        const [summaryData, rStats] = await Promise.allSettled([
          dashboardService.getSummary(),
          ransomwareService.getStats(),
          fetchCompanies()
        ])
        if (isMounted) {
          let updatedObj = { ...summary }
          if (summaryData.status === 'fulfilled' && summaryData.value) {
            updatedObj = { ...updatedObj, ...summaryData.value }
          }
          if (rStats.status === 'fulfilled' && rStats.value) {
            if (rStats.value.groupsCount || rStats.value.activeGroups) {
              updatedObj.active_threat_actors = rStats.value.groupsCount || rStats.value.activeGroups || 395
            }
          }
          setSummary(updatedObj)
        }
      } catch (error) {
        console.error('Error fetching dashboard summary:', error)
      } finally {
        if (isMounted) setIsUpdating(false)
      }
    }

    fetchData()
    const pollingInterval = setInterval(fetchData, 15000)

    return () => {
      isMounted = false
      clearInterval(pollingInterval)
    }
  }, [fetchCompanies])

  const monitoredCount = companies ? companies.length : 0

  const cards = [
    {
      label: t('monitoredCompanies', 'Monitored Companies'),
      value: `${monitoredCount} ACTIVE`,
      subtext: 'Portfolio →',
      icon: Building2,
      color: 'text-red-400',
      bgColor: 'bg-red-950/60 border-red-500/30',
      hoverColor: 'group-hover:text-red-400',
      path: '/companies',
    },
    {
      label: t('lastUpdated', 'Last Updated'),
      value: 'LIVE FEED',
      subtext: 'Real-time sync',
      icon: RefreshCw,
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-950/60 border-emerald-500/30',
      hoverColor: 'group-hover:text-emerald-400',
      path: '/updates',
    },
    {
      label: t('globalAttacksToday', 'Global Attacks Today'),
      value: (summary?.total_attacks || 12847).toLocaleString(),
      trend: '↑ 18%',
      subtext: 'Threat Pulses',
      icon: TrendingUp,
      color: 'text-red-500',
      bgColor: 'bg-red-950/60 border-red-500/30',
      hoverColor: 'group-hover:text-red-400',
      path: '/global-attacks',
    },
    {
      label: t('activeThreatActors', 'Active Threat Actors'),
      value: (summary?.active_threat_actors || 395).toLocaleString(),
      trend: '↑ 12%',
      subtext: 'APT Groups',
      icon: Shield,
      color: 'text-amber-400',
      bgColor: 'bg-amber-950/60 border-amber-500/30',
      hoverColor: 'group-hover:text-amber-400',
      path: '/threat-intelligence/actors',
    },
  ]

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 font-hud">
      {cards.map((card, index) => (
        <div
          key={index}
          onClick={() => router.push(card.path)}
          className="bg-[#0c050d] border border-red-500/20 rounded-xl p-3 sm:p-3.5 hover:border-red-500/50 transition-all duration-150 hover:shadow-[0_0_15px_rgba(239,68,68,0.15)] cursor-pointer flex flex-col justify-between group relative overflow-hidden backdrop-blur-md shadow-sm"
        >
          <div className="flex items-start justify-between mb-1.5">
            <div className="flex-1 min-w-0">
              <p className="text-[9.5px] text-zinc-400 uppercase tracking-wider font-bold truncate mb-0.5">
                {card.label}
              </p>
              <p className={`text-lg sm:text-xl font-black text-white tracking-tight ${card.hoverColor} transition-colors`}>
                {card.value}
              </p>
            </div>
            <div className={`p-2 rounded-lg ${card.bgColor} border flex-shrink-0 ml-2 shadow-xs`}>
              <card.icon className={`w-4 h-4 ${card.color}`} />
            </div>
          </div>

          <div className="flex items-center justify-between pt-2 border-t border-red-500/10 text-xs">
            <span className="text-zinc-400 font-bold text-[10px] truncate tracking-wide">{card.subtext}</span>
            {card.trend && (
              <span className={`font-mono font-black text-[9.5px] ${card.color} ml-1.5 flex-shrink-0 tracking-wider ${card.bgColor} px-1.5 py-0.5 rounded border`}>
                {card.trend}
              </span>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}
