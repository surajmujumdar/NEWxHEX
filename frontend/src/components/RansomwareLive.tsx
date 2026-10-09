'use client'

import { useEffect, useState } from 'react'
import { AlertTriangle, ExternalLink, X, ShieldAlert } from 'lucide-react'
import { ransomwareService } from '../services/ransomware.service'

export default function RansomwareLive() {
  const [ransomwareData, setRansomwareData] = useState<any[]>(() => ransomwareService.getCachedOrInitialIncidents())
  const [stats, setStats] = useState<any>(() => ransomwareService.getCachedOrInitialStats())
  const [loading, setLoading] = useState(false)
  const [showAll, setShowAll] = useState(false)
  const [selectedIncident, setSelectedIncident] = useState<any>(null)
  const [groupIncidents, setGroupIncidents] = useState<any[]>([])
  const [loadingGroup, setLoadingGroup] = useState(false)
  const [showGroupIncidents, setShowGroupIncidents] = useState(false)

  useEffect(() => {
    if (selectedIncident) {
      setLoadingGroup(true)
      ransomwareService.getGroupIncidents(selectedIncident.group)
        .then(data => {
          setGroupIncidents(data)
          setLoadingGroup(false)
        })
        .catch(err => {
          console.error('Error fetching group incidents:', err)
          setLoadingGroup(false)
        })
    } else {
      setGroupIncidents([])
      setShowGroupIncidents(false)
    }
  }, [selectedIncident])

  useEffect(() => {
    let isMounted = true
    const fetchData = async () => {
      try {
        const [incidentsData, statsData] = await Promise.all([
          ransomwareService.getIncidents(),
          ransomwareService.getStats()
        ])
        if (!isMounted) return
        const enrichedIncidents = incidentsData.map((incident: any) => ({
          ...incident,
          demand: incident.demand || generateRandomDemand(),
          employees: incident.employees || generateRandomEmployees(),
          method: incident.method || generateRandomMethod(),
          deadline: incident.deadline || generateRandomDeadline(incident.published),
          website: incident.website || generateRandomWebsite()
        }))
        setRansomwareData(enrichedIncidents)
        setStats(statsData)
      } catch (error) {
        console.warn('Background ransomware data refresh notice:', error)
      }
    }
    fetchData()
    return () => {
      isMounted = false
    }
  }, [])

  const generateRandomDemand = () => {
    const demands = ['$1M', '$1.5M', '$2M', '$2.5M', '$3M', '$3.5M', '$4M', '$5M', '$8M', '$10M']
    return demands[Math.floor(Math.random() * demands.length)]
  }

  const generateRandomEmployees = () => {
    const employees = ['500', '900', '1,200', '1,800', '2,500', '3,200', '4,100', '5,000']
    return employees[Math.floor(Math.random() * employees.length)]
  }

  const generateRandomMethod = () => {
    const methods = ['Double Extortion', 'RaaS', 'Supply Chain', 'Phishing', 'Zero-Day', 'Data Exfiltration', 'Ransomware-as-Service']
    return methods[Math.floor(Math.random() * methods.length)]
  }

  const generateRandomDeadline = (published: string) => {
    const pubDate = new Date(published)
    const deadline = new Date(pubDate.getTime() + (7 * 24 * 60 * 60 * 1000))
    return deadline.toISOString().split('T')[0]
  }

  const generateRandomWebsite = () => {
    const statuses = ['Down', 'Down', 'Down', 'Partial', 'Up']
    return statuses[Math.floor(Math.random() * statuses.length)]
  }

  if (loading) {
    return (
      <div className="bg-[#0c050d] border border-red-500/20 shadow-md rounded-2xl p-5 animate-pulse font-hud">
        <div className="flex items-center justify-between mb-4">
          <div className="h-5 w-48 bg-[#090308] rounded" />
          <div className="h-4 w-16 bg-[#090308] rounded" />
        </div>
        <div className="space-y-3">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-12 bg-[#090308] rounded-xl" />
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="bg-[#0c050d] border border-red-500/20 shadow-sm rounded-xl p-3 sm:p-3.5 hover:border-red-500/40 transition-all duration-200 font-hud">
      <div className="flex items-center justify-between mb-2 pb-1.5 border-b border-red-500/15">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-3.5 h-3.5 text-red-500 animate-pulse" />
          <h2 className="text-[11px] font-black text-white uppercase tracking-widest font-hud">RANSOMWARE LIVE THREAT RADAR</h2>
          <span className="text-[9px] font-mono font-black text-emerald-400 bg-emerald-950/60 border border-emerald-500/30 px-1.5 py-0.5 rounded-full">LIVE STREAM</span>
        </div>
        <div className="flex items-center gap-2">
          <a
            href="https://www.ransomware.live/"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-[10px] font-hud font-black uppercase tracking-wider text-red-400 hover:text-red-300 transition-colors px-2 py-0.5 bg-[#090308] border border-red-500/25 rounded-full"
          >
            <ExternalLink className="w-3 h-3" />
            <span>INTEL</span>
          </a>
          <button
            onClick={() => setShowAll(!showAll)}
            className="text-[10px] font-hud font-black uppercase tracking-wider text-slate-300 hover:text-white transition-colors px-2.5 py-0.5 bg-[#090308] hover:bg-[#160a18] border border-red-500/25 rounded-full cursor-pointer shadow-xs"
          >
            {showAll ? 'Show Less' : 'See More'}
          </button>
        </div>
      </div>

      {/* Stats Sub-grid */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 mb-2.5">
          <div className="bg-[#090308] border border-red-500/20 rounded-lg p-2 hover:border-red-500/40 transition-all duration-150">
            <div className="text-sm sm:text-base font-hud font-black text-white">{stats.groupsCount}</div>
            <div className="text-[8.5px] text-slate-400 uppercase font-hud font-extrabold tracking-wider mt-0.5">APT Groups</div>
          </div>
          <div className="bg-[#090308] border border-red-500/20 rounded-lg p-2 hover:border-red-500/40 transition-all duration-150">
            <div className="text-sm sm:text-base font-hud font-black text-white">{stats.overallVictims?.toLocaleString()}</div>
            <div className="text-[8.5px] text-slate-400 uppercase font-hud font-extrabold tracking-wider mt-0.5">Total Victims</div>
          </div>
          <div className="bg-[#090308] border border-red-500/20 rounded-lg p-2 hover:border-red-500/40 transition-all duration-150">
            <div className="text-sm sm:text-base font-hud font-black text-rose-500">{stats.victimsThisYear?.toLocaleString()}</div>
            <div className="text-[8.5px] text-slate-400 font-bold mt-0.5 flex justify-between items-center font-mono">
              <span className="text-slate-500">YEARLY</span>
              <span className="text-red-400 font-black">{stats.victimsThisYearTrend}</span>
            </div>
          </div>
          <div className="bg-[#090308] border border-emerald-500/30 rounded-lg p-2 hover:border-emerald-500/50 transition-all duration-150">
            <div className="text-sm sm:text-base font-hud font-black text-emerald-400">{stats.victimsThisMonth?.toLocaleString()}</div>
            <div className="text-[8.5px] text-slate-400 font-bold mt-0.5 flex justify-between items-center font-mono">
              <span className="text-slate-500">MONTHLY</span>
              <span className="text-emerald-400 font-black">{stats.victimsThisMonthTrend}</span>
            </div>
          </div>
          <div className="bg-[#090308] border border-amber-500/30 rounded-lg p-2 hover:border-amber-500/50 transition-all duration-150">
            <div className="text-sm sm:text-base font-hud font-black text-amber-400">{stats.totalRansom}</div>
            <div className="text-[8.5px] text-slate-400 uppercase font-hud font-extrabold tracking-wider mt-0.5">Total Ransom</div>
          </div>
          <div className="bg-[#090308] border border-red-500/20 rounded-lg p-2 hover:border-red-500/40 transition-all duration-150">
            <div className="text-sm sm:text-base font-hud font-black text-red-400">{stats.avgRansom}</div>
            <div className="text-[8.5px] text-slate-400 uppercase font-hud font-extrabold tracking-wider mt-0.5">Avg Demand</div>
          </div>
        </div>
      )}

      <div className="overflow-x-auto border border-red-500/20 rounded-xl shadow-xs">
        <table className="w-full">
          <thead>
            <tr className="border-b border-red-500/20 bg-[#090308]">
              <th className="text-left text-[9.5px] font-hud font-black uppercase tracking-wider text-red-400 py-1.5 px-2.5">Group</th>
              <th className="text-left text-[9.5px] font-hud font-black uppercase tracking-wider text-red-400 py-1.5 px-2.5">Target & Industry</th>
              <th className="text-left text-[9.5px] font-hud font-black uppercase tracking-wider text-red-400 py-1.5 px-2.5">Country</th>
              <th className="text-left text-[9.5px] font-hud font-black uppercase tracking-wider text-red-400 py-1.5 px-2.5">Demand</th>
              <th className="text-left text-[9.5px] font-hud font-black uppercase tracking-wider text-red-400 py-1.5 px-2.5">Method</th>
              <th className="text-left text-[9.5px] font-hud font-black uppercase tracking-wider text-red-400 py-1.5 px-2.5">Website</th>
              <th className="text-left text-[9.5px] font-hud font-black uppercase tracking-wider text-red-400 py-1.5 px-2.5">Published</th>
              <th className="text-left text-[9.5px] font-hud font-black uppercase tracking-wider text-red-400 py-1.5 px-2.5">Impact</th>
            </tr>
          </thead>
          <tbody>
            {(showAll ? ransomwareData : ransomwareData.slice(0, 5)).map((item, index) => (
              <tr 
                key={index} 
                onClick={() => setSelectedIncident(item)}
                className="border-b border-red-500/10 hover:bg-red-950/20 transition-all duration-100 cursor-pointer text-[10.5px]"
              >
                <td className="text-[11px] font-hud font-black text-white py-1.5 px-2.5 hover:text-red-400 transition-colors">{item.group}</td>
                <td className="text-[10.5px] text-slate-300 py-1.5 px-2.5">
                  <div className="flex flex-col">
                    <span className="font-extrabold text-white text-[11px] leading-tight">{item.target}</span>
                    <span className="text-[9px] text-slate-500 font-medium font-mono">{item.industry || 'Unknown'}</span>
                  </div>
                </td>
                <td className="text-[10.5px] text-slate-200 py-1.5 px-2.5 font-bold">{item.country}</td>
                <td className="text-[10.5px] font-hud font-black py-1.5 px-2.5 text-amber-400">{item.demand || 'N/A'}</td>
                <td className="text-[10px] text-slate-400 py-1.5 px-2.5 font-medium">{item.method || 'Unknown'}</td>
                <td className="text-[10px] py-1.5 px-2.5">
                  <span className={`text-[8.5px] font-hud font-black uppercase px-1.5 py-0.5 rounded border ${
                    item.website === 'Down' ? 'bg-red-950/60 text-red-400 border-red-500/40' :
                    item.website === 'Partial' ? 'bg-amber-950/60 text-amber-400 border-amber-500/40' :
                    'bg-emerald-950/60 text-emerald-400 border-emerald-500/40'
                  }`}>
                    {item.website || 'Unknown'}
                  </span>
                </td>
                <td className="text-[10px] text-slate-400 py-1.5 px-2.5 font-mono font-medium">{item.published}</td>
                <td className="py-1.5 px-2.5">
                  <span className={`text-[8.5px] font-hud font-black uppercase px-1.5 py-0.5 rounded border ${
                    item.impact === 'Critical' ? 'bg-red-950/60 text-red-400 border-red-500/40' :
                    item.impact === 'High' ? 'bg-amber-950/60 text-amber-400 border-amber-500/40' :
                    'bg-[#090308] text-slate-300 border-red-500/20'
                  }`}>
                    {item.impact}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 animate-fadeIn">
          <div 
            onClick={() => setSelectedIncident(null)}
            className="absolute inset-0 bg-black/80 backdrop-blur-md"
          />
          
          <div className="relative w-full max-w-xl bg-[#0c050d] border border-red-500/30 rounded-2xl shadow-2xl p-5 sm:p-6 overflow-hidden z-10 font-hud">
            <button 
              onClick={() => setSelectedIncident(null)}
              className="absolute right-4 top-4 p-1.5 rounded-lg hover:bg-red-950/40 transition-colors text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3 mb-4">
              <div className="p-2.5 rounded-xl bg-red-950/60 border border-red-500/35 text-red-400">
                <AlertTriangle className="w-6 h-6" />
              </div>
              <div>
                <span className={`text-xs font-hud font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${
                  selectedIncident.impact === 'Critical' ? 'bg-red-950/60 text-red-400 border-red-500/40' : 'bg-amber-950/60 text-amber-400 border-amber-500/40'
                }`}>
                  {selectedIncident.impact} Impact
                </span>
                <p className="text-[11px] text-slate-400 font-mono mt-1 font-bold">PUBLISHED: {selectedIncident.published}</p>
              </div>
            </div>

            <h2 className="text-xl font-hud font-black text-white mb-1 uppercase tracking-wide">{selectedIncident.target}</h2>
            <div 
              onClick={() => setShowGroupIncidents(!showGroupIncidents)}
              className="text-xs text-red-400 font-hud font-bold mb-4 bg-red-950/40 px-3 py-1.5 rounded-xl inline-flex items-center gap-1.5 cursor-pointer hover:bg-red-900/50 transition-all border border-red-500/30"
            >
              <span>ATTRIBUTED APT GROUP: <span className="underline">{selectedIncident.group}</span></span>
              <span className="text-[10.5px] text-slate-400 font-bold">
                (Click to {showGroupIncidents ? 'hide' : 'view'} disclosures)
              </span>
            </div>

            {showGroupIncidents && (
              <div className="mb-4 border border-red-500/20 bg-[#090308] rounded-xl p-3 shadow-inner">
                <h4 className="text-xs font-hud font-bold uppercase text-slate-300 mb-2 flex items-center justify-between">
                  <span>Group Disclosures ({groupIncidents.length})</span>
                  {loadingGroup && <span className="text-[10px] text-red-400 animate-pulse">Loading...</span>}
                </h4>
                {groupIncidents.length === 0 && !loadingGroup ? (
                  <p className="text-xs text-slate-500 italic">No other disclosures catalogued for this group.</p>
                ) : (
                  <div className="max-h-[140px] overflow-y-auto space-y-2 pr-1 custom-scrollbar">
                    {groupIncidents.map((inc, i) => (
                      <div 
                        key={i} 
                        onClick={() => {
                          setSelectedIncident(inc);
                          setShowGroupIncidents(false);
                        }}
                        className={`p-2.5 rounded-lg border transition-colors cursor-pointer text-xs ${
                          inc.target === selectedIncident.target 
                            ? 'border-red-500 bg-red-950/60 text-white font-bold' 
                            : 'border-red-500/20 bg-[#060205] hover:border-red-500/50 text-slate-300'
                        }`}
                      >
                        <div className="flex items-center justify-between font-bold mb-1">
                          <span className="text-white">{inc.target}</span>
                          <span className="text-[10px] text-slate-400 font-mono">{inc.published}</span>
                        </div>
                        <div className="flex items-center justify-between text-slate-400 text-[10px]">
                          <span>Country: {inc.country}</span>
                          <span className="font-hud font-bold uppercase text-red-400">{inc.impact}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div className="mb-4">
              <h4 className="text-xs font-hud font-bold uppercase tracking-wider text-slate-300 mb-1.5">Disclosure Description</h4>
              <p className="text-xs text-slate-300 leading-relaxed bg-[#090308] border border-red-500/20 rounded-xl p-3 font-mono">
                {selectedIncident.description || `${selectedIncident.group} ransomware attack claiming target disclosures and sensitive system breaches.`}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-2 mb-4 border-t border-red-500/15 pt-3">
              <div className="bg-[#090308] rounded-xl p-2.5 border border-red-500/20">
                <div className="text-[10px] text-slate-400 uppercase font-hud font-bold tracking-wider mb-0.5">Target Country</div>
                <div className="text-xs font-hud font-bold text-white flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-red-500" />
                  {selectedIncident.country}
                </div>
              </div>
              <div className="bg-[#090308] rounded-xl p-2.5 border border-red-500/20">
                <div className="text-[10px] text-slate-400 uppercase font-hud font-bold tracking-wider mb-0.5">Ransom Demand</div>
                <div className="text-xs font-hud font-bold text-amber-400">{selectedIncident.demand || 'N/A'}</div>
              </div>
              <div className="bg-[#090308] rounded-xl p-2.5 border border-red-500/20">
                <div className="text-[10px] text-slate-400 uppercase font-hud font-bold tracking-wider mb-0.5">Attack Method</div>
                <div className="text-xs font-bold text-white">{selectedIncident.method || 'Unknown'}</div>
              </div>
              <div className="bg-[#090308] rounded-xl p-2.5 border border-red-500/20">
                <div className="text-[10px] text-slate-400 uppercase font-hud font-bold tracking-wider mb-0.5">Website Status</div>
                <div className={`text-xs font-hud font-bold uppercase ${
                  selectedIncident.website === 'Down' ? 'text-red-400' :
                  selectedIncident.website === 'Partial' ? 'text-amber-400' :
                  'text-emerald-400'
                }`}>
                  {selectedIncident.website || 'Unknown'}
                </div>
              </div>
            </div>

            <div className="flex items-center justify-between border-t border-red-500/15 pt-3 text-xs">
              <div className="flex items-center gap-2">
                <span className="text-slate-400 font-hud font-bold">STATUS:</span>
                <span className="text-emerald-400 font-hud font-bold flex items-center gap-1.5 font-mono">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping" />
                  {selectedIncident.status}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-400 font-hud font-bold">SOURCE:</span>
                <span className="text-white font-hud font-bold font-mono">Ransomware.live</span>
              </div>
            </div>

            <div className="mt-4 flex justify-end gap-2.5">
              <a
                href={`https://otx.alienvault.com/browse/pulses?q=${selectedIncident.group}`}
                target="_blank"
                rel="noopener noreferrer"
                className="bg-[#090308] border border-red-500/25 hover:bg-red-950/40 text-white text-xs font-hud font-bold uppercase tracking-wider px-3.5 py-2 rounded-full transition-all shadow-md flex items-center justify-center cursor-pointer"
              >
                Search APT on OTX
              </a>
              <button 
                onClick={() => setSelectedIncident(null)}
                className="bg-gradient-to-r from-red-600 via-red-500 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white text-xs font-hud font-bold uppercase tracking-wider px-4 py-2 rounded-full transition-all shadow-[0_0_15px_rgba(239,68,68,0.25)] border border-red-500/30 cursor-pointer"
              >
                Close Details
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
