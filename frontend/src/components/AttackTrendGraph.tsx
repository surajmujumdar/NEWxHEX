'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import { TrendingUp, Activity, ShieldCheck, Zap } from 'lucide-react'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'

export default function AttackTrendGraph() {
  const [showFullChart, setShowFullChart] = useState(false)

  const attackTrendData = [
    { month: 'Jan', attacks: 850, critical: 245, high: 320, medium: 185, low: 100 },
    { month: 'Feb', attacks: 920, critical: 280, high: 350, medium: 190, low: 100 },
    { month: 'Mar', attacks: 880, critical: 260, high: 330, medium: 190, low: 100 },
    { month: 'Apr', attacks: 1050, critical: 320, high: 400, medium: 230, low: 100 },
    { month: 'May', attacks: 1180, critical: 380, high: 450, medium: 250, low: 100 },
    { month: 'Jun', attacks: 1247, critical: 420, high: 480, medium: 247, low: 100 },
  ]

  const stats = {
    totalAttacks: 6127,
    avgPerMonth: 1021,
    criticalAttacks: 1905,
    blockedAttacks: 4850,
    growthRate: '+46.7%',
    peakMonth: 'Jun'
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-[#0c050d] border border-red-500/20 shadow-sm rounded-xl p-3 sm:p-3.5 hover:border-red-500/40 transition-all duration-200 font-hud"
    >
      <div className="flex items-center justify-between mb-2 pb-1.5 border-b border-red-500/15">
        <div className="flex items-center gap-1.5">
          <TrendingUp className="w-3.5 h-3.5 text-red-500 animate-pulse" />
          <h2 className="text-[11px] font-hud font-bold text-white uppercase tracking-widest">ATTACK TREND TELEMETRY</h2>
          <span className="text-[8.5px] font-mono font-bold text-red-400 bg-red-950/60 border border-red-500/30 px-1.5 py-0.5 rounded-full">6M HORIZON</span>
        </div>
        <button
          onClick={() => setShowFullChart(!showFullChart)}
          className="text-[9.5px] font-hud font-bold uppercase tracking-wider text-red-300 hover:text-white transition-colors px-2.5 py-0.5 bg-[#090308] border border-red-500/30 hover:border-red-400 rounded-full cursor-pointer"
        >
          {showFullChart ? 'Show Less' : 'Expand'}
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-1.5 mb-2">
        <div className="bg-[#090308] border border-red-500/20 rounded-lg p-1.5 text-center">
          <div className="text-xs font-hud font-black text-white font-mono">{stats.totalAttacks.toLocaleString()}</div>
          <div className="text-[7.5px] text-slate-400 uppercase font-hud font-bold tracking-wider">Total</div>
        </div>
        <div className="bg-[#090308] border border-red-500/20 rounded-lg p-1.5 text-center">
          <div className="text-xs font-hud font-black text-white font-mono">{stats.avgPerMonth.toLocaleString()}</div>
          <div className="text-[7.5px] text-slate-400 uppercase font-hud font-bold tracking-wider">Avg/Mo</div>
        </div>
        <div className="bg-[#090308] border border-rose-500/30 rounded-lg p-1.5 text-center">
          <div className="text-xs font-hud font-black text-rose-400 font-mono">{stats.criticalAttacks.toLocaleString()}</div>
          <div className="text-[7.5px] text-rose-300/80 uppercase font-hud font-bold tracking-wider">Critical</div>
        </div>
        <div className="bg-[#090308] border border-emerald-500/30 rounded-lg p-1.5 text-center">
          <div className="text-xs font-hud font-black text-emerald-400 font-mono">{stats.blockedAttacks.toLocaleString()}</div>
          <div className="text-[7.5px] text-emerald-300/80 uppercase font-hud font-bold tracking-wider">Blocked</div>
        </div>
        <div className="bg-[#090308] border border-amber-500/30 rounded-lg p-1.5 text-center">
          <div className="text-xs font-hud font-black text-amber-400 font-mono">{stats.growthRate}</div>
          <div className="text-[7.5px] text-amber-300/80 uppercase font-hud font-bold tracking-wider">Growth</div>
        </div>
        <div className="bg-[#090308] border border-red-500/20 rounded-lg p-1.5 text-center">
          <div className="text-xs font-hud font-black text-red-300 font-mono">{stats.peakMonth}</div>
          <div className="text-[7.5px] text-slate-400 uppercase font-hud font-bold tracking-wider">Peak</div>
        </div>
      </div>

      <div className={showFullChart ? "h-40" : "h-24"}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={attackTrendData}>
            <defs>
              <linearGradient id="attackAreaGradRuby" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/>
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f0d22" />
            <XAxis dataKey="month" stroke="#64748b" fontSize={8.5} />
            <YAxis stroke="#64748b" fontSize={8.5} />
            <Tooltip
              contentStyle={{ backgroundColor: '#090308', border: '1px solid rgba(239, 68, 68, 0.4)', borderRadius: '8px', fontSize: '10px', color: '#ffffff' }}
              itemStyle={{ color: '#ef4444' }}
            />
            <Area
              type="monotone"
              dataKey="attacks"
              stroke="#ef4444"
              fill="url(#attackAreaGradRuby)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  )
}
