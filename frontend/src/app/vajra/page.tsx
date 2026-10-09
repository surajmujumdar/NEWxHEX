'use client'

import React, { useEffect, useState } from 'react'
import Dashboard from '@/components/Dashboard'

export default function VajraPage() {
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) {
    return (
      <div className="flex min-h-screen bg-[#060205] items-center justify-center font-main">
        <div className="flex flex-col items-center gap-3">
          <div className="w-12 h-12 rounded-2xl bg-red-950/60 border border-red-900/40 flex items-center justify-center animate-pulse shadow-[0_0_20px_rgba(239,68,68,0.25)]">
            <span className="text-red-500 font-hud font-bold text-lg">V</span>
          </div>
          <p className="text-zinc-400 text-xs font-mono tracking-wide">Initializing VAJRA Threat Intelligence Platform...</p>
        </div>
      </div>
    )
  }

  return <Dashboard />
}
