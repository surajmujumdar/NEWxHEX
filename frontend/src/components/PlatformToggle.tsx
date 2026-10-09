'use client'

import React from 'react'
import { Shield, Zap } from 'lucide-react'
import { usePlatformStore } from '@/store/platformStore'

interface PlatformToggleProps {
  className?: string
  compact?: boolean
}

export default function PlatformToggle({ className = '', compact = false }: PlatformToggleProps) {
  const { currentPlatform, setPlatform } = usePlatformStore()
  const isHexStrike = currentPlatform === 'HEXSTRIKE'

  return (
    <div
      className={`relative inline-flex items-center p-0.5 bg-[#090307]/90 border border-red-500/30 rounded-full select-none flex-shrink-0 font-hud backdrop-blur-xl transition-all duration-300 shadow-[0_0_15px_rgba(239,68,68,0.18)] ${className}`}
      data-purpose="platform-toggle"
    >
      {/* Background Animated Slider Pill */}
      <div
        className={`absolute top-0.5 bottom-0.5 rounded-full transition-all duration-300 ease-out ${
          isHexStrike
            ? 'left-[50%] w-[calc(50%-2px)] bg-gradient-to-r from-red-600 to-rose-700 border border-red-400/60 shadow-[0_0_15px_rgba(239,68,68,0.45)]'
            : 'left-0.5 w-[calc(50%-2px)] bg-gradient-to-r from-red-950 to-red-900 border border-red-500/50 shadow-[0_0_12px_rgba(239,68,68,0.35)]'
        }`}
      />

      {/* Button: VAJRA Side */}
      <button
        type="button"
        onClick={() => setPlatform('VAJRA')}
        className={`relative z-10 flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold transition-all duration-200 ${
          !isHexStrike
            ? 'text-white drop-shadow-[0_0_8px_rgba(239,68,68,0.8)]'
            : 'text-zinc-400 hover:text-zinc-200'
        }`}
        title="Switch to VAJRA Threat Intelligence Matrix"
      >
        <Shield
          className={`w-3.5 h-3.5 transition-transform duration-300 ${
            !isHexStrike ? 'text-red-400 scale-110 animate-pulse' : 'text-zinc-500'
          }`}
        />
        <span className="tracking-wider text-[11px] font-mono font-black">VAJRA</span>
        {!compact && (
          <span
            className={`hidden sm:inline-block text-[8px] font-mono px-1 py-0.2 rounded uppercase font-bold ${
              !isHexStrike
                ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                : 'text-zinc-500'
            }`}
          >
            INTEL
          </span>
        )}
      </button>

      {/* Button: HEXSTRIKE Side */}
      <button
        type="button"
        onClick={() => setPlatform('HEXSTRIKE')}
        className={`relative z-10 flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold transition-all duration-200 ${
          isHexStrike
            ? 'text-white drop-shadow-[0_0_10px_rgba(239,68,68,0.9)]'
            : 'text-zinc-400 hover:text-zinc-200'
        }`}
        title="Switch to HexStrike AI MCP Agents Platform"
      >
        <Zap
          className={`w-3.5 h-3.5 transition-transform duration-300 ${
            isHexStrike ? 'text-red-200 scale-110 animate-pulse' : 'text-zinc-500'
          }`}
        />
        <span className="tracking-wider text-[11px] font-mono font-black">HEXSTRIKE</span>
        {!compact && (
          <span
            className={`hidden sm:inline-block text-[8px] font-mono px-1.5 py-0.5 rounded font-bold uppercase ${
              isHexStrike
                ? 'bg-red-950/90 text-white border border-red-400/60 shadow-xs'
                : 'text-zinc-500'
            }`}
          >
            AI MCP
          </span>
        )}
      </button>
    </div>
  )
}
