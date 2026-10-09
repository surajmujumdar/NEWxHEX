'use client'

import { create } from 'zustand'

export type PlatformMode = 'VAJRA' | 'HEXSTRIKE'

interface PlatformState {
  currentPlatform: PlatformMode
  setPlatform: (platform: PlatformMode) => void
  togglePlatform: () => void
}

const getInitialPlatform = (): PlatformMode => {
  if (typeof window !== 'undefined') {
    const saved = localStorage.getItem('vajra_active_platform')
    if (saved === 'HEXSTRIKE' || saved === 'VAJRA') {
      return saved
    }
  }
  return 'VAJRA'
}

export const usePlatformStore = create<PlatformState>()((set) => ({
  currentPlatform: 'VAJRA',
  setPlatform: (platform: PlatformMode) => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('vajra_active_platform', platform)
    }
    set({ currentPlatform: platform })
  },
  togglePlatform: () => {
    set((state) => {
      const nextPlatform: PlatformMode = state.currentPlatform === 'VAJRA' ? 'HEXSTRIKE' : 'VAJRA'
      if (typeof window !== 'undefined') {
        localStorage.setItem('vajra_active_platform', nextPlatform)
      }
      return { currentPlatform: nextPlatform }
    })
  },
}))
