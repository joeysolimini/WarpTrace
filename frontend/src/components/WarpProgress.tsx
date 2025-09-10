import React from 'react'

export default function WarpProgress({ progress, label = 'Analyzing' }: { progress: number; label?: string }) {
  const pct = Math.max(0, Math.min(100, progress ?? 0))
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-xs text-white/70">{label}</span>
        <span className="text-xs text-white/70">{pct}%</span>
      </div>

      <div className="warp-track">
        <div className="warp-starfield" />
        <div className="warp-bar" style={{ width: `${pct}%` }}>
          <div className="warp-shimmer" />
          <div className="warp-comet" />
        </div>
      </div>

      <p className="text-[10px] text-white/50">Warping packets through anomaly detectors…</p>
    </div>
  )
}
