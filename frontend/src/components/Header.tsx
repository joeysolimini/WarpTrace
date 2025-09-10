import React from 'react'

export default function Header({
  loggedIn,
  onLogout,
  subtitle = 'Futuristic log analysis for SOC analysts',
  version = 'v0.1',
}: {
  loggedIn?: boolean
  onLogout?: () => void
  subtitle?: string
  version?: string
}) {
  return (
    <header className="grid grid-cols-[1fr_auto] grid-rows-[auto_auto] gap-y-1 mb-6">
      {/* Row 1, Left: wordmark */}
      <div className="row-start-1 col-start-1 text-2xl md:text-3xl font-black tracking-tight">
        <span className="bg-gradient-to-r from-warp-pink via-warp-fuchsia to-warp-purple bg-clip-text text-transparent">
          Warptrace
        </span>
      </div>

      {/* Row 1, Right: Logout aligned with wordmark */}
      <div className="row-start-1 col-start-2 flex justify-end">
        {loggedIn && (
          <button
            className="warp-btn text-xs px-3 py-1"
            onClick={onLogout}
            title="Sign out"
          >
            Logout
          </button>
        )}
      </div>

      {/* Row 2, Left: subtitle/tagline */}
      <div className="row-start-2 col-start-1 text-sm warp-subtle">
        {subtitle}
      </div>

      {/* Row 2, Right: version chip aligned with subtitle */}
      <div className="row-start-2 col-start-2 flex justify-end">
        <a
          className="text-xs px-3 py-1 rounded-lg border border-white/10 bg-white/5 hover:bg-white/10 transition"
          href="https://github.com/warptrace"
          onClick={(e) => e.preventDefault()}
        >
          {version}
        </a>
      </div>
    </header>
  )
}
