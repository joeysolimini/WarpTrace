module.exports = {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        warp: {
          bg1: '#0b0414',
          bg2: '#150a2a',
          pink: '#ff2fa1',
          fuchsia: '#c026d3',
          purple: '#7c3aed',
          glow: '#e879f9'
        }
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui'],
        display: ['Orbitron', 'Inter', 'ui-sans-serif']
      },
      boxShadow: {
        neon: '0 0 20px rgba(236, 72, 153, 0.35)',
      },
      backdropBlur: {
        xs: '2px',
      }
    },
  },
  plugins: [],
}

