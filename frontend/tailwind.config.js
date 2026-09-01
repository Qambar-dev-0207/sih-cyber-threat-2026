/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          darkest: '#030508',
          bg: '#06080F',
          card: '#0B0F19',
          elevated: '#111827',
          border: '#1E293B',
          cyan: '#06B6D4',
          'cyan-bright': '#22D3EE',
          'cyan-glow': 'rgba(6, 182, 212, 0.3)',
          amber: '#F97316',
          'amber-bright': '#FB923C',
          crimson: '#EF4444',
          'crimson-bright': '#F87171',
          'crimson-glow': 'rgba(239, 68, 68, 0.3)',
          emerald: '#10B981',
          'emerald-bright': '#34D399',
          yellow: '#EAB308',
          purple: '#8B5CF6',
          neon: '#00F0FF',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', 'Menlo', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      boxShadow: {
        'neon-cyan': '0 0 15px rgba(6, 182, 212, 0.35)',
        'neon-cyan-lg': '0 0 25px rgba(6, 182, 212, 0.5)',
        'neon-red': '0 0 15px rgba(239, 68, 68, 0.4)',
        'neon-red-lg': '0 0 25px rgba(239, 68, 68, 0.6)',
        'neon-amber': '0 0 15px rgba(249, 115, 22, 0.4)',
        'neon-green': '0 0 15px rgba(16, 185, 129, 0.4)',
        'panel': '0 4px 20px -2px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(30, 41, 59, 0.8)',
      },
      animation: {
        'pulse-fast': 'pulse 1s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scanline': 'scanline 8s linear infinite',
        'flicker': 'flicker 0.15s infinite',
        'glow-pulse': 'glowPulse 2s ease-in-out infinite',
      },
      keyframes: {
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(1000%)' },
        },
        glowPulse: {
          '0%, 100%': { opacity: '0.8', filter: 'drop-shadow(0 0 8px rgba(6,182,212,0.6))' },
          '50%': { opacity: '1', filter: 'drop-shadow(0 0 16px rgba(6,182,212,0.9))' },
        },
      },
    },
  },
  plugins: [],
}
