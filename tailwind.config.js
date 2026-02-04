/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Dark theme colors - Watchtower NOC aesthetic
        background: '#0a0e17',
        surface: '#111827',
        'accent-cyan': '#06b6d4',
        'accent-red': '#ef4444',
        'accent-amber': '#f59e0b',
        'accent-green': '#22c55e',
      },
      fontFamily: {
        mono: ['Fira Code', 'Consolas', 'Monaco', 'Courier New', 'monospace'],
      },
    },
  },
  plugins: [],
}
