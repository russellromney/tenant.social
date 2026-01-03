/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        // Background colors
        bg: {
          DEFAULT: 'var(--bg)',
          card: 'var(--bg-card)',
          hover: 'var(--bg-hover)',
          muted: 'var(--bg-muted)',
          input: 'var(--bg-input)',
        },

        // Text colors
        text: {
          DEFAULT: 'var(--text)',
          muted: 'var(--text-muted)',
          secondary: 'var(--text-secondary)',
          subtle: 'var(--text-subtle)',
          disabled: 'var(--text-disabled)',
        },

        // Accent colors
        accent: {
          DEFAULT: 'var(--accent)',
          text: 'var(--accent-text)',
        },

        // Border colors
        border: {
          DEFAULT: 'var(--border)',
          input: 'var(--border-input)',
        },

        // Status colors
        error: {
          DEFAULT: 'var(--error-bg)',
          text: 'var(--error-text)',
        },
        success: {
          DEFAULT: 'var(--success)',
          text: 'var(--success-text)',
        },
      },
    },
  },
  plugins: [],
}
