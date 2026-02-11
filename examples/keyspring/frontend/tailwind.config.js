/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: "#00d4aa",
          dark: "#00b894",
        },
        accent: {
          purple: "#8b5cf6",
          blue: "#3b82f6",
          orange: "#f97316",
        },
        bg: {
          primary: "#0a0a0f",
          secondary: "#12121a",
          card: "#16161f",
          elevated: "#1c1c28",
        },
      },
      fontFamily: {
        sans: ["DM Sans", "-apple-system", "BlinkMacSystemFont", "sans-serif"],
        mono: ["Space Mono", "SF Mono", "Monaco", "monospace"],
      },
      animation: {
        "spin-slow": "spin 2s linear infinite",
      },
    },
  },
  plugins: [],
};
