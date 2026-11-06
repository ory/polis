module.exports = {
  mode: 'jit',
  darkMode: 'class',
  content: [
    './pages/**/*.{js,ts,jsx,tsx}',
    './components/**/*.{js,ts,jsx,tsx}',
    './ee/**/*.{js,ts,jsx,tsx}',
    'node_modules/daisyui/dist/**/*.js',
    'node_modules/rsc-daisyui/dist/**/*.js',
    './internal-ui/src/**/*.{js,ts,jsx,tsx}',
  ],
  daisyui: {
    themes: [
      {
        // boxyhq: {
        //   primary: '#4f39f6',
        //   secondary: '#303846',
        //   accent: '#570DF8',
        //   neutral: '#3D4451',
        //   'base-100': '#FFFFFF',
        //   info: '#3ABFF8',
        //   success: '#36D399',
        //   warning: '#FBBD23',
        //   error: '#F87272',
        // },
        ory: {
          primary: '#4f39f6', // Ory's primary brand color
          secondary: '#1e1b4b', // Dark indigo for secondary (deep, tech feel)
          accent: '#7b61ff', // Lighter purple accent to complement primary
          neutral: '#2f2b3d', // Neutral greyish-purple for UI elements
          'base-100': '#ffffff', // Keep base white for readability
          info: '#5a8eff', // Softer blue tone that fits with purple scheme
          success: '#3cd0ad', // Tweaked success green to stay cool-toned
          warning: '#f4c150', // Muted warm yellow that pops but doesn't clash
          error: '#f46c8d', // Soft magenta-red error color, more on-brand
        },
      },
    ],
  },
  plugins: [require('@tailwindcss/typography'), require('daisyui')],
};
