# Yongsan SexMaster

An Electron application built with TypeScript, React, and Frida.

## Features

- 🚀 Modern Electron app with TypeScript and React
- ⚡ Fast development with esbuild
- 🎨 Beautiful UI with CSS Modules
- 🔒 Secure IPC communication between main and renderer processes
- 📦 Easy packaging with electron-builder

## Prerequisites

- Node.js 16.x or later
- npm 7.x or later
- Git

## Getting Started

1. **Clone the repository**
   ```bash
   git clone https://github.com/MswTester/yongsan-sexmaster.git
   cd yongsan-sexmaster
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

## Available Scripts

- `npm start` - Start the app in production mode
- `npm run dev` - Start the app in development mode with hot-reload
- `npm run build` - Build the app for production
- `npm run dist` - Package the app for distribution
- `npm run dist:win` - Create a Windows installer
- `npm run lint` - Run ESLint

## Project Structure

```
yongsan-sexmaster/
├── build/                  # Build assets and icons
├── dist/                   # Compiled files
├── src/
│   ├── main/              # Main process code
│   │   ├── main.ts         # Main process entry point
│   │   └── preload.ts      # Preload script
│   │
│   ├── renderer/          # Renderer process code
│   │   ├── components/     # React components
│   │   ├── App.tsx         # Main App component
│   │   ├── index.tsx       # Renderer entry point
│   │   ├── index.html      # HTML template
│   │   └── *.css           # Style files
│   │
│   └── types/            # TypeScript type definitions
│
├── .eslintrc.json        # ESLint configuration
├── tsconfig.base.json      # Base TypeScript config
├── tsconfig.main.json      # Main process TypeScript config
├── tsconfig.renderer.json  # Renderer process TypeScript config
└── package.json
```

## Development

1. Start the development server:
   ```bash
   npm run dev
   ```

2. This will start:
   - TypeScript compiler in watch mode for the main process
   - esbuild in watch mode for the renderer process
   - Electron app with hot-reload

## Building for Production

To create a production build:

```bash
npm run build
```

## Packaging

To create a distributable package:

```bash
# For Windows
npm run dist:win

# For all platforms
npm run dist
```

The output will be in the `release` directory.

## License

ISC

---

Created by [Your Name]
frida based
