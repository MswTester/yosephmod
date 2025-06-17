const esbuild = require('esbuild');
const path = require('path');

const isDev = process.env.NODE_ENV !== 'production';
const isWatch = process.argv.includes('--watch');

/** @type {import('esbuild').BuildOptions} */
const config = {
  entryPoints: ['src/renderer/index.tsx'],
  bundle: true,
  outfile: 'dist/renderer.js',
  platform: 'browser',
  target: ['chrome96'],
  loader: {
    '.ts': 'tsx',
    '.tsx': 'tsx',
    '.js': 'jsx',
    '.jsx': 'jsx',
    '.json': 'json',
    '.html': 'text',
    '.woff2': 'file',
    '.woff': 'file',
    '.ttf': 'file',
    '.eot': 'file',
    '.svg': 'file',
  },
  define: {
    'process.env.NODE_ENV': `"${process.env.NODE_ENV || 'development'}"`,
  },
  minify: !isDev,
  sourcemap: isDev,
  tsconfig: './tsconfig.renderer.json',
};

// Add watch options if in watch mode
if (isWatch) {
  config.watch = {
    onRebuild(error) {
      if (error) {
        console.error('Watch build failed:', error);
      } else {
        console.log('Watch build succeeded');
      }
    },
  };
}

// Build the renderer process
async function runBuild() {
  try {
    if (isWatch) {
      // For watch mode, use the context API
      const ctx = await esbuild.context({
        ...config,
        // Add watch-specific options here if needed
      });
      
      await ctx.watch();
      console.log('Watching for changes...');
      
      // Keep the process alive
      await new Promise(() => {});
    } else {
      // For production build
      await esbuild.build(config);
      console.log('Build completed successfully');
    }
  } catch (error) {
    console.error('Build failed:', error);
    process.exit(1);
  }
}

// Only run if this file is executed directly
if (require.main === module) {
  runBuild();
}
