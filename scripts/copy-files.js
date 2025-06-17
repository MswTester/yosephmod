const fs = require('fs-extra');
const path = require('path');

async function copyFiles() {
  try {
    // Create necessary directories
    await fs.ensureDir('dist/renderer');
    
    // Copy index.html
    await fs.copyFile(
      path.join('src/renderer/index.html'),
      path.join('dist/renderer/index.html')
    );
    console.log('Copied index.html to dist/renderer');

    // Copy CSS files
    const cssFiles = await fs.readdir('src/renderer');
    for (const file of cssFiles) {
      if (file.endsWith('.css')) {
        await fs.copyFile(
          path.join('src/renderer', file),
          path.join('dist/renderer', file)
        );
        console.log(`Copied ${file} to dist/renderer`);
      }
    }
    
    console.log('All files copied successfully');
  } catch (error) {
    console.error('Error copying files:', error);
    process.exit(1);
  }
}

copyFiles();
