const { execSync } = require('child_process');
const fs = require('fs-extra');
const path = require('path');

const AGENTS_SRC_DIR = path.join(__dirname, '../src/agents');
const AGENTS_DIST_DIR = path.join(__dirname, '../dist/agents');

async function buildAgents(production = false) {
  try {
    // Ensure dist directory exists
    await fs.ensureDir(AGENTS_DIST_DIR);
    
    // Clean previous builds
    await fs.emptyDir(AGENTS_DIST_DIR);
    
    // Check if agents directory exists and has files
    if (!await fs.pathExists(AGENTS_SRC_DIR)) {
      console.log('No agents directory found, skipping agent compilation');
      return;
    }
    
    const agentFiles = await fs.readdir(AGENTS_SRC_DIR);
    const tsFiles = agentFiles.filter(file => file.endsWith('.ts') && !file.includes('module.ts'));
    
    if (tsFiles.length === 0) {
      console.log('No TypeScript agent files found');
      return;
    }
    
    console.log(`Building ${tsFiles.length} agent(s)...`);
    
    // Compile each agent file
    for (const file of tsFiles) {
      const srcPath = path.join(AGENTS_SRC_DIR, file);
      const baseName = path.basename(file, '.ts');
      const distPath = path.join(AGENTS_DIST_DIR, `${baseName}.js`);
      
      console.log(`Compiling ${file}...`);
      
      try {
        // Use frida-compile to compile the agent
        execSync(`npx frida-compile ${srcPath} -o ${distPath}`, {
          stdio: 'inherit',
          cwd: path.join(__dirname, '..')
        });
        
        console.log(`✓ Compiled ${file} -> ${baseName}.js`);
      } catch (error) {
        console.error(`✗ Failed to compile ${file}:`, error.message);
        throw error;
      }
    }
    
    console.log('All agents compiled successfully!');
  } catch (error) {
    console.error('Agent compilation failed:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  buildAgents();
}

module.exports = { buildAgents };