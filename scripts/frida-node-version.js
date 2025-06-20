const wget = require('node-wget');
const fs = require('fs');
const path = require('path');
const tar = require('tar');
const os = require('os');
const { execSync } = require('child_process');
const { cwd } = require('process');
const { readJsonSync } = require('fs-extra');

const version = readJsonSync(path.join(cwd(), 'package.json'))?.dependencies?.frida?.replace('^', '');
if(!version) return console.log('Frida version not found in package.json');
const osName = os.platform();
const arch = os.arch();
const electronVersion = '125';
const tail = compareVersion(version, '16.7.15') >= 0 ?
    `napi-v8-${osName}-${arch}.tar.gz` :
    `electron-v${electronVersion}-${osName}-${arch}.tar.gz`
const url = `https://github.com/frida/frida/releases/download/${version}/frida-v${version}-${tail}`;
const downloadPath = path.join(__dirname, '../', `frida-v${version}-${tail}`);
const extractPath = path.join(__dirname, '../', 'build');
const targetPath = path.join(__dirname, '../', 'node_modules', 'frida', 'build');

function compareVersion(v1, v2) {
    const v1Parts = v1.split('.').map(Number);
    const v2Parts = v2.split('.').map(Number);
    for (let i = 0; i < Math.max(v1Parts.length, v2Parts.length); i++) {
        const v1Part = v1Parts[i] || 0;
        const v2Part = v2Parts[i] || 0;
        if (v1Part > v2Part) return 1;
        if (v1Part < v2Part) return -1;
    }
    return 0;
}

async function downloadAndInstall() {
    try {
        // Download the file
        console.log('Downloading Frida binding...');
        await new Promise((resolve, reject) => {
            wget({
                url: url,
                dest: downloadPath
            }, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        if(!fs.existsSync(extractPath)) {
            fs.mkdirSync(extractPath);
        }

        // Extract the tar.gz file
        console.log('Extracting archive...');
        osName.includes('linux') ? 
            execSync(`tar -xvf ${downloadPath}`) : 
            await tar.x({
            file: downloadPath,
            cwd: extractPath,
            strip: 1
        });

        // Move frida_binding.node to target location
        console.log('Installing binding...');
        const bindingPath = path.join(extractPath, 'frida_binding.node');
        if (!fs.existsSync(targetPath)) {
            fs.mkdirSync(targetPath, { recursive: true });
        }
        fs.copyFileSync(bindingPath, path.join(targetPath, 'frida_binding.node'));

        // Clean up
        console.log('Cleaning up...');
        fs.unlinkSync(downloadPath);
        fs.unlinkSync(bindingPath);

        console.log('Installation completed successfully!');
    } catch (error) {
        console.error('Error during installation:', error);
        process.exit(1);
    }
}

downloadAndInstall();