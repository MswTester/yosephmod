const wget = require('node-wget');
const fs = require('fs');
const path = require('path');
const tar = require('tar');
const os = require('os');

const version = '16.7.14';
const osName = os.platform();
const arch = os.arch();
const electronVersion = '125';
const url = `https://github.com/frida/frida/releases/download/${version}/frida-v${version}-electron-v${electronVersion}-${osName}-${arch}.tar.gz`;
const downloadPath = path.join(__dirname, '../', `frida-v${version}-electron-v${electronVersion}-${osName}-${arch}.tar.gz`);
const extractPath = path.join(__dirname, '../', 'build');
const targetPath = path.join(__dirname, '../', 'node_modules', 'frida', 'build');

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