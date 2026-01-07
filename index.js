const port = process.env.PORT || process.env.SERVER_PORT || 3000;
const FILE_PATH = process.env.FILE_PATH || './.npm';
const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const openhttp = process.env.OPENHTTP || '1';

const startScriptPath = `./start.sh`;
fs.chmodSync(startScriptPath, 0o755);
const startScript = spawn(startScriptPath, [], {
    env: {
        ...process.env,
        OPENHTTP: openhttp
    }
});
startScript.stdout.on('data', (data) => {
    console.log(`${data}`);
});
startScript.stderr.on('data', (data) => {
    console.error(`${data}`);
});
startScript.on('error', (error) => {
    console.error(`boot error: ${error}`);
    process.exit(1);
});

if (openhttp === '1') {
    const server = http.createServer((req, res) => {
        if (req.url === '/') {
            const indexPath = path.join(__dirname, 'index.html');
            fs.readFile(indexPath, 'utf8', (error, data) => {
                if (error) {
                    res.writeHead(500);
                    res.end('Error reading file');
                } else {
                    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                    res.end(data);
                }
            });
        } else {
            res.writeHead(404);
            res.end('Not found');
        }
    });
    server.listen(port, () => {
        console.log(`server is listening on port ${port}`);
    });
} else if (openhttp === '0') {
    console.log(`server is listening on port ${port}`);
}
