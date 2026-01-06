const FILE_PATH = process.env.FILE_PATH || './.npm';
const intervalInseconds = process.env.TIME || 100;
const OPENSERVER = (process.env.OPENSERVER || 'true') === 'true'; // true OR false
const KEEPALIVE = (process.env.KEEPALIVE || 'false') === 'true';

const ECH_PORT = process.env.ECH_PORT || 8001;
const ECH_PROTOCOL = process.env.ECH_PROTOCOL || 'ws';
const ECH_LISTEN = process.env.ECH_LISTEN || 'proxy://127.0.0.1:10808';
const ECH_DNS = process.env.ECH_DNS || 'dns.alidns.com/dns-query';
const ECH_URL = process.env.ECH_URL || 'cloudflare-ech.com';
const CFIP = process.env.CFIP || 'ip.sb';
const MY_DOMAIN = process.env.MY_DOMAIN || '';
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || 'zp.tcgd001.cf';
const ARGO_AUTH = process.env.ARGO_AUTH || 'eyJhIjoiNjFmNmJhODg2ODkxNmJmZmM1ZDljNzM2NzdiYmIwMDYiLCJ0IjoiNWU2MGY5NmItMmI2Yi00M2MxLWE5OTAtMDA4NTI0YTE0MTk5IiwicyI6IlltVXhZak15TmpZdFpEQmlZeTAwTWpReUxUbGlabVF0TmpnNVlqQTJOR00wWmprMyJ9';

const PORT = process.env.PORT || process.env.SERVER_PORT || 3000;
const UUID = process.env.UUID || '9e2588b8-2a6a-4cf1-a7d6-66e25cc9c7f4';
const NEZHA_VERSION = process.env.NEZHA_VERSION || 'V1';
const NEZHA_SERVER = process.env.NEZHA_SERVER || 'nazha.tcguangda.eu.org';
const NEZHA_PORT = process.env.NEZHA_PORT || '443';
const NEZHA_KEY = process.env.NEZHA_KEY || 'ilovehesufeng520';
const SUB_NAME = process.env.SUB_NAME || 'zeeploy';
const SUB_URL = process.env.SUB_URL || 'https://myjyup.shiguangda.nom.za/upload-a4aa34be-4373-4fdb-bff7-0a9c23405dac';

const axios = require("axios");
const { pipeline } = require('stream/promises');
const os = require('os');
const fs = require("fs");
const path = require("path");
const http = require('http');
const https = require('https');
const exec = require("child_process").exec;
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function createFolder(folderPath) {
    try {
        fs.statSync(folderPath);
        console.log(`${folderPath} already exists`);
    } catch (err) {
        if (err.code === 'ENOENT') {
            fs.mkdirSync(folderPath);
            console.log(`${folderPath} is created`);
        } else {
            // throw err;
        }
    }
}

const pathsToDelete = ['bot', 'web', 'npm', 'config.yml', 'boot.log', 'log.txt'];
function cleanupOldFiles() {
    for (const file of pathsToDelete) {
        const filePath = path.join(FILE_PATH, file);
        try {
            const stats = fs.statSync(filePath);
            if (stats.isDirectory()) {
                fs.rmSync(filePath, { recursive: true });
                // console.log(`${filePath} deleted (directory)`);
            } else {
                fs.unlinkSync(filePath);
                // console.log(`${filePath} deleted (file)`);
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                // console.error(`Failed to delete ${filePath}:`, error);
            }
        }
    }
}

function httpserver() {
    const server = http.createServer((req, res) => {
        if (req.url === '/') {
            res.writeHead(200);
            res.end('hello world');
        } else if (req.url === '/sub') {
            const subFilePath = FILE_PATH + '/log.txt';
            fs.readFile(subFilePath, 'utf8', (error, data) => {
                if (error) {
                    res.writeHead(500);
                    res.end('Error reading file');
                } else {
                    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
                    res.end(data);
                }
            });
        } else {
            res.writeHead(404);
            res.end('Not found');
        }
    });
    server.listen(PORT, () => {
        console.log(`server is running on port : ${PORT}`);
    });
}

function execPromise(command, options = {}) {
    return new Promise((resolve, reject) => {
        const child = exec(command, options, (error, stdout, stderr) => {
            if (error) {
                const err = new Error(`Command failed: ${error.message}`);
                err.code = error.code;
                err.stderr = stderr.trim();
                reject(err);
            } else {
                resolve(stdout.trim());
            }
        });
    });
}

async function detectProcess(processName) {
    const methods = [
        { cmd: `pidof "${processName}"`, name: 'pidof' },
        { cmd: `pgrep -x "${processName}"`, name: 'pgrep' },
        { cmd: `ps -eo pid,comm | awk -v name="${processName}" '$2 == name {print $1}'`, name: 'ps+awk' }
    ];

    for (const method of methods) {
        try {
            const stdout = await execPromise(method.cmd);
            if (stdout) {
                return stdout.replace(/\n/g, ' ').trim();
            }
        } catch (error) {
            if (error.code !== 127 && error.code !== 1) {
                console.debug(`[detectProcess] ${method.name} error:`, error.message);
            }
        }
    }
    return '';
}

async function killProcess(process_name) {
    console.log(`Attempting to kill process: ${process_name}`);
    try {
        const pids = await detectProcess(process_name);
        if (!pids) {
            console.warn(`Process '${process_name}' not found`);
            return { success: true, message: 'Process not found' };
        }

        await execPromise(`kill -9 ${pids}`);
        const msg = `Killed process (PIDs: ${pids})`;
        console.log(msg);
        return { success: true, message: msg };

    } catch (error) {
        const msg = `Kill failed: ${error.message}`;
        console.error(msg);
        return { success: false, message: msg };
    }
}

function getSystemArchitecture() {
    const arch = os.arch();
    if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
        return 'arm';
    } else {
        return 'amd';
    }
}

function getFilesForArchitecture(architecture) {
    const FILE_URLS = {
        bot: {
            arm: "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64",
            amd: "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
        },
        web: {
            arm: "https://github.com/kahunama/myfile/releases/download/main/ech-tunnel-linux-arm64",
            amd: "https://github.com/kahunama/myfile/releases/download/main/ech-tunnel-linux-amd64"
        },
        npm: {
            V0: {
                arm: "https://github.com/kahunama/myfile/releases/download/main/nezha-agent_arm",
                amd: "https://github.com/kahunama/myfile/releases/download/main/nezha-agent"
            },
            V1: {
                arm: "https://github.com/mytcgd/myfiles/releases/download/main/nezha-agentv1_arm",
                amd: "https://github.com/mytcgd/myfiles/releases/download/main/nezha-agentv1"
            }
        }
    };
    let baseFiles = [
        { fileName: "web", fileUrl: FILE_URLS.web[architecture] }
    ];

    if (OPENSERVER) {
        const botFile = {
            fileName: "bot",
            fileUrl: FILE_URLS.bot[architecture]
        };
        baseFiles.push(botFile);
    }

    if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY && NEZHA_VERSION) {
        const npmFile = {
            fileName: "npm",
            fileUrl: FILE_URLS.npm[NEZHA_VERSION][architecture]
        };
        baseFiles.push(npmFile);
    }

    return baseFiles;
}

async function download_function(fileName, fileUrl) {
    const filePath = path.join(FILE_PATH, fileName);
    let downloadSuccess = false;

    try {
        fs.statSync(filePath);
        console.log(`File ${fileName} already exists, skipping download.`);
        downloadSuccess = true;
    } catch (error) {
        if (error.code === 'ENOENT') {
            try {
                const response = await axios({
                    method: 'get',
                    url: fileUrl,
                    responseType: 'stream',
                });
                await pipeline(response.data, fs.createWriteStream(filePath));
                console.log(`Download ${fileName} successfully`);
                downloadSuccess = true;
            } catch (err) {
                console.log(`Download ${fileName} failed: ${err.message}`);
            }
        } else {
            console.log(`File ${fileName} access error: ${error.message}`);
        }
    }

    return { fileName, filePath, success: downloadSuccess };
}

async function downloadFiles() {
    const architecture = getSystemArchitecture();
    const filesToDownload = getFilesForArchitecture(architecture);

    const downloadResults = await Promise.all(
        filesToDownload.map(file =>
        download_function(file.fileName, file.fileUrl)
        )
    );

    for (const { fileName, filePath, success } of downloadResults) {
        if (success) {
            try {
                fs.chmodSync(filePath, 0o755);
                console.log(`Empowerment success for ${fileName}: 755`);
            } catch (err) {
                console.warn(`Empowerment failed for ${fileName}: ${err.message}`);
            }
        }
    }
}

function argoType() {
    if (!ARGO_AUTH || !ARGO_DOMAIN) {
        console.log("ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels");
        return;
    }

    if (ARGO_AUTH.includes('TunnelSecret')) {
        fs.writeFileSync(path.join(FILE_PATH, 'tunnel.json'), ARGO_AUTH);
        const tunnelYaml = `
        tunnel: ${ARGO_AUTH.split('"')[11]}
        credentials-file: ${path.join(FILE_PATH, 'tunnel.json')}
        protocol: http2

        ingress:
        - hostname: ${ARGO_DOMAIN}
        service: http://localhost:${ECH_PORT}
        originRequest:
        noTLSVerify: true
        - service: http_status:404
        `;
        fs.writeFileSync(path.join(FILE_PATH, 'tunnel.yml'), tunnelYaml);
    } else {
        console.log("ARGO_AUTH mismatch TunnelSecret,use token connect to tunnel");
    }
}

let args;
function get_cloud_flare_args() {
    if (ARGO_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/)) {
        args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}`;
    } else if (ARGO_AUTH.match(/TunnelSecret/)) {
        args = `tunnel --edge-ip-version auto --config ${FILE_PATH}/tunnel.yml run`;
    } else {
        args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${FILE_PATH}/boot.log --loglevel info --url http://localhost:${ECH_PORT}`;
    }
    return args
}

// nezconfig
let NEZHA_TLS;
function nezconfig() {
    const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
    if (NEZHA_VERSION === 'V0') {
        if (tlsPorts.includes(NEZHA_PORT)) {
            NEZHA_TLS = '--tls';
        } else {
            NEZHA_TLS = '';
        }
        return NEZHA_TLS
    } else if (NEZHA_VERSION === 'V1') {
        if (tlsPorts.includes(NEZHA_PORT)) {
            NEZHA_TLS = 'true';
        } else {
            NEZHA_TLS = 'false';
        }
        const nezv1configPath = path.join(FILE_PATH, '/config.yml');
        const v1configData = `client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}:${NEZHA_PORT}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${NEZHA_TLS}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;
        try {
            fs.writeFileSync(nezv1configPath, v1configData);
            console.log('config.yml file created and written successfully.');
        } catch (err) {
            console.error('Error creating or writing config.yml file:', err);
        }
    }
}

// run bot
async function runbot() {
    const botFilePath = path.join(FILE_PATH, 'bot');
    try {
        fs.statSync(botFilePath);
        try {
            await execPromise(`nohup ${FILE_PATH}/bot ${args} >/dev/null 2>&1 &`);
        } catch (error) {
            console.error(`bot running error: ${error}`);
        }
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.log('bot file not found, skip running');
        } else {
            // console.error(`bot stat error: ${error}`);
        }
    }
}

// run web
async function runweb() {
    const webFilePath = path.join(FILE_PATH, 'web');
    try {
        fs.statSync(webFilePath);
        try {
            await execPromise(`nohup ${FILE_PATH}/web -l "${ECH_PROTOCOL}://0.0.0.0:${ECH_PORT}" -token "${UUID}" >/dev/null 2>&1 &`);
        } catch (error) {
            console.error(`web running error: ${error}`);
        }
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.log('web file not found, skip running');
        } else {
            // console.error(`web stat error: ${error}`);
        }
    }
}

// run npm
async function runnpm() {
    const npmFilePath = path.join(FILE_PATH, 'npm');
    try {
        fs.statSync(npmFilePath);
        try {
            if (NEZHA_VERSION === 'V0') {
                await execPromise(`nohup ${FILE_PATH}/npm -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --report-delay=4 --skip-conn --skip-procs --disable-auto-update >/dev/null 2>&1 &`);
            } else if (NEZHA_VERSION === 'V1') {
                await execPromise(`nohup ${FILE_PATH}/npm -c ${FILE_PATH}/config.yml >/dev/null 2>&1 &`);
            }
        } catch (error) {
            console.error(`npm running error: ${error}`);
        }
    } catch (statError) {
        if (statError.code === 'ENOENT') {
            console.log('npm file not found, skip running');
        } else {
            // console.error(`Error checking npm file: ${statError.message}`);
        }
    }
}

// run
async function runapp() {
    if (OPENSERVER) {
        argoType();
        get_cloud_flare_args();
        await runbot();
        await delay(5000);
        console.log('bot is running');
    } else {
        console.log('bot is not allowed, skip running');
    }

    await runweb();
    await delay(1000);
    console.log('web is running');

    if (NEZHA_VERSION && NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
        nezconfig();
        await runnpm();
        await delay(1000);
        console.log('npm is running');
    } else {
        console.log('npm variable is empty, skip running');
    }
}

async function keep_alive() {
    const webPids = await detectProcess('web');
    if (webPids) {
        // console.log("web is already running. PIDs:", webPids);
    } else {
        console.log('web runs again !');
        await runweb();
    }

    await delay(5000);

    if (OPENSERVER) {
        const botPids = await detectProcess('bot');
        if (botPids) {
            // console.log("bot is already running. PIDs:", botPids);
        } else {
            console.log('bot runs again !');
            await runbot();
        }
    }

    await delay(5000);

    if (NEZHA_VERSION && NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
        const npmPids = await detectProcess('npm');
        if (npmPids) {
            // console.log("npm is already running. PIDs:", npmPids);
        } else {
            console.log('npm runs again !');
            await runnpm();
        }
    }
}

function getArgoDomainFromLog() {
    const bootfilePath = path.join(FILE_PATH, 'boot.log');
    try {
        const stats = fs.statSync(bootfilePath);
        if (stats.size === 0) {
            return null;
        }

        const fileContent = fs.readFileSync(bootfilePath, 'utf-8');
        const regex = /info.*https:\/\/(.*trycloudflare\.com)/g;
        let match;
        let lastMatch = null;

        while ((match = regex.exec(fileContent)) !== null) {
            lastMatch = match[1];
        }
        return lastMatch;
    } catch (error) {
        if (error.code === 'ENOENT') return null;
        console.error('Error reading boot.log:', error);
        return null;
    }
}

let argoDomain;
let UPLOAD_DATA = ''
async function extractDomains() {
    let currentArgoDomain = '';
    if (OPENSERVER) {
        if (ARGO_AUTH && ARGO_DOMAIN) {
            currentArgoDomain = ARGO_DOMAIN;
            // console.log('Using configured ARGO_DOMAIN:', currentArgoDomain);
        } else {
            await delay(3000);
            currentArgoDomain = getArgoDomainFromLog();
            if (!currentArgoDomain) {
                try {
                    console.log('ArgoDomain not found, re-running bot to obtain ArgoDomain');
                    const bootfilePath = path.join(FILE_PATH, 'boot.log');
                    try {
                        fs.statSync(bootfilePath);
                        try {
                            fs.unlinkSync(bootfilePath);
                            await delay(500);
                        } catch (error) {
                            console.error(`Error deleting boot.log: ${error}`);
                        }
                    } catch (error) {
                        if (error.code !== 'ENOENT') {
                            console.error(`Error checking boot.log: ${error}`);
                        }
                    }
                    const botprocess = 'bot';
                    await killProcess(botprocess);
                    await delay(1000);
                    await runbot();
                    console.log('bot is running');
                    await delay(10000);
                    currentArgoDomain = getArgoDomainFromLog();
                    if (!currentArgoDomain) {
                        console.error('Failed to obtain ArgoDomain even after restarting bot.');
                    }
                } catch (error) {
                    console.error('Error in bot process management:', error);
                    return;
                }
            } else {
                // console.log('ArgoDomain extracted from boot.log:', currentArgoDomain);
            }
        }
    }

    if (MY_DOMAIN) {
        currentArgoDomain = MY_DOMAIN;
        // console.log('Overriding ArgoDomain with MY_DOMAIN:', currentArgoDomain);
    }
    argoDomain = currentArgoDomain;
    let ECH_SERVER;
    ECH_SERVER = `wss://${argoDomain}:8443/tunnel`;
    UPLOAD_DATA = `ech://server=${ECH_SERVER}&listen=${ECH_LISTEN}&token=${UUID}&dns=${ECH_DNS}&ech=${ECH_URL}&ip=${CFIP}&name=${SUB_NAME}`;
    // console.log('UPLOAD_DATA:', UPLOAD_DATA);
}

function generateLinks() {
    if (UPLOAD_DATA) {
        const filePath = path.join(FILE_PATH, 'log.txt');
        fs.writeFileSync(filePath, Buffer.from(UPLOAD_DATA).toString('base64'));
        // console.log(Buffer.from(UPLOAD_DATA).toString('base64'));
    }
}

async function uploadSubscription(SUB_NAME, UPLOAD_DATA, SUB_URL) {
    const payload = JSON.stringify({ URL_NAME: SUB_NAME, URL: UPLOAD_DATA });

    const postData = Buffer.from(payload, 'utf8');
    const contentLength = postData.length;
    const parsedUrl = new URL(SUB_URL);
    const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || 443,
        path: parsedUrl.pathname,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Content-Length': contentLength
        }
    };

    try {
        const responseBody = await new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                if (res.statusCode < 200 || res.statusCode >= 300) {
                    return reject(new Error(`HTTP error! status: ${res.statusCode}, response: ${res.statusMessage}`));
                }
                let responseBody = '';
                res.on('data', (chunk) => responseBody += chunk);
                res.on('end', () => resolve(responseBody));
            });
            req.on('error', (error) => reject(error));
            req.write(postData);
            req.end();
        });
        // console.log('Upload successful:', responseBody);
        return responseBody;
    } catch (error) {
        console.error(`Upload failed:`, error.message);
    }
}

function cleanfiles() {
    setTimeout(() => {
        let filesToDelete;
        if (KEEPALIVE) {
            filesToDelete = [];
        } else {
            filesToDelete = [
                `${FILE_PATH}/bot`,
                `${FILE_PATH}/web`,
                `${FILE_PATH}/npm`,
                `${FILE_PATH}/config.yml`
            ];
        }

        filesToDelete.forEach(filePath => {
            try {
                const stats = fs.statSync(filePath);

                if (stats.isDirectory()) {
                    fs.rmSync(filePath, { recursive: true });
                } else {
                    fs.unlinkSync(filePath);
                }
                // console.log(`${filePath} deleted`);
            } catch (error) {
                if (error.code !== 'ENOENT') {
                    // console.error(`Failed to delete ${filePath}: ${error}`);
                }
            }
        });

        console.clear()
        console.log('App is running');
    }, 60000);
}

let previousargoDomain = '';
async function subupload() {
    if (previousargoDomain && argoDomain === previousargoDomain) {
        // console.log('domain name has not been updated, no need to upload');
    } else {
        const response = await uploadSubscription(SUB_NAME, UPLOAD_DATA, SUB_URL);
        generateLinks();
        previousargoDomain = argoDomain;
    }
    await delay(50000);
    await extractDomains();
}

// main
async function main() {
    createFolder(FILE_PATH);
    cleanupOldFiles();
    await downloadFiles();
    await delay(5000);
    await runapp();
    await extractDomains();
    generateLinks();
    httpserver();
    cleanfiles();
    if (SUB_URL && SUB_NAME) {
        const response = await uploadSubscription(SUB_NAME, UPLOAD_DATA, SUB_URL);
        if (KEEPALIVE && OPENSERVER && !ARGO_AUTH && !ARGO_DOMAIN) {
            previousargoDomain = argoDomain;
            setInterval(subupload, intervalInseconds * 1000);
            // setInterval(subupload, 100000);  //100s
        }
    }
    if (KEEPALIVE) {
        await keep_alive();
        setInterval(keep_alive, intervalInseconds * 1000);
    }
}
main();
