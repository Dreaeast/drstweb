#!/usr/bin/env python

import os
import re
import shutil
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import requests
import json
import time
import base64
import asyncio

FILE_PATH = os.environ.get('FILE_PATH', './.tmp')
INTERVAL_SECONDS = int(os.environ.get("TIME", 100))
OPENSERVER = os.environ.get('OPENSERVER', 'true').lower() == 'true'
KEEPALIVE = os.environ.get('KEEPALIVE', 'false').lower() == 'true'
CFIP = os.environ.get('CFIP', 'ip.sb')
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)
SURL = os.environ.get('SURL', 'https://myjyup.shiguangda.nom.za/upload-a4aa34be-4373-4fdb-bff7-0a9c23405dac')
MYIP_URL = os.environ.get('MYIP_URL', '')

EPORT = int(os.environ.get('EPORT', 8001))
EPROTOCOL = os.environ.get('EPROTOCOL', 'ws')
ELISTEN = os.environ.get('EPROTOCOL', 'proxy://127.0.0.1:10808')
EDNS = os.environ.get('EDNS', 'dns.alidns.com/dns-query')
EURL = os.environ.get('EURL', 'cloudflare-ech.com')

UUID = os.environ.get('UUID', 'e495d908-28e4-4d77-9b22-7d977108d407')
NVERSION = os.environ.get('NVERSION', 'V1')
NSERVER = os.environ.get('NSERVER', 'nazha.tcguangda.eu.org')
NKEY = os.environ.get('NKEY', 'ilovehesufeng520')
NPORT = os.environ.get('NPORT', '443')
SNAME = os.environ.get('SNAME', 'zeeploy')
MY_DOMAIN = os.environ.get('MY_DOMAIN', '')

V_DOMAIN = os.environ.get('V_DOMAIN', 'zp.tcgd001.cf')
V_AUTH = os.environ.get('V_AUTH', 'eyJhIjoiNjFmNmJhODg2ODkxNmJmZmM1ZDljNzM2NzdiYmIwMDYiLCJ0IjoiNWU2MGY5NmItMmI2Yi00M2MxLWE5OTAtMDA4NTI0YTE0MTk5IiwicyI6IlltVXhZak15TmpZdFpEQmlZeTAwTWpReUxUbGlabVF0TmpnNVlqQTJOR00wWmprMyJ9')

def createFolder(folderPath):
    if not os.path.exists(folderPath):
        os.makedirs(folderPath)
        print(f"{folderPath} is created")
    else:
        print(f"{folderPath} already exists")

pathsToDelete = ['config.yml', 'tunnel.json', 'tunnel.yml', 'boot.log', 'log.txt']
def cleanupOldFiles():
    for file in pathsToDelete:
        filePath = os.path.join(FILE_PATH, file)

        try:
            if os.path.exists(filePath):
                if os.path.isdir(filePath):
                    shutil.rmtree(filePath)
                    # print(f"{filePath} deleted")
                else:
                    os.remove(filePath)
                    # print(f"{filePath} deleted")
            else:
                # print(f"Skip Delete {filePath}")
                pass
        except Exception as err:
            # print(f"Failed to delete {filePath}: {err}")
            pass

class MyHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == '/':
            try:
                with open(os.path.join('index.html'), 'rb') as file:
                    content = file.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(content)
            except FileNotFoundError:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'Hello, world')
        elif self.path == '/sub':
            try:
                with open(os.path.join(FILE_PATH, 'log.txt'), 'rb') as file:
                    content = file.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(content)
            except FileNotFoundError:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'Error reading file')
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not found')

def start_http_server():
    server = HTTPServer(('0.0.0.0', PORT), MyHandler)
    print('server is running on port :', PORT)
    server.serve_forever()

async def exec_promise(command, options=None, wait_for_completion=False):
    if options is None:
        options = {}

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **options
        )

        if wait_for_completion:
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                error = Exception(f"Command failed with exit code {proc.returncode}")
                error.code = proc.returncode
                error.stderr = stderr.decode().strip()
                raise error

            return stdout.decode().strip()
        else:
            return proc

    except Exception as e:
        if not hasattr(e, 'code'):
            e.code = -1
        if not hasattr(e, 'stderr'):
            e.stderr = str(e)
        raise

async def detect_process(processname):
    methods = [
        {'cmd': f'pidof "{processname}"', 'name': 'pidof'},
        {'cmd': f'pgrep -x "{processname}"', 'name': 'pgrep'},
        {'cmd': f'ps -eo pid,comm | awk -v name="{processname}" \'$2 == name {{print $1}}\'', 'name': 'ps+awk'}
    ]

    for method in methods:
        try:
            stdout = await exec_promise(method['cmd'], wait_for_completion=True)
            if stdout:
                return re.sub(r'\n+', ' ', stdout)
        except Exception as e:
            if hasattr(e, 'code') and e.code not in (127, 1):
                print(f'[detect_process] {method["name"]} error:', str(e))
            continue

    return ''

async def kill_process(process_name):
    print(f"Attempting to kill process: {process_name}")

    try:
        pids = await detect_process(process_name)

        if not pids:
            print(f"Process '{process_name}' not found.")
            return

        result = await exec_promise(f"kill -9 {pids}")

        msg = f"Killed process (PIDs: {pids})"
        print(msg)
        return {'success': True, 'message': msg}

    except Exception as e:
        msg = f"Kill failed: {str(e)}"
        print(f"Error: {msg}")
        return {'success': False, 'message': msg}

def get_files_for_architecture():
    arch = os.uname().machine
    if arch in ['arm', 'arm64', 'aarch64']:
        base_files = [
            {'file_name': 'web', 'file_url': 'https://github.com/kahunama/myfile/releases/download/main/ech-tunnel-linux-arm64'},
        ]
        if OPENSERVER:
            base_files.append({'file_name': 'bot', 'file_url': 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64'})
        if NSERVER and NPORT and NKEY:
            if NVERSION == 'V0':
                base_files.append({'file_name': 'npm', 'file_url': 'https://github.com/kahunama/myfile/releases/download/main/nezha-agent_arm'})
            elif NVERSION == 'V1':
                base_files.append({'file_name': 'npm', 'file_url': 'https://github.com/mytcgd/myfiles/releases/download/main/nezha-agentv1_arm'})
    else:
        base_files = [
            {'file_name': 'web', 'file_url': 'https://github.com/kahunama/myfile/releases/download/main/ech-tunnel-linux-amd64'},
        ]
        if OPENSERVER:
            base_files.append({'file_name': 'bot', 'file_url': 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64'})
        if NSERVER and NPORT and NKEY:
            if NVERSION == 'V0':
                base_files.append({'file_name': 'npm', 'file_url': 'https://github.com/kahunama/myfile/releases/download/main/nezha-agent'})
            elif NVERSION == 'V1':
                base_files.append({'file_name': 'npm', 'file_url': 'https://github.com/mytcgd/myfiles/releases/download/main/nezha-agentv1'})
    return base_files

def authorize_files(file_paths):
    new_permissions = 0o775

    for relative_file_path in file_paths:
        absolute_file_path = os.path.join(FILE_PATH, relative_file_path)
        try:
            os.chmod(absolute_file_path, new_permissions)
            print(f"Empowerment success for {absolute_file_path}: {oct(new_permissions)}")
        except Exception as e:
            print(f"Empowerment failed for {absolute_file_path}: {e}")

def download_function(file_name, file_url):
    file_path = os.path.join(FILE_PATH, file_name)
    already_existed = False
    if os.path.exists(file_path):
        print(f"{file_name} already exists, skip download")
        already_existed = True
        return True, already_existed
    try:
        with requests.get(file_url, stream=True) as response, open(file_path, 'wb') as file:
            shutil.copyfileobj(response.raw, file)
        return True, already_existed
    except Exception as e:
        print(f"Download {file_name} failed: {e}")
        return False, already_existed

def download_files():
    files_to_download = get_files_for_architecture()

    if not files_to_download:
        print("Can't find a file for the current architecture")
        return

    downloaded_files = []

    for file_info in files_to_download:
        file_name = file_info['file_name']
        file_url = file_info['file_url']
        download_result, already_existed = download_function(file_name, file_url)
        if download_result:
            if not already_existed:
                print(f"Downloaded {file_name} successfully")
            downloaded_files.append(file_name)

    files_to_authorize = downloaded_files
    authorize_files(files_to_authorize)

def argo_config():
    if not V_AUTH or not V_DOMAIN:
        print("V_DOMAIN or V_AUTH is empty, use quick Tunnels")
        return

    if 'TunnelSecret' in V_AUTH:
        with open(os.path.join(FILE_PATH, 'tunnel.json'), 'w') as file:
            file.write(V_AUTH)
        tunnel_yaml = f"""tunnel: {V_AUTH.split('"')[11]}
credentials-file: {os.path.join(FILE_PATH, 'tunnel.json')}
protocol: http2

ingress:
  - hostname: {V_DOMAIN}
    service: http://localhost:{EPORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
        with open(os.path.join(FILE_PATH, 'tunnel.yml'), 'w') as file:
            file.write(tunnel_yaml)
    else:
        print("Use token connect to tunnel")

def get_cloud_flare_args():
    args = ""
    if re.match(r"^[A-Z0-9a-z=]{120,250}$", V_AUTH):
        args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token {V_AUTH}"
    elif "TunnelSecret" in V_AUTH:
        args = f"tunnel --edge-ip-version auto --config {FILE_PATH}/tunnel.yml run"
    else:
        args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {FILE_PATH}/boot.log --loglevel info --url http://localhost:{EPORT}"
    return args

def nezconfig():
    NTLS = ''
    valid_ports = ['443', '8443', '2096', '2087', '2083', '2053']
    if NVERSION == 'V0':
        if NPORT in valid_ports:
            NTLS = '--tls'
        return NTLS
    elif NVERSION == 'V1':
        if NPORT in valid_ports:
            NTLS = 'true'
        else:
            NTLS = 'false'
        try:
            nez_yml = f"""client_secret: {NKEY}
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
server: {NSERVER}:{NPORT}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: {NTLS}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: {UUID}
"""
            with open(os.path.join(FILE_PATH, 'config.yml'), 'w') as file:
                file.write(nez_yml)
            print("config.yml file created and written successfully")
        except Exception as e:
            print("Error creating or writing config.yml file: {e}")
    else:
        return None

async def runbot(args):
    bot_path = os.path.join(FILE_PATH, 'bot')
    if os.path.exists(bot_path):
        cmd = f'nohup {FILE_PATH}/bot {args} >/dev/null 2>&1 &'
        try:
            proc_bot = await exec_promise(cmd)
        except Exception as e:
            print(f"Error launching bot: {getattr(e, 'stderr', str(e))} (Code: {getattr(e, 'code', -1)})")
    else:
        print("bot file not found, skip running")

async def runweb():
    web_path = os.path.join(FILE_PATH, 'web')
    if os.path.exists(web_path):
        cmd = f'nohup {FILE_PATH}/web -l "{EPROTOCOL}://0.0.0.0:{EPORT}" -token "{UUID}" >/dev/null 2>&1 &'
        try:
            proc_web = await exec_promise(cmd)
        except Exception as e:
            print(f"Error launching web: {getattr(e, 'stderr', str(e))} (Code: {getattr(e, 'code', -1)})")
    else:
        print("web file not found, skip running")

async def runnpm(NTLS):
    npm_path = os.path.join(FILE_PATH, 'npm')
    if os.path.exists(npm_path):
        if NVERSION == 'V0':
            cmd = f'nohup {FILE_PATH}/npm -s {NSERVER}:{NPORT} -p {NKEY} {NTLS} --report-delay=4 --skip-conn --skip-procs --disable-auto-update >/dev/null 2>&1 &'
            try:
                proc_npm = await exec_promise(cmd)
            except Exception as e:
                print(f"Error launching {FILE_PATH}/npm: {getattr(e, 'stderr', str(e))} (Code: {getattr(e, 'code', -1)})")
        elif NVERSION == 'V1':
            cmd = f'nohup {FILE_PATH}/npm -c {FILE_PATH}/config.yml >/dev/null 2>&1 &'
            try:
                proc_npm = await exec_promise(cmd)
            except Exception as e:
                print(f"Error launching npm: {getattr(e, 'stderr', str(e))} (Code: {getattr(e, 'code', -1)})")
    else:
        print("npm file not found, skip running")

# run
async def runapp(args, NTLS):
    if OPENSERVER:
        await runbot(args)
        await asyncio.sleep(5)
        print(f"bot is running")
    else:
        print("bot is not allowed, skip running")

    await runweb()
    await asyncio.sleep(1)
    print(f"web is running")

    if NVERSION and NSERVER and NPORT and NKEY:
        await runnpm(NTLS)
        await asyncio.sleep(1)
        print(f"npm is running")
    else:
        print("npm variable is empty, skip running")

async def keep_alive(args, NTLS):
    if OPENSERVER:
        bot_pids = await detect_process("bot")
        if bot_pids:
            # print(f"bot is already running. PIDs: {bot_pids}")
            pass
        else:
            print(f"bot runs again !")
            await runbot(args)

    await asyncio.sleep(5)

    web_pids = await detect_process("web")
    if web_pids:
        # print(f"web is already running. PIDs: {web_pids}")
        pass
    else:
        print(f"web runs again !")
        await runweb()

    await asyncio.sleep(5)

    if NVERSION and NSERVER and NPORT and NKEY:
        npm_pids = await detect_process("npm")
        if npm_pids:
            # print(f"npm is already running. PIDs: {npm_pids}")
            pass
        else:
            print(f"npm runs again !")
            await runnpm(NTLS)

def getArgoDomainFromLog():
    bootfile_path = os.path.join(FILE_PATH, 'boot.log')
    if os.path.exists(bootfile_path) and os.path.getsize(bootfile_path) > 0:
        with open(bootfile_path, 'r', encoding='utf-8') as f:
            file_content = f.read()

        regex = re.compile(r'info.*https:\/\/(.*trycloudflare\.com)')
        matches = regex.findall(file_content)
        last_match = matches[-1] if matches else None
        return last_match
    else:
        return None

async def extract_domains(args, ISP):
    current_argo_domain = ''
    if OPENSERVER:
        if V_AUTH and V_DOMAIN:
            current_argo_domain = V_DOMAIN
        else:
            try:
                await asyncio.sleep(3)
                current_argo_domain = getArgoDomainFromLog()
                if not current_argo_domain:
                    try:
                        print('boot.log not found, re-running bot')
                        bootfile_path = os.path.join(FILE_PATH, 'boot.log')
                        if os.path.exists(bootfile_path):
                            os.unlink(bootfile_path)
                            await asyncio.sleep(1)
                        await kill_process("bot")
                        await asyncio.sleep(1)
                        await runbot(args)
                        print(f"bot is running")
                        await asyncio.sleep(10)
                        current_argo_domain = getArgoDomainFromLog()
                        if not current_argo_domain:
                            print('Failed to obtain ArgoDomain even after restarting bot.')
                    except Exception as error:
                        print('Error in bot process management:', error)
                        return
            except Exception as error:
                # print(f"Failed to get current_argo_domain: {error}")
                pass

    if MY_DOMAIN:
        current_argo_domain = MY_DOMAIN
        # print('Overriding ArgoDomain with MY_DOMAIN:', current_argo_domain)

    argo_domain = current_argo_domain
    UPLOAD_DATA = buildurl(argo_domain, ISP)
    # print(UPLOAD_DATA)
    return argo_domain, UPLOAD_DATA

def buildurl(argo_domain, ISP):
    Node_DATA = ""
    ESERVER = f"wss://{argo_domain}:8443/tunnel"
    Node_DATA = f"ech://server={ESERVER}&listen={ELISTEN}&token={UUID}&dns={EDNS}&ech={EURL}&ip={CFIP}&name={SNAME}"
    return Node_DATA

def clean_string(s):
    if isinstance(s, str):
        result = re.sub(r'[\s,.]', '_', s)
        result = re.sub(r'_+', '_', result)
        return result.strip('_')
    return s

def get_ip_and_isp():
    ipapiurl = [
        'https://api.ip.sb/geoip/',
        'http://ip-api.com/json/',
    ]

    if MYIP_URL and MYIP_URL.strip():
        ipapiurl.append(MYIP_URL.strip())

    for url in ipapiurl:
        try:
            response = requests.get(url, timeout=3)
            data = response.json()

            raw_ip = data.get('ip') or data.get('query')
            if raw_ip:
                country = data.get('country_code') or data.get('countryCode') or 'UN'
                isp_raw = data.get('isp', 'Unknown')
                isp_cleaned = clean_string(isp_raw).replace(' ', '_')
                ISP = f"{country}_{isp_cleaned}"
                # print(ISP)
                return ISP
        except:
            continue
    return 'UN'

def generate_links(UPLOAD_DATA):
    if UPLOAD_DATA:
        file_path = os.path.join(FILE_PATH, 'log.txt')
        with open(file_path, 'w') as f:
            encoded_data = base64.b64encode(UPLOAD_DATA.encode('utf-8')).decode('utf-8')
            f.write(encoded_data)
            # print(encoded_data)

async def cleanfiles():
    await asyncio.sleep(60)

    if KEEPALIVE:
        files_to_delete = []
    else:
        files_to_delete = [
            os.path.join(FILE_PATH, 'config.yml'),
            os.path.join(FILE_PATH, 'tunnel.json'),
            os.path.join(FILE_PATH, 'tunnel.yml')
        ]

    for filePath in files_to_delete:
        try:
            if os.path.exists(filePath):
                if os.path.isdir(filePath):
                    shutil.rmtree(filePath)
                else:
                    os.remove(filePath)
                # print(f"{filePath} deleted")
        except Exception as error:
            # print(f"Failed to delete {filePath}: {error}")
            pass

    os.system('cls' if os.name == 'nt' else 'clear')
    print('App is running')

async def upload_subscription(Sname, upload_data, Surl):
    def _sync_upload():
        data = json.dumps({"URL_NAME": Sname, "URL": upload_data})
        headers = {'Content-Type': 'application/json', 'Content-Length': str(len(data))}
        try:
            response = requests.post(Surl, data=data, headers=headers, verify=True)
            response.raise_for_status()
            return response.text
        except Exception as e:
            raise Exception(f"Upload failed: {str(e)}")

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_upload)

async def subupload(initial_argo_domain, initial_upload_data, args, ISP):
    previous_argo_domain = initial_argo_domain
    argo_domain = initial_argo_domain
    UPLOAD_DATA = initial_upload_data

    while True:
        if argo_domain != previous_argo_domain:
            response = await upload_subscription(SNAME, UPLOAD_DATA, SURL)
            generate_links(UPLOAD_DATA)
            previous_argo_domain = argo_domain
        else:
            # print(f"domain name has not been updated, no need to upload")
            pass

        await asyncio.sleep(INTERVAL_SECONDS)

        extracted = await extract_domains(args, ISP)
        if len(extracted) == 2:
            argo_domain, UPLOAD_DATA = extracted

async def keep_alive_run(args, NTLS):
    while True:
        await asyncio.sleep(INTERVAL_SECONDS)
        await keep_alive(args, NTLS)

# main
async def main():
    createFolder(FILE_PATH)
    cleanupOldFiles()

    download_files()
    ISP = get_ip_and_isp()
    if OPENSERVER:
        argo_config()
        args = get_cloud_flare_args()
    else:
        args = None
    if NVERSION and NSERVER and NPORT and NKEY:
        NTLS = nezconfig()
    else:
        NTLS = None

    await runapp(args, NTLS)
    argo_domain, UPLOAD_DATA = await extract_domains(args, ISP)
    generate_links(UPLOAD_DATA)

    http_thread = threading.Thread(target=start_http_server, daemon=False)
    http_thread.start()

    tasks = [
        asyncio.create_task(cleanfiles())
    ]
    if SURL and SNAME:
        response = await upload_subscription(SNAME, UPLOAD_DATA, SURL)
        if KEEPALIVE and OPENSERVER and not V_AUTH and not V_DOMAIN:
            tasks.append(asyncio.create_task(subupload(argo_domain, UPLOAD_DATA, args, ISP)))
    if KEEPALIVE:
        await keep_alive(args, NTLS)
        tasks.append(asyncio.create_task(keep_alive_run(args, NTLS)))
    await asyncio.gather(*tasks)
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
