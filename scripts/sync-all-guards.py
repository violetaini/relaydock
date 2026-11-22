import sqlite3, os, subprocess, base64, socket

conn = sqlite3.connect('/opt/relaydock/data/arcway.db')
c = conn.cursor()

def get_or_create_guard_secret(sid):
    c.execute('SELECT secret FROM remote_server_guard_secrets WHERE server_id = ?', (sid,))
    row = c.fetchone()
    if row and row[0]:
        return row[0]
    secret = base64.urlsafe_b64encode(os.urandom(32)).decode('ascii').rstrip('=')
    c.execute('INSERT INTO remote_server_guard_secrets (server_id, secret) VALUES (?, ?)', (sid, secret))
    conn.commit()
    return secret

servers = c.execute('SELECT id, name, ip_address, listen_port, token FROM remote_servers').fetchall()

print(f'Starting sync for {len(servers)} servers...')

for sid, name, ip, port, token in servers:
    guard_port = (port or 23889) + 1
    listen_port = port or 23889
    secret = get_or_create_guard_secret(sid)
    
    print(f'\n--- Checking Server {sid}: {name} ({ip}) ---')
    
    # Check if already healthy
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)
    already_healthy = (s.connect_ex((ip, guard_port)) == 0)
    s.close()
    
    if already_healthy:
        print(f'Server {sid} already has guard running on port {guard_port}.')
        continue
        
    print(f'Deploying guard to Server {sid}...')
    
    # 1. Detect architecture via SSH
    check_cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no', '-p', '30222', f'root@{ip}', 'uname -m']
    res = subprocess.run(check_cmd, capture_output=True, text=True, timeout=10)
    if res.returncode != 0:
        print(f'Failed to SSH to {ip}: {res.stderr.strip()}')
        continue
    arch_raw = res.stdout.strip()
    bin_name = 'arcway-expiry-guard-linux-arm64' if 'aarch64' in arch_raw or 'arm64' in arch_raw else 'arcway-expiry-guard-linux-amd64'
    src_bin = f'/opt/relaydock/bin/{bin_name}'
    
    # 2. SCP binary
    scp_cmd = ['scp', '-P', '30222', '-o', 'StrictHostKeyChecking=no', src_bin, f'root@{ip}:/usr/local/bin/arcway-expiry-guard']
    res = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=30)
    if res.returncode != 0:
        print(f'SCP failed: {res.stderr.strip()}')
        continue
        
    # 3. Configure and start
    remote_sh = f'''set -e
chmod +x /usr/local/bin/arcway-expiry-guard
mkdir -p /var/lib/arcway-expiry-guard
if [ ! -f /var/lib/arcway-expiry-guard/state.json ]; then
    echo 'eyJ2ZXJzaW9uIjoxLCJlbnRyaWVzIjpbXX0K' | base64 -d > /var/lib/arcway-expiry-guard/state.json
    chmod 0600 /var/lib/arcway-expiry-guard/state.json
fi
cat << 'EOF' > /etc/arcway-expiry-guard.env
ARCWAY_GUARD_LISTEN=:{guard_port}
ARCWAY_AGENT_URL=http://127.0.0.1:{listen_port}
ARCWAY_GUARD_STATE=/var/lib/arcway-expiry-guard/state.json
ARCWAY_GUARD_SECRET={secret}
ARCWAY_AGENT_TOKEN={token}
EOF
chmod 0600 /etc/arcway-expiry-guard.env

cat << 'EOF' > /etc/systemd/system/arcway-expiry-guard.service
[Unit]
Description=Arcway Managed Client Expiry Guard
After=network-online.target relaydock-agent.service
Wants=network-online.target
Requires=relaydock-agent.service

[Service]
Type=simple
EnvironmentFile=/etc/arcway-expiry-guard.env
ExecStart=/usr/local/bin/arcway-expiry-guard
Restart=always
RestartSec=5
WorkingDirectory=/var/lib/arcway-expiry-guard
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/arcway-expiry-guard

[Install]
WantedBy=multi-user.target
EOF

command -v chronyc >/dev/null 2>&1 && chronyc makestep || true
systemctl daemon-reload
systemctl enable --now arcway-expiry-guard
systemctl restart arcway-expiry-guard
'''
    deploy_cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no', '-p', '30222', f'root@{ip}', 'bash -s']
    res = subprocess.run(deploy_cmd, input=remote_sh, capture_output=True, text=True, timeout=20)
    if res.returncode != 0:
        print(f'Remote setup failed: {res.stderr.strip()}')
    else:
        print(f'Server {sid} guard deployed successfully! Verifying...')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        ok = (s.connect_ex((ip, guard_port)) == 0)
        s.close()
        print(f'Server {sid} port {guard_port} reachability: {ok}')

print('\nAll done!')
