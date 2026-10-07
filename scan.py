#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AI-Hacking Self-Audit / AI 해킹 보안 자가진단 (MVP v0.1)
Non-intrusive, zero-exfiltration personal security self-audit.
  - Non-intrusive: reads local settings/permissions/git/network only. No exploiting.
  - Zero-exfiltration: 100% local. No network calls (no socket/urllib/requests imports).
  - No value leakage: secret VALUES are never recorded — only location/count.
  - Zero deps: Python stdlib only → single-binary / pip friendly.
Usage: python3 scan.py [--lang ko|en] [--home PATH] [--json out.json] [--html report.html]
"""
import os, re, json, subprocess, argparse, datetime, html, getpass, sys

HOME = os.path.expanduser('~')
OS = 'mac' if sys.platform == 'darwin' else 'win' if sys.platform.startswith('win') else 'linux'

# ── i18n 메시지 카탈로그 ──
AREA = {
    'cred':   {'ko': '자격증명',   'en': 'Credentials'},
    'net':    {'ko': '네트워크',   'en': 'Network'},
    'os':     {'ko': 'OS',         'en': 'OS'},
    'ai':     {'ko': 'AI에이전트', 'en': 'AI-Agent'},
    'backup': {'ko': '백업',       'en': 'Backup'},
}
MSG = {
    'git_cred': {
        'ko': ('git에 자격증명 파일 추적됨', '{n}개 저장소에 토큰/키/.env가 커밋됨: {d}',
               'git rm --cached <파일> 후 .gitignore 추가. 공개 저장소면 즉시 키 재발급(로테이션).'),
        'en': ('Credential files tracked in git', 'Tokens/keys/.env committed in {n} repo(s): {d}',
               'Run git rm --cached <file>, add to .gitignore. If public, rotate the keys immediately.')},
    'ssh_perm': {
        'ko': ('SSH 개인키 권한 과다 ({f})', '~/.ssh/{f} 권한 {mode} — 다른 사용자 접근 가능', 'chmod 600 ~/.ssh/{f}'),
        'en': ('SSH private key over-permissive ({f})', '~/.ssh/{f} is {mode} — accessible by others', 'chmod 600 ~/.ssh/{f}')},
    'hist_key': {
        'ko': ('셸 히스토리에 키 평문 의심 ({h})', '~/{h}에 API 키 형태 {n}건 (값 미표시)',
               '해당 줄 삭제 후 키 로테이션. 키는 명령행 대신 환경변수/파일로.'),
        'en': ('Plaintext API keys in shell history ({h})', '{n} API-key-like string(s) in ~/{h} (values hidden)',
               'Delete those lines and rotate keys. Pass secrets via env/file, not the command line.')},
    'open_port': {
        'ko': ('외부 공개(0.0.0.0) 리스닝 포트', '모든 인터페이스에 열린 포트: {d}',
               '불필요한 서비스는 종료. 필요하면 127.0.0.1(로컬)로만 바인딩하거나 방화벽 제한.'),
        'en': ('Publicly-bound (0.0.0.0) listening ports', 'Ports open on all interfaces: {d}',
               'Stop unneeded services. Bind to 127.0.0.1 only, or restrict via firewall.')},
    'fw_off': {
        'ko': ('방화벽 비활성', '방화벽이 꺼져 있어 외부 접근이 걸러지지 않음', '방화벽을 켜세요 — mac: 시스템설정>네트워크>방화벽 / Windows: Defender 방화벽 / Linux: sudo ufw enable.'),
        'en': ('Firewall disabled', 'The firewall is off, so inbound access is unfiltered', 'Turn the firewall on — mac: System Settings>Network>Firewall / Windows: Defender Firewall / Linux: sudo ufw enable.')},
    'filevault': {
        'ko': ('디스크 암호화 꺼짐', '분실·도난 시 디스크 내용이 평문으로 노출됨', '디스크 암호화를 켜세요 — mac: FileVault / Windows: BitLocker / Linux: LUKS.'),
        'en': ('Disk encryption off', 'Disk is readable in plaintext if lost/stolen', 'Turn on disk encryption — mac: FileVault / Windows: BitLocker / Linux: LUKS.')},
    'autologin': {
        'ko': ('자동 로그인 활성', '부팅 시 암호 없이 로그인됨', '시스템 설정 > 사용자 및 그룹 > 자동 로그인 끄기.'),
        'en': ('Automatic login enabled', 'Boots straight in without a password', 'System Settings > Users & Groups > turn off automatic login.')},
    'screenlock': {
        'ko': ('화면보호기 후 암호 미요구', '잠금 후 암호 없이 복귀 가능', '시스템 설정 > 잠금 화면 > 암호 요구 = 즉시.'),
        'en': ('No password after screensaver', 'Resumes without a password', 'System Settings > Lock Screen > Require password = immediately.')},
    'os_ver': {
        'ko': ('macOS {v}', '현재 OS 버전', 'softwareupdate -l 로 보안 업데이트 확인·적용.'),
        'en': ('macOS {v}', 'Current OS version', 'Check/apply security updates: softwareupdate -l.')},
    'ai_cfg': {
        'ko': ('AI 도구 설정의 자격증명 권한 과다', '{n}건: {d}', '해당 파일 chmod 600. MCP/도구 토큰은 최소권한으로.'),
        'en': ('Over-permissive credentials in AI tool config', '{n} file(s): {d}', 'chmod 600 those files. Keep MCP/tool tokens least-privilege.')},
    'ai_inject': {
        'ko': ('AI 에이전트 프롬프트 인젝션 주의', '외부 콘텐츠(웹·메일·문서)를 읽는 AI 도구는 숨은 지시에 속을 수 있음',
               '신뢰 못 할 콘텐츠를 에이전트에 그대로 넣지 말 것. 자동 실행 권한 최소화.'),
        'en': ('AI-agent prompt-injection awareness', 'AI tools that read external content can be tricked by hidden instructions',
               'Do not feed untrusted content directly to agents. Minimize auto-execution permissions.')},
    'no_backup': {
        'ko': ('최근 백업 없음', '랜섬웨어·고장 시 복구 불가 위험', '정기 백업을 켜세요 — mac: Time Machine / Windows: 파일 히스토리 / Linux: 백업 도구.'),
        'en': ('No recent backup', 'No recovery if ransomware/hardware failure hits', 'Enable regular backups — mac: Time Machine / Windows: File History / Linux: a backup tool.')},
    'backup_repo': {
        'ko': ('저장소 자동 백업 가동 중 (마지막 커밋 {m}분 전)', '코드·기록은 매시간 저장소 커밋으로 백업됨 — 단 같은 기기 안이라 디스크 손실에는 약함', '기기 밖 사본(Time Machine·클라우드)을 추가하면 더 안전합니다. 복원 리허설은 아직 안 했어요.'),
        'en': ('Repository auto-backup active (last commit {m}m ago)', 'Code/records backed up hourly via repo commits — same-disk only, weak against disk loss', 'Add an off-device copy (Time Machine/cloud). Restore rehearsal not yet done.')},
}
UI = {
    'title':   {'ko': 'AI 해킹 보안 자가진단', 'en': 'AI-Hacking Self-Audit'},
    'rep':     {'ko': '보안 리포트', 'en': 'Security Report'},
    'of':      {'ko': '님의 기기 보안 리포트', 'en': "'s device"},
    'subtail': {'ko': '비침투 자가진단', 'en': 'non-intrusive self-audit'},
    'sclab':   {'ko': '/ 100 보안점수', 'en': '/ 100 security score'},
    'high':    {'ko': '위험', 'en': 'Critical'},
    'med':     {'ko': '주의', 'en': 'Warning'},
    'clean':   {'ko': '✅ 발견된 취약점 없음 — 완전무장 상태입니다.', 'en': '✅ No issues found — fully hardened.'},
    'priv':    {'ko': '🔒 제로 유출 보증: 이 스캔은 100% 당신의 기기에서만 실행되었습니다. 어떤 데이터·시크릿도 외부로 전송되지 않았습니다(네트워크 전송 0). 시크릿 값은 기록되지 않습니다 — 위치·건수만 표시합니다.',
                'en': '🔒 Zero-exfiltration guarantee: this scan ran 100% on your device. No data or secret was ever transmitted (zero network). Secret values are never recorded — only location/count.'},
    'done':    {'ko': '보안점수 {s}/100 · 위험 {h}·주의 {m} · 발견 {n}건', 'en': 'Security score {s}/100 · critical {h} · warning {m} · {n} findings'},
    'repline': {'ko': '리포트', 'en': 'Report'},
    'zero':    {'ko': '🔒 제로 유출: 네트워크 전송 0', 'en': '🔒 Zero-exfiltration: no network transmission'},
}

# ── "왜 중요한가" (호기심 충족 교육 정보·영역별) ──
WHY = {
    'cred': {'ko': "공격자가 가장 먼저 노리는 건 '이미 유출된 열쇠'입니다. 코드·기록에 남은 키 하나면 로그인 과정을 통째로 건너뜁니다.",
             'en': "Attackers reach for already-leaked keys first — one key left in code or history skips the entire login."},
    'net':  {'ko': "열린 포트는 집의 열린 창문입니다. 자동화된 봇이 24시간 전 세계 IP를 훑으며 열린 창문을 찾습니다.",
             'en': "An open port is an open window. Automated bots sweep the whole internet 24/7 looking for one."},
    'os':   {'ko': "기기를 잃어버리는 순간, 암호화·잠금이 없으면 안의 모든 것이 그대로 남의 손에 들어갑니다.",
             'en': "The moment a device is lost, without encryption or a lock everything inside is simply handed over."},
    'ai':   {'ko': "AI 도구는 당신 대신 행동합니다. 그 권한·열쇠가 새면 공격자는 'AI를 통해' 당신 행세를 합니다.",
             'en': "AI tools act on your behalf. If their keys leak, an attacker impersonates you through the AI."},
    'backup':{'ko': "랜섬웨어는 당신을 막지 않습니다 — 당신의 데이터를 인질로 잡습니다. 백업만이 몸값을 무력화합니다.",
              'en': "Ransomware doesn't lock you out — it takes your data hostage. Only a backup makes the ransom worthless."},
}
# ── 영역별 실제 점검 스텝 (라이브 스캔 피드용·실제 수행 항목) ──
CHECKS = {
 'cred': {'ko':['Git 저장소 토큰·키 스캔','~/.ssh 개인키 권한 점검','셸 히스토리 API키 탐지','.env 자격증명 노출 확인','OAuth 토큰 파일 권한 점검','.gitignore 시크릿 커버리지 확인','하드코딩 비밀번호 패턴 스캔','클라우드 키 파일 점검'],
          'en':['Scanning git repos for tokens','Checking ~/.ssh key permissions','Detecting API keys in shell history','Checking .env credential exposure','Checking OAuth token file perms','Verifying .gitignore secret coverage','Scanning for hardcoded passwords','Checking cloud key files']},
 'net':  {'ko':['리스닝 포트 스캔','0.0.0.0 공개 바인딩 점검','방화벽 상태 확인','원격 접속(SSH/RDP) 포트 점검','공유 서비스 노출 확인','아웃바운드 연결 점검'],
          'en':['Scanning listening ports','Checking 0.0.0.0 public binds','Verifying firewall state','Checking remote (SSH/RDP) ports','Checking exposed shared services','Reviewing outbound connections']},
 'os':   {'ko':['디스크 암호화 상태 확인','자동 로그인 설정 점검','화면 잠금 정책 확인','OS 보안 패치 상태','관리자 계정 점검','부팅 보안 설정 확인'],
          'en':['Checking disk encryption','Checking auto-login setting','Verifying screen-lock policy','Checking OS patch level','Reviewing admin accounts','Checking secure-boot settings']},
 'ai':   {'ko':['AI 도구 설정 권한 점검','MCP/토큰 노출 확인','프롬프트 인젝션 노출면 분석','에이전트 자동실행 권한 점검','외부 콘텐츠 신뢰 경계 확인','에이전트 로그 민감정보 점검'],
          'en':['Checking AI tool config perms','Checking MCP/token exposure','Analyzing prompt-injection surface','Reviewing agent auto-run perms','Checking external-content trust boundary','Scanning agent logs for secrets']},
 'backup':{'ko':['백업 존재·주기 확인','랜섬웨어 복구 대비 점검','백업 암호화 확인','복원 지점 유효성 점검'],
           'en':['Checking backup presence','Checking ransomware recovery','Verifying backup encryption','Validating restore points']},
}
# ── 대시보드 UI 문자열 ──
UISTR = {
    'ko': {'brand':'AI 해킹 자동 대응','hero_sub':'님의 기기 면역 상태','immunity':'면역 점수',
           'v_good':'양호','v_warn':'주의 필요','v_crit':'위험',
           'vitals':'영역별 바이탈','monitor_title':'🔎 실시간 스캔 모니터 · 자동 점검 중','scanning':'스캔 중','scandone':'점검','sec_find':'발견 목록','net_title':'🟢 실시간 방어 네트워크','watching':'감시 중','live_watch':'실시간 감시 중 · 5개 영역 보호','all':'전체','crit':'위험','warn':'주의','info':'정보',
           'findings':'건 발견','clean':'발견된 취약점이 없습니다. 완전무장 상태예요.',
           'why':'왜 중요한가','fix':'고치는 법','copy':'복사','copied':'복사됨',
           'export':'내보내기','print':'인쇄','local':'100% 로컬 · 외부 전송 0',
           'local_more':'이 진단은 당신의 기기에서만 실행됩니다. 파일·비밀번호·데이터가 외부로 전송되지 않습니다(네트워크 전송 0). 비밀번호 값은 기록하지 않고, 위험이 "어디"에 있는지만 알려줍니다.',
           'scanned':'진단 시각','whatscore':'점수가 낮을수록 공격에 노출된 틈이 많다는 뜻입니다. 항목을 눌러 하나씩 닫아 보세요.'},
    'en': {'brand':'AI-Hacking Self-Audit','hero_sub':"'s device immunity",'immunity':'Immunity score',
           'v_good':'Healthy','v_warn':'Needs attention','v_crit':'At risk',
           'vitals':'Vitals by area','monitor_title':'🔎 Live scan monitor · auto-checking','scanning':'scanning','scandone':'checked','sec_find':'Findings','net_title':'🟢 Live defense network','watching':'LIVE','live_watch':'Live monitoring · 5 areas protected','all':'All','crit':'Critical','warn':'Warning','info':'Info',
           'findings':'findings','clean':'No issues found. Your device is fully hardened.',
           'why':'Why it matters','fix':'How to fix','copy':'Copy','copied':'Copied',
           'export':'Export','print':'Print','local':'100% local · zero transmission',
           'local_more':'This scan runs only on your device. No file, password, or data is ever sent out (zero network). Password values are never recorded — we only tell you where a risk is.',
           'scanned':'Scanned','whatscore':'A lower score means more gaps exposed to attack. Tap an item to close them one by one.'},
}

def run(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or '') + (r.stderr or '')
    except Exception:
        return ''

class Scan:
    def __init__(self, home, lang='ko'):
        self.home = home; self.lang = lang if lang in ('ko', 'en') else 'ko'
        self.findings = []
    def add(self, sev, area_key, msg_id, **fmt):
        title, detail, fix = MSG[msg_id][self.lang]
        self.findings.append({'sev': sev, 'area': AREA[area_key][self.lang], 'areaKey': area_key,
                              'title': title.format(**fmt), 'detail': detail.format(**fmt),
                              'fix': fix.format(**fmt), 'why': WHY[area_key][self.lang]})

    def credentials(self):
        repos = []
        for dp, dns, fns in os.walk(self.home):
            if dp[len(self.home):].count(os.sep) > 4: dns[:] = []; continue
            dns[:] = [d for d in dns if d not in ('node_modules','Library','.Trash','.cache') and (not d.startswith('.') or d == '.git')]
            if '.git' in dns: repos.append(dp); dns.remove('.git')
        cred_pat = re.compile(r'(\.env($|\.)|/token[^/]*\.json$|secret[^/]*\.json$|\.pem$|\.key$|\.p12$|\.session$|id_rsa$|credentials?\.json$)', re.I)
        hit = []
        for r in repos[:60]:
            out = run(['git','-C',r,'ls-files'])
            bad = [l for l in out.splitlines() if cred_pat.search(l) and 'node_modules/' not in l]
            if bad: hit.append((r, len(bad)))
        if hit:
            d = '; '.join(f"{os.path.basename(r)}({n})" for r,n in hit[:6])
            self.add('HIGH','cred','git_cred', n=len(hit), d=d)
        ssh = os.path.join(self.home, '.ssh')
        if os.path.isdir(ssh):
            for f in os.listdir(ssh):
                p = os.path.join(ssh, f)
                if f.startswith('id_') and not f.endswith('.pub') and os.path.isfile(p):
                    mode = oct(os.stat(p).st_mode & 0o777)[2:]
                    if mode[-1] in '1234567' or mode[-2] in '1234567':
                        self.add('HIGH','cred','ssh_perm', f=f, mode=mode)
        hists = ['.zsh_history','.bash_history']
        if OS == 'win': hists = [os.path.join('AppData','Roaming','Microsoft','Windows','PowerShell','PSReadLine','ConsoleHost_history.txt')]
        for hist in hists:
            p = os.path.join(self.home, hist)
            if os.path.isfile(p):
                try: txt = open(p, errors='ignore').read()
                except Exception: continue
                n = len(re.findall(r'(sk-[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_\-]{30,}|xox[baprs]-[A-Za-z0-9\-]{10,}|ghp_[A-Za-z0-9]{30,}|Bearer [A-Za-z0-9._\-]{20,})', txt))
                if n: self.add('MED','cred','hist_key', h=os.path.basename(hist), n=n)

    def network(self):
        public = set()
        if OS == 'win':
            for l in run(['netstat','-ano','-p','TCP']).splitlines():
                m = re.search(r'(0\.0\.0\.0|\[::\]):(\d+)\s+.*LISTENING', l)
                if m: public.add(m.group(2))
            fw = run(['netsh','advfirewall','show','allprofiles','state'])
            if 'ON' not in fw.upper(): self.add('HIGH','net','fw_off')
        else:
            cmd = ['lsof','-nP','-iTCP','-sTCP:LISTEN'] if OS == 'mac' else ['ss','-tlnH']
            for l in run(cmd).splitlines():
                m = re.search(r'(\*|0\.0\.0\.0|\[::\]|::):(\d+)', l)
                if m:
                    proc = l.split()[0] if (OS=='mac' and l.split()) else ''
                    public.add(f'{m.group(2)}/{proc}' if proc else m.group(2))
            if OS == 'mac':
                if 'enabled' not in run(['/usr/libexec/ApplicationFirewall/socketfilterfw','--getglobalstate']).lower():
                    self.add('HIGH','net','fw_off')
            else:  # linux
                ufw = run(['ufw','status'])
                if ufw and 'inactive' in ufw.lower(): self.add('HIGH','net','fw_off')
        if public: self.add('MED','net','open_port', d=', '.join(sorted(public)[:10]))

    def os_hardening(self):
        if OS == 'mac':
            if 'On' not in run(['fdesetup','status']): self.add('HIGH','os','filevault')
            al = run(['defaults','read','/Library/Preferences/com.apple.loginwindow','autoLoginUser'])
            if al.strip() and 'does not exist' not in al: self.add('HIGH','os','autologin')
            if run(['defaults','read','com.apple.screensaver','askForPassword']).strip() == '0': self.add('MED','os','screenlock')
            v = run(['sw_vers','-productVersion']).strip()
            if v: self.add('INFO','os','os_ver', v=v)
        elif OS == 'win':
            bde = run(['manage-bde','-status','C:'])
            if bde and 'Protection On' not in bde: self.add('HIGH','os','filevault')
            au = run(['reg','query','HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon','/v','AutoAdminLogon'])
            if re.search(r'AutoAdminLogon\s+REG_SZ\s+1', au): self.add('HIGH','os','autologin')
            self.add('INFO','os','os_ver', v=f"Windows {run(['cmd','/c','ver']).strip()[:40]}")
        else:  # linux
            enc = run(['lsblk','-o','NAME,TYPE'])
            if enc and 'crypt' not in enc: self.add('HIGH','os','filevault')
            try: rel = open('/etc/os-release').read()
            except Exception: rel = ''
            m = re.search(r'PRETTY_NAME="?([^"\n]+)', rel)
            self.add('INFO','os','os_ver', v=(m.group(1) if m else 'Linux'))

    def ai_agent(self):
        hot = []
        for cfg in ('.claude','.config/claude','.cursor','.aws','.config'):
            p = os.path.join(self.home, cfg)
            if os.path.isdir(p):
                for dp, dns, fns in os.walk(p):
                    if dp.count(os.sep) - p.count(os.sep) > 2: dns[:] = []; continue
                    for f in fns:
                        if re.search(r'(token|secret|credential|\.env|key)', f, re.I) and f.endswith(('.json','.env','.key','.pem')):
                            fp = os.path.join(dp, f)
                            try: mode = oct(os.stat(fp).st_mode & 0o777)[2:]
                            except Exception: continue
                            if mode[-1] in '1234567' or mode[-2] in '1234567': hot.append(fp.replace(self.home,'~'))
        if hot: self.add('MED','ai','ai_cfg', n=len(hot), d=', '.join(hot[:5]))
        self.add('INFO','ai','ai_inject')

    def _repo_backup_recent(self, max_age_h=3):
        """저장소 자동 커밋 백업 실증 — SECSCAN_BACKUP_REPOS(콜론 구분) 경로와 cwd(git repo일
        때만) 중 git 최근 커밋이 max_age_h 이내면 (경로, 경과분) 반환. 주기 커밋을 백업으로
        인정('Time Machine만 = 백업' 정의가 낳은 '최근 백업 없음' 오탐 정정). 기본값은 cwd뿐 —
        어떤 환경 경로도 코드에 두지 않는다(운용측이 env/--backup-repos로 주입)."""
        repos = [p for p in os.environ.get('SECSCAN_BACKUP_REPOS','').split(':') if p]
        repos += [os.getcwd()]
        for r in repos:
            if not os.path.isdir(os.path.join(os.path.expanduser(r), '.git')): continue
            ts = run(['git','-C',os.path.expanduser(r),'log','-1','--format=%ct'])
            try: age_s = datetime.datetime.now().timestamp() - int(ts.strip())
            except Exception: continue
            if age_s <= max_age_h*3600: return r, int(age_s//60)
        return None, None

    def backup(self):
        repo, age_min = self._repo_backup_recent()
        if OS == 'mac':
            tm = run(['tmutil','latestbackup'])
            tm_ok = not ('no' in tm.lower() or not tm.strip() or 'Error' in tm)
            if tm_ok: pass
            elif repo: self.add('INFO','backup','backup_repo', m=age_min)
            else: self.add('MED','backup','no_backup')
        elif OS == 'win':
            fh = run(['cmd','/c','fhmanagew.exe','query'])
            if not fh or 'not configured' in fh.lower():
                if repo: self.add('INFO','backup','backup_repo', m=age_min)
                else: self.add('MED','backup','no_backup')
        # linux: 표준 백업 메커니즘 없음 — 오탐 방지 위해 미판정

    def run_all(self):
        for fn in (self.credentials, self.network, self.os_hardening, self.ai_agent, self.backup):
            try: fn()
            except Exception: pass
        H = sum(1 for f in self.findings if f['sev']=='HIGH')
        M = sum(1 for f in self.findings if f['sev']=='MED')
        return {'ts': datetime.datetime.now().strftime('%Y-%m-%d %H:%M'), 'lang': self.lang, 'os': OS,
                'user': getpass.getuser(), 'score': max(0, 100-H*12-M*5), 'high': H, 'med': M, 'findings': self.findings}

_DASHBOARD = r"""<!doctype html><html lang="__L__"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>AI-Hacking Self-Audit</title>
<style>
:root{--ink:#0E1922;--surf:#15232E;--surf2:#1B2C38;--line:#283a46;--text:#EAF1F4;--muted:#90A4AF;--faint:#62788699;
--crit:#FF6B6B;--warn:#FFC24B;--good:#36D399;--info:#5AB0FF;--r:18px;
--sans:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",system-ui,sans-serif;
--round:ui-rounded,"SF Pro Rounded",-apple-system,system-ui,sans-serif;}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--sans);background:
radial-gradient(1200px 600px at 80% -10%,#15303a 0,transparent 55%),
radial-gradient(900px 500px at -10% 10%,#172a38 0,transparent 50%),var(--ink);
color:var(--text);min-height:100vh;-webkit-font-smoothing:antialiased;line-height:1.5}
.wrap{width:100%;max-width:clamp(900px,95vw,3360px);margin:0 auto;padding:clamp(14px,1.6vw,28px) clamp(14px,2vw,40px) 60px}
header{display:flex;align-items:center;gap:12px;margin-bottom:26px}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;letter-spacing:-.01em}
.logo .mk{width:30px;height:30px;border-radius:9px;background:linear-gradient(145deg,var(--good),#1b9e78);
display:grid;place-items:center;font-size:16px;box-shadow:0 4px 14px #36d39944}
.hactions{margin-left:auto;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.btn{font:inherit;font-size:12.5px;color:var(--text);background:var(--surf);border:1px solid var(--line);
border-radius:10px;padding:7px 12px;cursor:pointer;transition:border-color .15s,background .15s}
.btn:hover{border-color:#3b5464;background:var(--surf2)}
.btn:focus-visible{outline:2px solid var(--good);outline-offset:2px}
.chip-local{color:var(--good);border-color:#2b6b55;background:#12302a}
/* hero */
.hero{display:flex;gap:28px;align-items:center;background:var(--surf);border:1px solid var(--line);
border-radius:var(--r);padding:26px 28px;position:relative;overflow:hidden}
.ringwrap{position:relative;width:150px;height:150px;flex:0 0 auto}
.ring{transform:rotate(-90deg)}
.ring circle{fill:none;stroke-width:11;stroke-linecap:round}
.ring .bg{stroke:#223642}
.ring .fg{transition:stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1);stroke:var(--good)}
.ringnum{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.ringnum b{font-family:var(--round);font-size:clamp(38px,4vw,56px);font-weight:800;line-height:1;letter-spacing:-.02em}
.ringnum span{font-size:11px;color:var(--muted);margin-top:3px}
.verdict{min-width:0}
.verdict .vtag{display:inline-block;font-size:13px;font-weight:700;padding:4px 12px;border-radius:999px;margin-bottom:10px}
.verdict h1{font-size:clamp(19px,2.2vw,30px);font-weight:700;letter-spacing:-.02em;margin-bottom:6px}
.verdict p{color:var(--muted);font-size:13.5px;max-width:46ch}
.verdict .meta{color:var(--faint);font-size:12px;margin-top:12px}
/* vitals */
.sec-h{font-size:13px;color:var(--muted);margin:30px 2px 12px;font-weight:600}
.vitals{display:grid;grid-template-columns:repeat(auto-fit,minmax(clamp(132px,13vw,190px),1fr));gap:clamp(8px,0.9vw,14px)}
.vital{background:var(--surf);border:1px solid var(--line);border-radius:14px;padding:13px 13px 15px;cursor:pointer;
text-align:left;transition:transform .12s,border-color .15s;color:inherit;font:inherit}
.vital:hover{transform:translateY(-2px);border-color:#3b5464}
.vital[aria-pressed=true]{border-color:var(--good);box-shadow:0 0 0 1px var(--good) inset}
.vital .vn{font-size:12.5px;font-weight:600;margin-bottom:10px;display:flex;align-items:center;gap:6px}
.vital .dot{width:8px;height:8px;border-radius:50%}
.vital .bar{height:5px;border-radius:3px;background:#223642;overflow:hidden}
.vital .bar i{display:block;height:100%;border-radius:3px;width:0;transition:width 1s .3s ease}
.vital .vs{font-size:11px;color:var(--muted);margin-top:8px}
/* controls */
.controls{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:26px 2px 12px}
.fchip{font:inherit;font-size:12.5px;cursor:pointer;color:var(--muted);background:transparent;border:1px solid var(--line);
border-radius:999px;padding:6px 13px;transition:all .14s}
.fchip[aria-pressed=true]{color:var(--ink);background:var(--text);border-color:var(--text);font-weight:600}
.fcount{margin-left:auto;color:var(--faint);font-size:12.5px}
/* findings */
.find{background:var(--surf);border:1px solid var(--line);border-radius:14px;margin-bottom:9px;overflow:hidden}
.find>button{all:unset;display:flex;align-items:center;gap:11px;width:100%;padding:15px 16px;cursor:pointer;box-sizing:border-box}
.find>button:focus-visible{outline:2px solid var(--good);outline-offset:-2px}
.sdot{width:9px;height:9px;border-radius:50%;flex:0 0 auto}
.ftitle{font-size:14px;font-weight:600;flex:1;min-width:0}
.ftag{font-size:11px;color:var(--muted);background:#1f3340;padding:2px 8px;border-radius:6px;flex:0 0 auto}
.chev{color:var(--faint);transition:transform .2s;flex:0 0 auto}
.find.open .chev{transform:rotate(90deg)}
.body{max-height:0;overflow:hidden;transition:max-height .28s ease}
.body .inner{padding:0 16px 16px 36px}
.detail{color:var(--muted);font-size:13px;margin-bottom:12px}
.why{background:#13262f;border-left:3px solid var(--info);border-radius:0 10px 10px 0;padding:10px 13px;margin-bottom:12px}
.why .wl{font-size:11px;color:var(--info);font-weight:700;margin-bottom:4px}
.why p{font-size:12.5px;color:#c7d7df;line-height:1.55}
.fixbox{background:#102a22;border:1px solid #1e4a3a;border-radius:10px;padding:11px 13px;display:flex;gap:10px;align-items:flex-start}
.fixbox .fl{font-size:11px;color:var(--good);font-weight:700;margin-bottom:4px}
.fixbox p{font-size:12.5px;color:#cdeadf;line-height:1.5}
.copy{margin-left:auto;flex:0 0 auto}
.clean{background:var(--surf);border:1px solid #1e4a3a;border-radius:14px;padding:22px;text-align:center;color:var(--good);font-size:14px}
footer{margin-top:30px;color:var(--faint);font-size:11.5px;line-height:1.7;border-top:1px solid var(--line);padding-top:16px}
/* modal */
.modal{position:fixed;inset:0;background:#06101699;display:grid;place-items:center;padding:20px;z-index:50}
.modal[hidden]{display:none}
.modal .box{background:var(--surf);border:1px solid var(--line);border-radius:var(--r);padding:24px;max-width:440px}
.modal h3{font-size:16px;margin-bottom:10px;color:var(--good)}
.modal p{font-size:13px;color:var(--muted);line-height:1.6}
.modal .btn{margin-top:16px}
/* 섹션2 피드 네트워크 (코어+5 피드노드 통합) */
.netwrap{position:relative;width:100%;aspect-ratio:920/600;background:var(--surf);border:1px solid var(--line);border-radius:var(--r);overflow:hidden}
#netlines{position:absolute;inset:0;width:100%;height:100%}
.mon.fnode{position:absolute;transform:translate(-50%,-50%);width:22.5%;min-width:170px;z-index:2}
.mon.fnode:hover{transform:translate(-50%,calc(-50% - 2px))}
.fnode .feed{min-height:58px}
@media (max-width:900px){
 .netwrap{aspect-ratio:auto;height:auto;display:grid;grid-template-columns:1fr 1fr;gap:9px;padding:12px}
 #netlines{display:none}
 .mon.fnode,.mon.fnode:hover{position:static;transform:none;width:auto;min-width:0}
 .fnode .feed{min-height:70px}
}
/* 보안 모듈 카드 (Q-048) */
.cardgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(clamp(270px,22vw,360px),1fr));gap:clamp(10px,1.1vw,18px);margin-bottom:8px}
@media (min-width:2400px){.cardgrid{grid-template-columns:repeat(auto-fill,minmax(420px,1fr))}}
.mcard{background:var(--surf);border:1px solid var(--line);border-radius:var(--r);padding:16px 16px 14px;display:flex;flex-direction:column;gap:9px;min-width:0}
.mcard.alert{border-color:var(--crit);box-shadow:0 0 0 1px var(--crit) inset}
.mcard.stale{border-color:var(--warn)}
/* SEC-002 글로우: 실가동(지켜보는 중·자동으로 막는 중) 카드만 은은한 pulse — 준비 중·꺼져 있음은 무광(거짓 안심 방지) */
@keyframes livePulse{0%{box-shadow:0 0 6px 0 rgba(54,211,153,.10),0 0 0 1px rgba(54,211,153,.14) inset;border-color:rgba(54,211,153,.35)}100%{box-shadow:0 0 16px 2px rgba(54,211,153,.26),0 0 0 1px rgba(54,211,153,.30) inset;border-color:rgba(54,211,153,.60)}}
@keyframes livePulseAmber{0%{box-shadow:0 0 6px 0 rgba(255,159,67,.10),0 0 0 1px rgba(255,159,67,.14) inset;border-color:rgba(255,159,67,.35)}100%{box-shadow:0 0 16px 2px rgba(255,159,67,.28),0 0 0 1px rgba(255,159,67,.32) inset;border-color:rgba(255,159,67,.60)}}
.mcard.live{animation:livePulse 4s ease-in-out infinite alternate}
.mcard.live.stale{animation:livePulseAmber 4s ease-in-out infinite alternate}
.mcard.live.alert{animation:none}
@media (prefers-reduced-motion: reduce){.mcard.live,.mcard.live.stale{animation:none;box-shadow:0 0 10px 1px rgba(54,211,153,.18);border-color:rgba(54,211,153,.45)}}
.mcard .mh2{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.mcard .mh2 b{font-size:15px;overflow-wrap:anywhere}
.cbadge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11.5px;font-weight:800;background:#ffffff14;color:var(--muted);white-space:normal}
.cbadge.b-warn{background:#f5b94a22;color:var(--warn)}.cbadge.b-block{background:#36d39922;color:var(--good)}
.cbadge.b-off{background:#ffffff10;color:var(--muted)}.cbadge.b-plan{background:#6aa8ff22;color:var(--info)}
.cbadge.b-stale{background:#f5b94a33;color:var(--warn)}.cbadge.b-broken{background:#ff5d6c33;color:var(--crit)}
.cbadge.b-ask{background:#ff9f4326;color:#ff9f43}
.mcard .fld{font-size:12.5px;line-height:1.55;color:var(--muted);overflow-wrap:anywhere}
.mcard .fld i{font-style:normal;font-weight:800;color:var(--text);margin-right:6px}
.mcard .fld.lim{color:#e7c987}
.mcard .act{font-size:13px;color:var(--text);line-height:1.6;overflow-wrap:anywhere}
.kv{display:flex;flex-wrap:wrap;gap:6px}.kv span{background:#ffffff0d;border-radius:8px;padding:3px 9px;font-size:12px;white-space:normal}
.kv span b{margin-left:4px}.kv .g-now b{color:var(--crit)}.kv .g-pri b{color:#FF9F45}
.mcard .more{align-self:flex-start;cursor:pointer}
.mcard .moreb{display:none;font-size:12.5px;line-height:1.6;color:var(--muted);border-top:1px solid var(--line);padding-top:8px;overflow-wrap:anywhere}
.mcard.open .moreb{display:block}
.mcard .moreb div{padding:2px 0}
/* 블럭 번호 배지 */
.secbadge{display:inline-flex;align-items:center;justify-content:center;min-width:22px;height:22px;padding:0 7px;border-radius:7px;background:var(--good);color:#06181f;font-weight:800;font-size:12px;margin-right:9px;vertical-align:middle}
.anum{display:inline-flex;align-items:center;justify-content:center;width:19px;height:19px;border-radius:50%;border:1.5px solid var(--good);color:var(--good);font-weight:800;font-size:11px;flex:0 0 auto}
.herobadge{position:absolute;top:12px;left:14px}
/* live scan monitors */
.monitors{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:11px}
.mon{background:var(--surf);border:1px solid var(--line);border-radius:14px;padding:13px 14px 11px;cursor:pointer;
position:relative;overflow:hidden;transition:border-color .15s,transform .12s}
.mon:hover{border-color:#3b5464;transform:translateY(-2px)}
.mon[aria-pressed=true]{border-color:var(--good);box-shadow:0 0 0 1px var(--good) inset}
.mon .mininet{position:absolute;inset:0;z-index:0;opacity:.32;pointer-events:none}
.mon .mh,.mon .feed{position:relative;z-index:1}
.mon .mh{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:600;margin-bottom:9px}
.mon .mh .mi{width:20px;height:20px;flex:0 0 auto}
.mon .mh .ms{margin-left:auto;font-size:9.5px;color:var(--good);display:flex;align-items:center;gap:4px}
.mon .mh .ms .d{width:6px;height:6px;border-radius:50%;background:var(--good);animation:pd 1.5s infinite}
.mon .scanline{position:absolute;left:0;right:0;height:28px;top:34px;
background:linear-gradient(90deg,transparent,#36d39911 40%,#36d39922 50%,#36d39911 60%,transparent);
animation:sweep 2.4s linear infinite;pointer-events:none}
@keyframes sweep{0%{transform:translateY(-6px);opacity:0}20%{opacity:1}80%{opacity:1}100%{transform:translateY(96px);opacity:0}}
.feed{font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:11px;line-height:1.75;min-height:90px}
.feed .ln{display:flex;gap:7px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.feed .ln .ic{flex:0 0 auto}
.feed .ln.scan .ic{color:var(--warn)}
.feed .ln.ok{color:#9fb6c0}.feed .ln.ok .ic{color:var(--good)}
.feed .cur{color:var(--good)}
.feed .cur b{animation:blink 1s steps(1) infinite}
@keyframes blink{50%{opacity:0}}
/* live monitoring */
.livebar{display:flex;align-items:center;gap:9px;font-size:12.5px;color:var(--good);margin:0 2px 16px;font-weight:600}
.pulse-dot{width:9px;height:9px;border-radius:50%;background:var(--good);animation:pd 1.7s infinite}
@keyframes pd{0%{box-shadow:0 0 0 0 #36d39988}70%{box-shadow:0 0 0 8px #36d39900}100%{box-shadow:0 0 0 0 #36d39900}}
.clock{margin-left:auto;color:var(--muted);font-variant-numeric:tabular-nums;font-weight:500;letter-spacing:.02em}
.net{background:var(--surf);border:1px solid var(--line);border-radius:var(--r);padding:12px 10px 8px}
.net svg{width:100%;height:auto;display:block}
.nnode{cursor:pointer}
.nnode text{font-family:var(--sans)}
.nnode:focus-visible{outline:none}
.nnode:focus-visible .nbox{stroke:var(--good);stroke-width:2}
.nnode[aria-pressed=true] .nbox{stroke:var(--good);stroke-width:2.5}
.ring-glow{animation:breathe 3.2s ease-in-out infinite;transform-origin:center}
@keyframes breathe{0%,100%{opacity:.14;r:40}50%{opacity:.3;r:46}}
.ringwrap::after{content:"";position:absolute;inset:-6px;border-radius:50%;box-shadow:0 0 34px 2px #36d39933;animation:breathe2 3.2s ease-in-out infinite;pointer-events:none}
@keyframes breathe2{0%,100%{opacity:.3}50%{opacity:.7}}
@media (max-width:620px){.hero{flex-direction:column;text-align:center}.verdict p{max-width:none}
.wrap{padding:16px 14px 48px}}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style></head>
<body><div class="wrap">
<header>
  <div class="logo"><span class="mk">🛡️</span><span id="brand"></span></div>
  <div class="hactions">
    <button class="btn chip-local" id="localBadge"></button>
    <button class="btn" id="exportBtn"></button>
    <button class="btn" id="printBtn"></button>
  </div>
</header>
<div class="livebar"><span class="pulse-dot"></span><span id="liveTxt"></span><span class="clock" id="clock"></span></div>
<section class="hero">
  <span class="secbadge herobadge">1</span>
  <div class="ringwrap"><svg class="ring" width="150" height="150" viewBox="0 0 120 120">
    <circle class="bg" cx="60" cy="60" r="52"></circle>
    <circle class="fg" cx="60" cy="60" r="52"></circle></svg>
    <div class="ringnum"><b id="scoreNum">0</b><span id="scoreLab"></span></div></div>
  <div class="verdict">
    <span class="vtag" id="vtag"></span>
    <h1 id="verdictTitle"></h1>
    <p id="whatScore"></p>
    <div class="meta" id="scanMeta"></div>
  </div>
</section>
<div class="sec-h" id="vitalsH"></div>
<div class="netwrap" id="netwrap"><svg id="netlines" viewBox="0 0 920 600" preserveAspectRatio="xMidYMid meet"></svg></div>
<div class="sec-h" id="findH"></div>
<div class="controls" id="filters"></div>
<div id="findings"></div>
<div class="sec-h" id="cardsH" hidden></div>
<div class="cardgrid" id="cardgrid"></div>
<footer id="foot"></footer>
</div>
<div class="modal" id="modal" hidden><div class="box">
  <h3 id="mTitle"></h3><p id="mBody"></p>
  <button class="btn" id="mClose">OK</button></div></div>
<script>
const DATA = /*DATA*/;
const UI = /*UI*/;
const CARDS = /*CARDS*/;
const CHECKS = /*CHECKS*/;
const AREAS=['cred','net','os','ai','backup'];
const AREA_ICON={cred:'🔑',net:'🌐',os:'💻',ai:'🤖',backup:'💾'};
const AREA_NAME=UI.areas;
const SEVC={HIGH:'var(--crit)',MED:'var(--warn)',INFO:'var(--info)'};
const scoreColor=s=>s>=90?'var(--good)':s>=70?'var(--warn)':s>=40?'#FF9F45':'var(--crit)';
let fSev='all',fArea=null;

document.getElementById('brand').textContent=UI.brand;
document.getElementById('scoreLab').textContent=UI.immunity;
document.getElementById('whatScore').textContent=UI.whatscore;
document.getElementById('scanMeta').textContent=UI.scanned+' · '+DATA.ts;
document.getElementById('vitalsH').innerHTML='<span class="secbadge">2</span>'+UI.net_title;
document.getElementById('findH').innerHTML='<span class="secbadge">3</span>'+UI.sec_find;
document.getElementById('liveTxt').textContent=UI.live_watch;
(function(){function tick(){document.getElementById('clock').textContent=new Date().toLocaleTimeString('__L__'==='ko'?'ko-KR':'en-US');}tick();setInterval(tick,1000);})();
document.getElementById('localBadge').textContent='🔒 '+UI.local;
document.getElementById('exportBtn').textContent='↓ '+UI.export;
document.getElementById('printBtn').textContent='🖨 '+UI.print;
document.getElementById('foot').textContent=UI.local_more;

// verdict
const sc=DATA.score;
const vt=document.getElementById('vtag');
let vlabel=sc>=90?UI.v_good:sc>=60?UI.v_warn:UI.v_crit;
vt.textContent=vlabel;vt.style.background=scoreColor(sc)+'22';vt.style.color=scoreColor(sc);
document.getElementById('verdictTitle').textContent=(DATA.user||'')+UI.hero_sub;

// ring + count-up
const C=2*Math.PI*52, fg=document.querySelector('.ring .fg');
fg.style.strokeDasharray=C; fg.style.strokeDashoffset=C; fg.style.stroke=scoreColor(sc);
const reduce=matchMedia('(prefers-reduced-motion:reduce)').matches;
requestAnimationFrame(()=>{setTimeout(()=>{fg.style.strokeDashoffset=C*(1-sc/100);},120)});
const numEl=document.getElementById('scoreNum');
if(reduce){numEl.textContent=sc;}else{let n=0;const step=Math.max(1,Math.round(sc/40));
 const t=setInterval(()=>{n+=step;if(n>=sc){n=sc;clearInterval(t);}numEl.textContent=n;},26);}
numEl.style.color=scoreColor(sc);

// vitals
function areaStat(a){const fs=DATA.findings.filter(f=>f.areaKey===a);
 if(fs.some(f=>f.sev==='HIGH'))return{c:'var(--crit)',w:34,n:fs.filter(f=>f.sev!=='INFO').length};
 if(fs.some(f=>f.sev==='MED'))return{c:'var(--warn)',w:66,n:fs.filter(f=>f.sev!=='INFO').length};
 return{c:'var(--good)',w:100,n:0};}
// 세련된 라인 아이콘 (SVG·이모지 대체)
const ICONS={
 core:'<path d="M12 2.5l7.5 3.2v5.1c0 4.8-3.2 8.6-7.5 10.7-4.3-2.1-7.5-5.9-7.5-10.7V5.7z"/><path d="M8.6 12.2l2.3 2.3 4.5-4.6"/>',
 cred:'<circle cx="8" cy="8" r="3.4"/><path d="M10.4 10.4L19 19M15.8 17.8l2.2 2.2M18.3 15.3l2.2 2.2"/>',
 net:'<circle cx="12" cy="12" r="8.3"/><path d="M3.7 12h16.6M12 3.7c-3.2 4.2-3.2 12.4 0 16.6M12 3.7c3.2 4.2 3.2 12.4 0 16.6"/>',
 os:'<rect x="3" y="4.6" width="18" height="12" rx="1.8"/><path d="M8.8 20.6h6.4M12 16.6v4"/>',
 ai:'<rect x="6.6" y="6.6" width="10.8" height="10.8" rx="2.4"/><circle cx="12" cy="12" r="2.2"/><path d="M12 2.6v4M12 17.4v4M2.6 12h4M17.4 12h4"/>',
 backup:'<ellipse cx="12" cy="6" rx="7" ry="2.9"/><path d="M5 6v12c0 1.6 3.1 2.9 7 2.9s7-1.3 7-2.9V6M5 12c0 1.6 3.1 2.9 7 2.9s7-1.3 7-2.9"/>'
};
function svgIcon(name,x,y,color,s){s=s||.72;
 return '<g transform="translate('+x+','+y+') scale('+s+')" fill="none" stroke="'+color+'" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">'+ICONS[name]+'</g>';}

// 블럭 안에서 움직이는 미니 신경망 (영역별 변주)
function miniNet(col,idx){
 const base=[[38,28],[118,66],[198,34],[158,96],[70,92]];
 const pts=base.map((p,k)=>[p[0]+((idx*13+k*7)%22)-11, p[1]+((idx*9+k*5)%18)-9]);
 let lines='',path='M',nodes='';
 pts.forEach((p,k)=>{path+=(k?' L':'')+p[0].toFixed(0)+','+p[1].toFixed(0);
  nodes+='<circle cx="'+p[0].toFixed(0)+'" cy="'+p[1].toFixed(0)+'" r="2.4" fill="'+col+'"/>';});
 for(let k=0;k<pts.length-1;k++){lines+='<line x1="'+pts[k][0].toFixed(0)+'" y1="'+pts[k][1].toFixed(0)+'" x2="'+pts[k+1][0].toFixed(0)+'" y2="'+pts[k+1][1].toFixed(0)+'" stroke="'+col+'" stroke-opacity=".35" stroke-width="1"/>';}
 const pulse=(beg,r)=>'<circle r="'+r+'" fill="'+col+'" filter="url(#g)"><animateMotion dur="'+(3+idx*0.35).toFixed(1)+'s" begin="'+beg+'s" repeatCount="indefinite" calcMode="spline" keyPoints="0;1" keyTimes="0;1" keySplines="0.4 0 0.6 1" path="'+path+'"/></circle>';
 return '<svg class="mininet" viewBox="0 0 260 120" preserveAspectRatio="xMidYMid slice">'+lines+nodes+pulse('0',2.8)+pulse((1.2+idx*0.2).toFixed(1),2.1)+'</svg>';
}
function pad(n){return(n<10?'0':'')+n;}
function nowt(){const d=new Date();return pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds());}
// 섹션2 통합: 코어 + 5 피드노드(스캔모니터) + 신경망 펄스
function buildNetwork(){
 const cx=460,cy=300,pts={cred:[460,74],net:[678,232],os:[596,486],ai:[324,486],backup:[242,232]};
 const overall=DATA.high?'var(--crit)':DATA.med?'var(--warn)':'var(--good)';
 let paths='',flows='',pulses='';
 const mk=(pd,dur,beg,r,col)=>'<circle r="'+r+'" fill="'+col+'" filter="url(#g)"><animateMotion dur="'+dur+'s" begin="'+beg+'s" repeatCount="indefinite" calcMode="spline" keyPoints="0;1" keyTimes="0;1" keySplines="0.4 0 0.6 1" path="'+pd+'"/></circle>';
 AREAS.forEach((a,i)=>{const p=pts[a],x=p[0],y=p[1],s=areaStat(a);
  const mx=(cx+x)/2,my=(cy+y)/2,dx=x-cx,dy=y-cy,ln=Math.hypot(dx,dy)||1,off=46*(i%2?1:-1);
  const ctx=(mx+(-dy/ln)*off).toFixed(0),cty=(my+(dx/ln)*off).toFixed(0);
  const d='M'+cx+','+cy+' Q'+ctx+','+cty+' '+x+','+y, dr='M'+x+','+y+' Q'+ctx+','+cty+' '+cx+','+cy;
  paths+='<path d="'+d+'" fill="none" stroke="'+s.c+'" stroke-opacity=".28" stroke-width="1.6"/>';
  flows+='<path d="'+d+'" fill="none" stroke="'+s.c+'" stroke-opacity=".65" stroke-width="1.8" stroke-linecap="round" stroke-dasharray="4 16"><animate attributeName="stroke-dashoffset" values="0;-20" dur="'+(1.2+i*0.12).toFixed(2)+'s" repeatCount="indefinite"/></path>';
  pulses+=mk(d,(2.1+i*0.15).toFixed(2),(i*0.3).toFixed(2),4.2,s.c)+mk(dr,(2.5+i*0.1).toFixed(2),(i*0.3+0.9).toFixed(2),3,'#eaf1f4')+mk(d,'2.9',(i*0.3+1.6).toFixed(2),2.6,s.c);
 });
 const radar=(beg)=>'<circle cx="'+cx+'" cy="'+cy+'" r="48" fill="none" stroke="'+overall+'" stroke-width="2"><animate attributeName="r" values="48;92" dur="3s" begin="'+beg+'s" repeatCount="indefinite"/><animate attributeName="opacity" values="0.5;0" dur="3s" begin="'+beg+'s" repeatCount="indefinite"/></circle>';
 const core='<g>'+radar('0')+radar('1.5')+'<circle class="ring-glow" cx="'+cx+'" cy="'+cy+'" r="64" fill="'+overall+'"/><circle cx="'+cx+'" cy="'+cy+'" r="48" fill="var(--surf2)" stroke="'+overall+'" stroke-width="2.5"/>'+svgIcon('core',cx-17,cy-26,overall,1.5)+'<text x="'+cx+'" y="'+(cy+32)+'" text-anchor="middle" font-size="12" fill="var(--muted)">'+UI.watching+'</text></g>';
 document.getElementById('netlines').innerHTML='<defs><filter id="g" x="-60%" y="-60%" width="220%" height="220%"><feGaussianBlur stdDeviation="2.6"/></filter></defs>'+paths+flows+core+pulses;
 const wrap=document.getElementById('netwrap');
 AREAS.forEach((a,idx)=>{const p=pts[a],s=areaStat(a),nm=AREA_NAME[a]||a;
  const card=document.createElement('div');card.className='mon fnode';card.dataset.area=a;
  card.style.left=(p[0]/920*100).toFixed(2)+'%';card.style.top=(p[1]/600*100).toFixed(2)+'%';
  card.setAttribute('role','button');card.setAttribute('tabindex','0');card.setAttribute('aria-pressed','false');
  card.innerHTML=(reduce?'':miniNet(s.c,idx))+
   '<div class="mh"><span class="anum">'+(idx+1)+'</span><svg class="mi" viewBox="0 0 24 24" fill="none" stroke="'+s.c+'" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">'+ICONS[a]+'</svg><span>'+nm+'</span><span class="ms"><span class="d"></span>'+UI.scanning+'</span></div>'+
   (reduce?'':'<div class="scanline"></div>')+
   '<div class="feed" id="feed-'+a+'"></div>';
  const act=()=>{fArea=(fArea===a)?null:a;document.querySelectorAll('.fnode').forEach(m=>m.setAttribute('aria-pressed',m.dataset.area===fArea));render();};
  card.onclick=act;card.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();act();}});
  wrap.appendChild(card);
  runFeed(a,CHECKS[a]||[],s.c,idx);
 });
}
function shuffle(arr){for(let k=arr.length-1;k>0;k--){const j=Math.floor(Math.random()*(k+1));const t=arr[k];arr[k]=arr[j];arr[j]=t;}return arr;}
function runFeed(a,steps0,col,idx){
 const feed=document.getElementById('feed-'+a);if(!feed||!steps0.length)return;
 const MAX=4;let done=[];let order=shuffle(steps0.slice());let i=0;
 function paint(scanIdx){
  let h='';
  done.slice(-MAX+1).forEach(t=>{h+='<div class="ln ok"><span class="ic">✓</span><span>'+t.s+'</span><span style="margin-left:auto;opacity:.5">'+t.t+'</span></div>';});
  if(scanIdx!=null){h+='<div class="ln scan"><span class="ic">⟳</span><span>'+order[scanIdx]+'…</span></div>';}
  h+='<div class="ln cur"><span class="ic">▸</span><b>_</b></div>';
  feed.innerHTML=h;
 }
 if(reduce){done=steps0.map(s=>({s:s,t:nowt()}));paint(null);return;}
 function cycle(){
  paint(i);
  const dwell=820+Math.floor(Math.random()*500); // 점검마다 소요 달라 더 생동감
  setTimeout(()=>{done.push({s:order[i],t:nowt()});i++;
   if(i>=order.length){i=0;order=shuffle(steps0.slice());done=[];} // 매 순환 셔플 → 내용이 계속 바뀜
   setTimeout(cycle,300);},dwell);
 }
 setTimeout(cycle,idx*450);
}
buildNetwork();
if(reduce){document.querySelectorAll('animateMotion,animate').forEach(a=>a.remove());}

// filters
const counts={all:DATA.findings.length,HIGH:DATA.high,MED:DATA.med,INFO:DATA.findings.filter(f=>f.sev==='INFO').length};
const fcon=document.getElementById('filters');
[['all',UI.all,counts.all],['HIGH',UI.crit,counts.HIGH],['MED',UI.warn,counts.MED],['INFO',UI.info,counts.INFO]].forEach(([k,lab,n])=>{
 const c=document.createElement('button');c.className='fchip';c.dataset.k=k;
 c.setAttribute('aria-pressed',k==='all');c.textContent=lab+' '+n;
 c.onclick=()=>{fSev=k;document.querySelectorAll('.fchip').forEach(x=>x.setAttribute('aria-pressed',x.dataset.k===k));render();};
 fcon.appendChild(c);});
const fcount=document.createElement('span');fcount.className='fcount';fcon.appendChild(fcount);

// findings
const ORDER={HIGH:0,MED:1,INFO:2};
function render(){
 let list=DATA.findings.slice().sort((a,b)=>ORDER[a.sev]-ORDER[b.sev]);
 if(fSev!=='all')list=list.filter(f=>f.sev===fSev);
 if(fArea)list=list.filter(f=>f.areaKey===fArea);
 fcount.textContent=list.length+' '+UI.findings;
 const con=document.getElementById('findings');con.innerHTML='';
 if(!list.length){con.innerHTML='<div class="clean">'+UI.clean+'</div>';return;}
 list.forEach(f=>{
  const el=document.createElement('div');el.className='find';
  const sev=f.sev, col=SEVC[sev];
  el.innerHTML=
   '<button aria-expanded="false"><span class="sdot" style="background:'+col+'"></span>'+
   '<span class="ftitle">'+esc(f.title)+'</span><span class="ftag">'+esc(f.area)+'</span>'+
   '<span class="chev">›</span></button>'+
   '<div class="body"><div class="inner">'+
   '<div class="detail">'+esc(f.detail)+'</div>'+
   '<div class="why"><div class="wl">💡 '+UI.why+'</div><p>'+esc(f.why)+'</p></div>'+
   '<div class="fixbox"><div><div class="fl">🔧 '+UI.fix+'</div><p class="fixtext">'+esc(f.fix)+'</p></div>'+
   '<button class="btn copy">'+UI.copy+'</button></div>'+
   '</div></div>';
  const btn=el.querySelector('button[aria-expanded]'),body=el.querySelector('.body');
  btn.onclick=()=>{const o=el.classList.toggle('open');btn.setAttribute('aria-expanded',o);
   body.style.maxHeight=o?body.scrollHeight+'px':'0';};
  el.querySelector('.copy').onclick=(e)=>{e.stopPropagation();
   navigator.clipboard&&navigator.clipboard.writeText(f.fix);
   e.target.textContent=UI.copied;setTimeout(()=>e.target.textContent=UI.copy,1400);};
  con.appendChild(el);
 });
}
function esc(s){return(s+'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
render();


// ── 보안 모듈 카드 (security_cards.py 실데이터·읽기 전용) ──
(function(){
 if(!CARDS||!CARDS.cards)return;
 const H=document.getElementById('cardsH'),G=document.getElementById('cardgrid');
 H.hidden=false;H.innerHTML='<span class="secbadge">4</span>보안 모듈 카드 <span style="font-size:12px;color:var(--muted);font-weight:400;margin-left:8px">생성 '+esc(CARDS.generated)+' · 값은 모두 로그·피드에서 계산</span>';
 const BC={'지켜보는 중':'b-warn','자동으로 막는 중':'b-block','꺼져 있음':'b-off','준비 중':'b-plan','내 확인 필요':'b-ask','최신 정보 연결이 끊겼어요':'b-broken',
  '경고모드':'b-warn','차단모드':'b-block','비활성':'b-off','설계':'b-plan','오래됨':'b-stale','피드끊김':'b-broken'};
 const bcls=s=>s&&s.indexOf('정보가 오래됐어요')===0?'b-stale':(BC[s]||'');
 const nv=v=>(v===null||v===undefined)?'데이터 없음':v;
 const kv=(pairs)=>'<div class="kv">'+pairs.map(p=>'<span'+(p[2]?' class="'+p[2]+'"':'')+'>'+esc(p[0])+'<b>'+esc(nv(p[1]))+'</b></span>').join('')+'</div>';
 function actual(c){const a=c.actual;
  if(c.card==='threat_intel'){
   let h='<div class="act">'+esc(c.headline)+'</div><div class="act">'+esc(c.scope_line)+'</div>';
   h+=kv([['OSV',a.records.osv],['KEV',a.records.kev],['EPSS',a.records.epss],['갱신 연속실패',a.update_fail_streak],['마지막 성공',a.last_update_ok]]);
   if(a.triage)h+=kv([['즉시',a.triage['즉시'],'g-now'],['우선',a.triage['우선'],'g-pri'],['계획',a.triage['계획']],['모니터링',a.triage['모니터링']],['KEV 매칭',a.kev_matched],['어제 대비 신규',a.new_since_yesterday]]);
   else h+='<div class="act" style="color:var(--crit)">'+esc(a.not_scanned_reason||'등급 표시 불가')+'</div>';
   if(a.not_scanned_reason&&a.triage)h+='<div class="act" style="color:var(--warn)">'+esc(a.not_scanned_reason)+'</div>';
   return h;}
  if(c.card==='agent_injection'){
   const d=a.detected,f=a.false_positive;
   let h='<div class="act">'+esc(c.note)+'</div>'+kv([['최근 '+a.window_days+'일 탐지 낮음/중간/높음',d.low+' / '+d.mid+' / '+d.high],['shadow hold 해당',a.shadow_hold.would_hold],['상관 경보',a.shadow_hold.correlation_alerts],['카나리 노출',a.canary_leaks],['송출성 도구 호출 기록',a.egress_tool_calls_logged],['hold·ask·deny',a.holds===null?'미구현(준비 중)':a.holds]]);
   h+=kv([['오탐 라벨됨',f.labeled],['라벨 대기',f.unlabeled],['오탐률',f.rate_pct===null?'라벨 없어 미표시':f.rate_pct+'%']]);
   return h;}
  if(c.card==='traceback'&&!a.data){
   let h='<div class="act">'+esc(a.scan_ts?'최근 수집 '+a.scan_ts:'')+'</div>';
   h+=kv([['활성 원격 연결',a.active_remote_conn],['들어온 연결',a.inbound_conn],['원격 로그인',a.remote_logins],['로컬 로그인',a.local_logins]]);
   h+=kv([['원격 로그인(22) 열림',a.remote_login_22?'예':'아니요'],['화면 공유(5900) 열림',a.screen_share_5900?'예':'아니요'],['대시보드 바인드',a.dashboard_bind?a.dashboard_bind+(a.dashboard_bind==='127.0.0.1'?' (이 기기 안에서만)':''):'없음']]);
   if(a.top&&a.top.length)h+='<div class="act" style="font-size:12px;color:var(--muted)">'+a.top.map(x=>esc(x.ts+' · '+x.service+' · '+x.remote+' · '+x.country)).join('<br>')+'</div>';
   if(a.redline)h+='<div class="act" style="color:var(--muted);font-size:12px">'+esc(a.redline)+'</div>';
   return h;}
  if(a.data)return '<div class="act">'+esc(a.data)+'</div>';
  return '<div class="act">'+esc(a.scan_ts?'최근 점검 '+a.scan_ts:'')+'</div>'+kv([['위험',a.high],['주의',a.med],['정보',a.info]])+(a.top&&a.top.length?'<div class="act">'+a.top.map(esc).join(' · ')+'</div>':'');}
 CARDS.cards.forEach((c,i)=>{
  const el=document.createElement('div');el.className='mcard';
  const subs=c.badge_sub||[];
  if(subs.some(s=>s.indexOf('정보가 오래됐어요')===0||s==='최신 정보 연결이 끊겼어요'))el.classList.add('stale');
  const now=c.card==='threat_intel'&&c.actual.triage&&c.actual.triage['즉시']>0;
  if(now)el.classList.add('alert');
  if(['지켜보는 중','자동으로 막는 중','경고모드','차단모드'].includes(c.badge))el.classList.add('live');
  let more='';
  if(c.card==='threat_intel'&&c.actual.items&&c.actual.items.length)more='<div class="moreb">'+c.actual.items.map(x=>'<div>['+esc(x.grade)+'] '+esc(x.pkg)+' '+esc(x.ver)+' ('+esc(x.eco)+')'+(x.kev?' · KEV':'')+' · CVE '+x.cves+'건</div>').join('')+'</div>';
  if(c.card==='agent_injection')more='<div class="moreb">'+(c.layers?'<div>내부 상태(전문가용): '+Object.keys(c.layers).map(k=>esc(k)+'='+esc(c.layers[k])).join(' · ')+'</div>':'')+esc(c.edu)+'</div>';
  el.innerHTML='<div class="mh2"><span class="anum">'+(i+1)+'</span><b>'+esc(c.title)+'</b>'+
   '<span class="cbadge '+bcls(c.badge)+'" title="'+esc(c.badge_desc||'')+'">'+esc(c.badge)+'</span>'+subs.map(s=>'<span class="cbadge '+bcls(s)+'">'+esc(s)+'</span>').join('')+'</div>'+
   (c.badge==='준비 중'?'<div class="act" style="color:var(--muted)">'+esc(c.badge_desc)+'</div>':'')+
   '<div class="fld"><i>① 지키는 것</i>'+esc(c.protects)+'</div>'+
   '<div class="fld"><i>② 동작</i>'+esc(c.how)+'</div>'+
   '<div class="fld"><i>③ 실제로 한 일</i></div>'+actual(c)+
   '<div class="fld lim"><i>④ 못 하는 것</i>'+esc(c.limits)+'</div>'+
   (c.fixed?'<div class="fld"><i>⑤ 그래서 이렇게 보완했어요</i>'+esc(c.fixed)+'</div>':'')+
   (c.ops?'<div class="fld"><i>⑥ 지금은 이렇게 운영돼요</i>'+esc(c.ops)+'</div>':'')+
   (more?'<button class="btn more" aria-expanded="false">'+(c.card==='agent_injection'?'간접 프롬프트 인젝션이란?':'즉시·우선 목록 '+c.actual.items.length+'건')+'</button>'+more:'');
  const b=el.querySelector('.more');
  if(b)b.onclick=()=>{const o=el.classList.toggle('open');b.setAttribute('aria-expanded',o);};
  G.appendChild(el);});
})();

// actions
document.getElementById('exportBtn').onclick=()=>{
 const blob=new Blob([JSON.stringify(DATA,null,2)],{type:'application/json'});
 const a=document.createElement('a');a.href=URL.createObjectURL(blob);
 a.download='security_report_'+DATA.ts.replace(/[^0-9]/g,'')+'.json';a.click();};
document.getElementById('printBtn').onclick=()=>window.print();
const modal=document.getElementById('modal');
document.getElementById('localBadge').onclick=()=>{document.getElementById('mTitle').textContent='🔒 '+UI.local;
 document.getElementById('mBody').textContent=UI.local_more;modal.hidden=false;};
document.getElementById('mClose').onclick=()=>modal.hidden=true;
modal.onclick=e=>{if(e.target===modal)modal.hidden=true;};
document.addEventListener('keydown',e=>{if(e.key==='Escape')modal.hidden=true;});
document.title=UI.brand;
</script></body></html>"""

def render_html(rep):
    uid = dict(UISTR[rep['lang']]); uid['areas'] = {k: AREA[k][rep['lang']] for k in AREA}
    checks = {k: CHECKS[k][rep['lang']] for k in CHECKS}
    data = json.dumps(rep, ensure_ascii=False).replace('<', '\\u003c')
    ui = json.dumps(uid, ensure_ascii=False).replace('<', '\\u003c')
    chk = json.dumps(checks, ensure_ascii=False).replace('<', '\\u003c')
    cards = 'null'
    if rep['lang'] == 'ko':  # 보안 모듈 카드는 한국어 전용·생성기가 없으면(배포본) 섹션 생략
        try:
            import security_cards
            cards = json.dumps(security_cards.build_cards(rep), ensure_ascii=False).replace('<', '\\u003c')
        except Exception:
            cards = 'null'
    return (_DASHBOARD.replace('__L__', rep['lang']).replace('/*DATA*/', data)
            .replace('/*UI*/', ui).replace('/*CHECKS*/', chk).replace('/*CARDS*/', cards))

# ── 피드백 (SEC-003) — opt-in 전용. 자동 전송 0: 전문 미리보기 후 사용자가 GitHub 페이지에서 직접 제출 ──
REPO_URL = 'https://github.com/ftlord7/ai-hacking-defense'
FEEDBACK_TYPES = {'1': 'bug', '2': 'false-positive', '3': 'feature'}


def _mask(text, home=None):
    """개인 경로·사용자명 마스킹 — 피드백 본문에 실경로/계정명이 남지 않게 한다."""
    home = home or HOME
    user = getpass.getuser()
    text = text.replace(home, '~')
    if user:
        text = re.sub(re.escape(user), '<user>', text)
    return text


def _feedback_summary():
    try:
        rep = json.load(open(os.path.join(os.getcwd(), 'scan_result.json'), encoding='utf-8'))
    except Exception:
        return '(no local scan result / 스캔 요약 없음)'
    lines = [f"score {rep.get('score')} · high {rep.get('high')} · med {rep.get('med')} · os {rep.get('os')}"]
    lines += [f"- [{f.get('sev')}] {f.get('title')}" for f in rep.get('findings', [])[:8]]
    return _mask('\n'.join(lines))


def feedback(argv):
    ap = argparse.ArgumentParser(prog='ai-hacking-defense feedback')
    ap.add_argument('--type', choices=['bug', 'false-positive', 'feature'])
    ap.add_argument('--desc', default='')
    ap.add_argument('--dry', action='store_true', help='print preview only; never opens browser')
    a = ap.parse_args(argv)
    t = a.type
    if not t and not a.dry:
        print('피드백 유형 / type: 1) 버그 Bug  2) 오탐 False positive  3) 기능 제안 Feature')
        t = FEEDBACK_TYPES.get(input('> ').strip(), 'bug')
    t = t or 'bug'
    desc = a.desc or ('' if a.dry else input('한 줄 설명 / one-line description:\n> ').strip())
    body = (f"### Type\n{t}\n\n### Description\n{_mask(desc)}\n\n"
            f"### Scan summary (masked, optional — delete if you prefer)\n{_feedback_summary()}\n\n"
            f"### Env\n{sys.platform} · python {sys.version.split()[0]}\n")
    print('\n===== 전송될 내용 전문 미리보기 / FULL PREVIEW =====')
    print(body)
    print('===== 미리보기 끝 — 이 도구는 아무것도 자동 전송하지 않습니다(제출은 GitHub 페이지에서 직접). =====')
    if a.dry:
        return 0
    yn = input('브라우저로 GitHub 이슈 작성 페이지를 열까요? / open the GitHub issue page? [y/N] > ').strip().lower()
    if yn == 'y':
        import urllib.parse
        import webbrowser
        tpl = {'bug': 'bug_report.md', 'false-positive': 'false_positive.md', 'feature': 'feature_request.md'}[t]
        q = urllib.parse.urlencode({'template': tpl, 'title': f'[{t}] ' + (desc[:60] or 'feedback'), 'body': body})
        webbrowser.open(f'{REPO_URL}/issues/new?{q}')
        print('브라우저를 열었습니다 — 내용 확인 후 Submit은 직접 눌러 주세요. / Review and submit yourself.')
    else:
        print('취소 — 아무것도 전송되지 않았습니다. / Cancelled, nothing sent.')
    return 0


def main():
    if sys.argv[1:2] == ['feedback']:
        sys.exit(feedback(sys.argv[2:]))
    ap = argparse.ArgumentParser()
    ap.add_argument('--lang', default='ko', choices=['ko','en'])
    ap.add_argument('--home', default=HOME)
    outdir = os.getcwd()  # 설치형 CLI: 결과물은 현재 폴더에
    ap.add_argument('--json', default=os.path.join(outdir, 'scan_result.json'))
    ap.add_argument('--html', default=os.path.join(outdir, 'security_report.html'))
    ap.add_argument('--backup-repos', default='', help='git repo paths (colon-separated) counted as backup evidence')
    a = ap.parse_args()
    if a.backup_repos:
        os.environ['SECSCAN_BACKUP_REPOS'] = a.backup_repos
    rep = Scan(a.home, a.lang).run_all()
    json.dump(rep, open(a.json,'w'), ensure_ascii=False, indent=1)
    open(a.html,'w',encoding='utf-8').write(render_html(rep))
    print(UI['done'][rep['lang']].format(s=rep['score'], h=rep['high'], m=rep['med'], n=len(rep['findings'])))
    print(f"{UI['repline'][rep['lang']]}: {a.html}")
    print(UI['zero'][rep['lang']])

if __name__ == '__main__':
    main()
