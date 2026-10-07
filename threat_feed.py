#!/usr/bin/env python3
"""위협 지능 피드 갱신기 — OSV DB + CISA KEV + EPSS (다운로드 전용).

- 🔴 이 모듈이 **유일하게 네트워크를 쓴다.** 스캐너(vulnscan.py)·트리아지(triage.py)는 네트워크 0.
  갱신기는 스캔 대상 파일(락파일 등)을 **읽지 않는다**(OSV는 더미 락파일로 DB 다운로드만 유도).
- 🔴 egress: 소스 FQDN 고정 allowlist · HTTPS GET 전용 · 리다이렉트도 allowlist 검증 · 요청에 환경정보 0.
  ※ OSV 단계는 osv-scanner 서브프로세스가 내려받으므로 FQDN 강제는 불가 → 문서화(OSV_FQDN)·결과 기록만.
- 검증 실패 시 이전 데이터 유지(원자적 교체) + 메타에 오류·연속실패 기록. 보고 전용(패치·설치 0).
- kill switch: ~/.cache/ai-hacking-defense/threat_feed.disabled (env AHD_THREATFEED_KILL 로 변경 가능)
- 출력: 시크릿 무출력. 결과 = 캐시 디렉터리 + threat_feed_meta.json.
"""
import argparse, datetime, gzip, hashlib, io, json, os, shutil, sys, tempfile, urllib.parse, urllib.request, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser('~')
FEED_DIR = os.path.join(HOME, '.cache', 'ai-hacking-defense', 'feed')
OSV_DB_DIR = os.path.join(HOME, '.cache', 'ai-hacking-defense', 'osv')
META_PATH = os.path.join(HERE, 'threat_feed_meta.json')
KILL_SWITCH = os.environ.get('AHD_THREATFEED_KILL') or os.path.join(
    os.path.expanduser('~'), '.cache', 'ai-hacking-defense', 'threat_feed.disabled')

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz'
OSV_FQDN = 'osv-vulnerabilities.storage.googleapis.com'   # osv-scanner 가 사용(서브프로세스·강제 불가)
ALLOW_FQDN = frozenset({'www.cisa.gov', 'epss.empiricalsecurity.com'})  # 이 모듈이 직접 접속 가능한 전부
MAX_BYTES = {'kev': 20 * 1024 * 1024, 'epss': 60 * 1024 * 1024}
TIMEOUT = 60
SOURCES = ('osv', 'kev', 'epss')


class EgressDenied(Exception):
    pass


def check_url(url):
    p = urllib.parse.urlparse(url)
    if p.scheme != 'https':
        raise EgressDenied(f'https 아님: {p.scheme}')
    if (p.hostname or '') not in ALLOW_FQDN:
        raise EgressDenied(f'allowlist 밖 호스트: {p.hostname}')
    return url


class _AllowRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)  # 리다이렉트 목적지도 allowlist
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_get(url, cap):
    """allowlist 검증 GET. 헤더에 식별정보 없음. 반환 bytes."""
    check_url(url)
    opener = urllib.request.build_opener(_AllowRedirect)
    req = urllib.request.Request(url, headers={'User-Agent': 'ai-hacking-defense-feed/1 (download-only)'})
    with opener.open(req, timeout=TIMEOUT) as r:
        buf = r.read(cap + 1)
    if len(buf) > cap:
        raise ValueError(f'크기 상한 초과(>{cap})')
    return buf


def now_iso():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def atomic_write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        shutil.copy2(path, path + '.prev')
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix='.tmp_')
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
    os.replace(tmp, path)


# ---- 검증/파싱 (순수 함수 — 모의 테스트 대상) ----
def validate_kev(raw):
    d = json.loads(raw)
    v = d.get('vulnerabilities')
    if not isinstance(v, list) or len(v) < 100 or not all('cveID' in x for x in v[:50]):
        raise ValueError('KEV 구조/규모 이상')
    return {'records': len(v), 'asof': (d.get('dateReleased') or '')[:10], 'catalog_version': d.get('catalogVersion') or ''}


def epss_iter(raw_gz_bytes):
    """(cve, epss, percentile) 스트림 + 헤더 메타. 반환: (meta_dict, generator)"""
    f = io.TextIOWrapper(gzip.GzipFile(fileobj=io.BytesIO(raw_gz_bytes)), encoding='utf-8')
    meta = {}
    header = None
    rows = []
    for line in f:
        line = line.strip()
        if not line:
            continue
        if line.startswith('#'):
            for part in line.lstrip('#').split(','):
                if ':' in part:
                    k, v = part.split(':', 1)
                    meta[k.strip()] = v.strip()
            continue
        if header is None:
            header = [h.strip() for h in line.split(',')]
            if header[:2] != ['cve', 'epss']:
                raise ValueError('EPSS 헤더 이상')
            continue
        p = line.split(',')
        if len(p) < 2 or not p[0].startswith('CVE-'):
            raise ValueError('EPSS 행 이상')
        rows.append((p[0], float(p[1])))
    return meta, rows


def validate_epss(raw):
    meta, rows = epss_iter(raw)
    if len(rows) < 10000:
        raise ValueError(f'EPSS 규모 이상({len(rows)})')
    if not all(0.0 <= e <= 1.0 for _, e in rows[:2000]):
        raise ValueError('EPSS 값 범위 이상')
    return {'records': len(rows), 'asof': (meta.get('score_date') or '')[:10], 'model_version': meta.get('model_version', '')}


# ---- 메타 ----
def load_meta(path=None):
    try:
        with open(path or META_PATH, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {'schema': 1, 'sources': {}}


def save_meta(meta, path=None):
    meta['updated_at'] = now_iso()
    atomic_write(path or META_PATH, (json.dumps(meta, ensure_ascii=False, indent=1) + '\n').encode('utf-8'))


def record(meta, name, ok, info=None, err=None):
    s = meta['sources'].setdefault(name, {})
    if ok:
        s.update(info or {})
        s['last_ok_ts'] = now_iso()
        s['fail_streak'] = 0
        s['last_error'] = None
    else:
        s['fail_streak'] = int(s.get('fail_streak', 0)) + 1
        s['last_error'] = f'{now_iso()} {str(err)[:200]}'  # 오류 문자열만 (시크릿 없음)


# ---- 소스별 갱신 ----
def update_file_source(name, url, validator, fetch, meta, feed_dir):
    fname = {'kev': 'kev.json', 'epss': 'epss.csv.gz'}[name]
    s = meta['sources'].setdefault(name, {})
    s['fqdn'] = urllib.parse.urlparse(url).hostname
    try:
        raw = fetch(url, MAX_BYTES[name])
        info = validator(raw)
        atomic_write(os.path.join(feed_dir, fname), raw)
        info.update({'sha256': sha256(raw), 'bytes': len(raw)})
        record(meta, name, True, info)
        return True
    except Exception as e:  # 검증 실패 → 이전 파일 유지
        record(meta, name, False, err=f'{type(e).__name__}: {e}')
        return False


def default_osv_runner(update_dir_files, cache_dir=None):
    """더미 락파일(임시 디렉터리)로 osv-scanner 의 오프라인 DB 다운로드만 유도. 자산 파일은 읽지 않음."""
    import subprocess
    if not shutil.which('osv-scanner'):
        return 127, 'osv-scanner 미설치'
    env = dict(os.environ)
    env['OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY'] = cache_dir or OSV_DB_DIR
    cmd = ['osv-scanner', 'scan', 'source', '--no-resolve', '--format', 'json', '--offline', '--download-offline-databases']
    for f in update_dir_files:
        cmd += ['-L', f]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
    except subprocess.TimeoutExpired:
        return 124, 'timeout'
    return r.returncode, (r.stderr or '')[-300:]


def osv_inventory(db_dir):
    files = []
    for dp, _, fns in os.walk(db_dir):
        for fn in fns:
            if fn.endswith('.zip'):
                p = os.path.join(dp, fn)
                h = hashlib.sha256()
                with open(p, 'rb') as f:
                    for chunk in iter(lambda: f.read(1 << 20), b''):
                        h.update(chunk)
                try:
                    with zipfile.ZipFile(p) as z:
                        n = len(z.namelist())
                except zipfile.BadZipFile:
                    raise ValueError(f'손상된 DB zip: {os.path.relpath(p, db_dir)}')
                files.append({'name': os.path.relpath(p, db_dir), 'sha256': h.hexdigest(), 'bytes': os.path.getsize(p), 'records': n})
    return sorted(files, key=lambda x: x['name'])


def update_osv(meta, runner=default_osv_runner, db_dir=OSV_DB_DIR):
    """빈 스테이징 디렉터리에 **새로 받아** 검증 후 교체(기존 캐시 재사용 시 '갱신된 척' 방지). 실패 시 기존 DB 유지."""
    s = meta['sources'].setdefault('osv', {})
    s['fqdn'] = OSV_FQDN
    s['fqdn_enforced'] = False  # 서브프로세스 — 정직 기록
    tmp = tempfile.mkdtemp(prefix='feedosv_')
    stage = os.path.join(tmp, 'stage')
    os.makedirs(stage)
    try:
        a = os.path.join(tmp, 'requirements.txt')
        b = os.path.join(tmp, 'package-lock.json')
        open(a, 'w').write('pip==0.0.0\n')
        open(b, 'w').write(json.dumps({'name': 'dummy', 'lockfileVersion': 3, 'packages': {
            '': {'name': 'dummy', 'version': '0.0.0'}, 'node_modules/dummy-pkg': {'version': '0.0.0'}}}))
        rc, err = runner([a, b], stage)
        if rc == 127 or rc == 124:
            raise RuntimeError(err)
        inv = osv_inventory(stage)
        if not inv:
            raise RuntimeError('OSV DB zip 없음(다운로드 실패)' + (f': {err.strip()[-120:]}' if err.strip() else ''))
        prev = s.get('files') or []
        if prev and len(inv) < len(prev):
            raise RuntimeError('새 DB 생태계 수가 이전보다 적음 → 교체 거부')
        # 원자적 교체: 기존은 .prev 로 보존
        os.makedirs(os.path.dirname(db_dir), exist_ok=True)
        if os.path.isdir(db_dir):
            shutil.rmtree(db_dir + '.prev', ignore_errors=True)
            os.replace(db_dir, db_dir + '.prev')
        shutil.move(stage, db_dir)
        inv = osv_inventory(db_dir)
        digest = hashlib.sha256(''.join(f['sha256'] for f in inv).encode()).hexdigest()
        record(meta, 'osv', True, {'records': sum(f['records'] for f in inv), 'sha256': digest, 'files': inv,
                                   'asof': datetime.date.today().isoformat(), 'fresh_download': True})
        return True
    except Exception as e:
        record(meta, 'osv', False, err=f'{type(e).__name__}: {e}')
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def update_all(which=SOURCES, fetch=http_get, osv_runner=default_osv_runner, feed_dir=FEED_DIR,
               meta_path=None, db_dir=OSV_DB_DIR, kill_switch=KILL_SWITCH):
    if os.path.exists(kill_switch):
        return {'status': 'DISABLED', 'results': {}}
    meta = load_meta(meta_path)
    results = {}
    if 'kev' in which:
        results['kev'] = update_file_source('kev', KEV_URL, validate_kev, fetch, meta, feed_dir)
    if 'epss' in which:
        results['epss'] = update_file_source('epss', EPSS_URL, validate_epss, fetch, meta, feed_dir)
    if 'osv' in which:
        results['osv'] = update_osv(meta, osv_runner, db_dir)
    meta['egress'] = {
        'direct_allowlist': sorted(ALLOW_FQDN), 'osv_subprocess_fqdn': OSV_FQDN,
        'method': 'HTTPS GET download-only', 'uploaded_data': 'none',
        'note': '스캐너·트리아지는 네트워크 0. 이 갱신기만 접속. OSV FQDN은 osv-scanner 서브프로세스(강제 불가·기록만).'}
    save_meta(meta, meta_path)
    return {'status': 'OK' if all(results.values()) else 'PARTIAL', 'results': results}


# ---- selftest (네트워크 0 · 가짜 fetch/runner) ----
def selftest():
    def kev_blob(n=150):
        return json.dumps({'catalogVersion': '2026.10.06', 'dateReleased': '2026-10-05T10:00:00Z',
                           'vulnerabilities': [{'cveID': f'CVE-2024-{i:04d}'} for i in range(n)]}).encode()

    def epss_blob(n=12000):
        lines = ['#model_version:v2026.01.01,score_date:2026-10-05T00:00:00+0000', 'cve,epss,percentile']
        lines += [f'CVE-2024-{i:05d},{(i % 100) / 100:.5f},0.5' for i in range(n)]
        return gzip.compress('\n'.join(lines).encode())

    # 1) allowlist
    for bad in ('http://www.cisa.gov/x', 'https://evil.example.com/x', 'https://www.cisa.gov.evil.com/x'):
        try:
            check_url(bad)
            raise AssertionError('allowlist 통과 — 실패:' + bad)
        except EgressDenied:
            pass
    check_url(KEV_URL); check_url(EPSS_URL)
    try:  # 리다이렉트 allowlist
        _AllowRedirect().redirect_request(urllib.request.Request(KEV_URL), None, 302, 'x', {}, 'https://evil.example.com/y')
        raise AssertionError('redirect 통과 — 실패')
    except EgressDenied:
        pass
    # 2) 정상 갱신 + 메타 + sha256
    tmp = tempfile.mkdtemp(); fd = os.path.join(tmp, 'feed'); mp = os.path.join(tmp, 'meta.json'); dbd = os.path.join(tmp, 'osv')
    calls = []

    def fetch_ok(url, cap):
        calls.append(url)
        return kev_blob() if 'cisa' in url else epss_blob()

    def osv_ok(files, cache):
        os.makedirs(os.path.join(cache, 'osv-scalibr', 'PyPI'), exist_ok=True)
        with zipfile.ZipFile(os.path.join(cache, 'osv-scalibr', 'PyPI', 'all.zip'), 'w') as z:
            z.writestr('GHSA-x.json', '{}')
        return 0, ''
    r = update_all(fetch=fetch_ok, osv_runner=osv_ok, feed_dir=fd, meta_path=mp, db_dir=dbd, kill_switch=os.path.join(tmp, 'no'))
    m = load_meta(mp)
    assert r['status'] == 'OK' and set(calls) == {KEV_URL, EPSS_URL}, r
    assert m['sources']['kev']['records'] == 150 and len(m['sources']['kev']['sha256']) == 64
    assert m['sources']['epss']['records'] == 12000 and m['sources']['epss']['asof'] == '2026-10-05'
    assert m['sources']['osv']['records'] == 1 and m['sources']['osv']['fqdn_enforced'] is False
    assert m['sources']['osv'].get('fresh_download') is True and os.path.isfile(os.path.join(dbd, 'osv-scalibr', 'PyPI', 'all.zip'))
    kev_before = open(os.path.join(fd, 'kev.json'), 'rb').read()
    # 3) 손상 응답 → 이전 파일 유지 + fail_streak
    r = update_all(which=('kev', 'epss'), fetch=lambda u, c: b'{broken', feed_dir=fd, meta_path=mp, db_dir=dbd, kill_switch=os.path.join(tmp, 'no'))
    m = load_meta(mp)
    assert r['status'] == 'PARTIAL' and open(os.path.join(fd, 'kev.json'), 'rb').read() == kev_before
    assert m['sources']['kev']['fail_streak'] == 1 and m['sources']['kev']['last_ok_ts'], m['sources']['kev']
    # 4) allowlist 밖 fetch 가 호출돼도 실패 처리(실제 http_get 경로)
    assert update_file_source('kev', 'https://evil.example.com/k.json', validate_kev, http_get, m, fd) is False
    # 5) OSV 실패(zip 없음) → 실패 기록 + 기존 DB 유지 (스테이징 방식)
    r = update_all(which=('osv',), osv_runner=lambda f, c: (1, 'x'), feed_dir=fd, meta_path=mp, db_dir=dbd, kill_switch=os.path.join(tmp, 'no'))
    assert r['results']['osv'] is False and os.path.isfile(os.path.join(dbd, 'osv-scalibr', 'PyPI', 'all.zip'))
    # 5b) 재갱신 시 이전 DB 가 .prev 로 보존
    assert update_all(which=('osv',), osv_runner=osv_ok, feed_dir=fd, meta_path=mp, db_dir=dbd, kill_switch=os.path.join(tmp, 'no'))['results']['osv']
    assert os.path.isdir(dbd + '.prev')
    # 6) kill switch
    ks = os.path.join(tmp, 'off'); open(ks, 'w').close()
    assert update_all(fetch=fetch_ok, feed_dir=fd, meta_path=mp, kill_switch=ks)['status'] == 'DISABLED'
    shutil.rmtree(tmp)
    print('threat_feed selftest PASS (6 groups)')


def main():
    ap = argparse.ArgumentParser(description='위협 지능 피드 갱신기 (다운로드 전용)')
    ap.add_argument('--update', action='store_true', help='네트워크 사용 — 명시 시에만')
    ap.add_argument('--source', action='append', choices=SOURCES)
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.update:
        print('사용: --update [--source osv|kev|epss] | --selftest  (메타:', META_PATH, ')')
        return
    r = update_all(tuple(a.source) if a.source else SOURCES)
    print(f"[위협피드 갱신] status={r['status']} " + ' '.join(f'{k}={"OK" if v else "FAIL"}' for k, v in r['results'].items()))
    m = load_meta()
    for k, s in m.get('sources', {}).items():
        print(f"  · {k}: asof={s.get('asof')} records={s.get('records')} fail_streak={s.get('fail_streak')} sha256={str(s.get('sha256'))[:12]}")
        if s.get('last_error'):
            print('    last_error:', s['last_error'])
    print('  egress: 직접=', sorted(ALLOW_FQDN), '+ osv-scanner=', OSV_FQDN, '· 업로드 0 · 메타:', META_PATH)


if __name__ == '__main__':
    main()
