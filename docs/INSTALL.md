# 설치 가이드 (한국어) — AI-Hacking Self-Audit

> 외부로 단 1바이트도 보내지 않는 개인 보안 자가진단 도구입니다. 설치부터 첫 리포트까지 3분이면 됩니다.
> English guide: [INSTALL_EN.md](INSTALL_EN.md)

## 1. 준비물
- Python 3.8 이상 (`python3 --version` 으로 확인)
- 그 외 의존성 **0** — 표준 라이브러리만 사용합니다.

## 2. 설치

### 방법 A — pip (권장)
```bash
pip install ai-hacking-defense
```

### 방법 B — 소스에서
```bash
git clone https://github.com/ftlord7/ai-hacking-defense
cd ai-hacking-defense
pip install .
```

## 3. 첫 스캔
```bash
ai-hacking-defense              # 한국어 리포트
ai-hacking-defense --lang en    # English report
```
현재 폴더에 두 파일이 생깁니다:
- `security_report.html` — 브라우저로 여는 리포트(아래 그림)
- `scan_result.json` — 같은 내용의 데이터 파일

![리포트 예시](img/report_sample.png)

## 4. 리포트 열기
```bash
open security_report.html        # macOS
# Windows: start security_report.html / Linux: xdg-open security_report.html
```

## 5. 플랫폼 안내 (정직 고지)
- **macOS**: 전 점검 항목 검증 완료 — 현재 정식 지원.
- **Windows / Linux**: 일부 점검이 플랫폼 분기로 동작하지만 **아직 전수 검증 전(실험적)** 입니다. 동작 결과를 이슈로 알려주시면 정식 지원이 빨라집니다.

## 6. 제거
```bash
pip uninstall ai-hacking-defense
```
리포트 파일 2개만 지우면 흔적이 남지 않습니다. 이 도구는 설정을 바꾸지 않고, 백그라운드에 상주하지 않습니다.

## 문제가 생기면
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) → 해결 안 되면 `ai-hacking-defense feedback` (전송 내용을 먼저 전부 보여드리고, 제출은 GitHub에서 직접 하십니다).
