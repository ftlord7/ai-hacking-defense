# Troubleshooting / 문제 해결

**`pip: command not found` / 파이썬이 없다고 나옵니다**
Python 3.8+을 설치하세요: https://www.python.org/downloads/ — 설치 후 `python3 -m pip install ai-hacking-defense`.

**`error: externally-managed-environment` (macOS Homebrew / Debian)**
가상환경을 쓰세요 / use a venv:
```bash
python3 -m venv ~/.venvs/ahd && ~/.venvs/ahd/bin/pip install ai-hacking-defense
~/.venvs/ahd/bin/ai-hacking-defense
```

**`ai-hacking-defense: command not found` (설치는 됐는데 명령이 없음)**
pip의 스크립트 폴더가 PATH에 없는 경우입니다. `python3 -m scan`이 아니라 다음으로 실행하세요:
```bash
python3 -m pip show -f ai-hacking-defense   # 설치 위치 확인
python3 -c "import scan; scan.main()"       # 직접 실행 (임시)
```

**리포트가 비어 보이거나 깨집니다 / Report looks broken**
브라우저에서 JavaScript가 꺼져 있으면 카드가 렌더되지 않습니다. 다른 브라우저로 열어 보세요.

**Permission denied 류 경고가 보입니다**
정상입니다 — 일반 사용자 권한으로 읽을 수 없는 항목은 건너뛰며, 그만큼 점검 범위 밖이라고 정직하게 처리됩니다. sudo로 돌릴 필요 없습니다(권장하지 않음).

**Windows/Linux에서 일부 항목이 "데이터 없음"**
전수 검증 전(실험적) 플랫폼입니다. 이슈로 알려주시면 정식 지원이 빨라집니다.

**그 외 / anything else**
`ai-hacking-defense feedback` — 전송 전문을 먼저 보여드리고, GitHub 제출은 직접 하십니다.
