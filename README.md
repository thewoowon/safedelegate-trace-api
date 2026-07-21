# SafeDelegate Trace — API

**금융 AI 대리행위의 권한 통제 및 행동 증명 서비스** — 백엔드.

AI 에이전트와 금융 실행 사이에 놓이는 **통제·증거 계층**의 도메인 엔진입니다. 사용자가
위임한 권한 범위를 결정론적으로 강제하고, 고위험 행위에는 인간 승인을 요구하며, 모든
중대 단계에 대해 추가 전용(append-only)·해시 체인으로 연결된 **MSTS-Lite 트레이스**와
소비자용 **행동영수증**을 생성합니다. 허용·차단의 최종 판단은 LLM이 아니라
**결정론적 정책 엔진**이 수행합니다.

소비자·운영자용 웹 프런트엔드는 별도 저장소인 `safedelegate-trace`에 있습니다.

> **프로토타입 고지.** 모든 실행은 합성 데이터 위에서의 **시뮬레이션**입니다. 실제 계좌·거래·
> 개인정보를 사용하지 않으며, 프로덕션 금융 시스템이 아닙니다. 2026 금융 AI Challenge 제출용 MVP입니다.

---

## 설계 원칙 (경계 우선)

각 경계는 신뢰 경계이며 편의를 위해 우회하지 않습니다.

```
Web → API → Agent Orchestrator → Policy Gate → Tool Gateway → Execution Adapter
                                      │
                              Trace Engine → Receipt Service
```

- **Agent Orchestrator** — 요청을 타입드 실행 계획으로 변환. 도구를 직접 실행하거나 자기
  계획을 승인할 수 없음. 외부/검색 텍스트는 항상 *데이터*로 취급(명령이 아님).
- **Policy Gate** — 불변 정책 버전과 계획 해시에 대해 **20개 순서 규칙**을 실행. 결정·위험
  점수·규칙별 근거를 반환하고 **fail-closed**. 우선순위: `QUARANTINE > DENY > REQUIRE_APPROVAL > ALLOW`.
- **Tool Gateway** — 도구 이름을 허용목록에, 인자를 JSON Schema에 검증한 뒤 등록된 어댑터만
  호출. 차단된 호출도 기록.
- **Execution Adapters** — 시뮬레이션 전용. 멱등적이며 되돌림 메타데이터를 노출.
- **Trace Engine** — 정규 JSON(JCS 방식) + 트레이스별 SHA-256 해시 체인. 추가 전용.
- **Receipt Service** — 저장된 증거에서만 결정론적으로 영수증 생성(모델 기억으로 재생성하지 않음).

핵심 불변식: 승인은 정확한 계획 해시 + 정책 버전에만 유효하며, 계획이 바뀌면 이전 승인은
무효가 된다 · 만료·철회된 위임은 새 실행을 인가할 수 없다 · 위법한 상태 전이는 서버가 거부한다.

## 기술 스택

- **FastAPI** · **Pydantic v2** · **SQLAlchemy 2** · **Alembic**
- **SQLite**(로컬 기본) / **PostgreSQL**(배포) — `DATABASE_URL`로 전환, 드라이버는 psycopg 3
- 기본 결정론적 mock AI 어댑터 (`LLM_PROVIDER=mock`, `DEMO_MODE=true`) — 외부 AI 없이 데모 재현
- Python 3.12+

## 시작하기

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

- API: http://localhost:8000 · 문서(OpenAPI): http://localhost:8000/docs
- 헬스: `GET /health` · 데모 시드(멱등): `GET /v1/demo/bootstrap`

## 엔드포인트

| 그룹 | 엔드포인트 |
|---|---|
| 시스템 | `GET /health` · `GET /v1/demo/bootstrap` |
| 위임 | `GET /v1/agents` · `GET/POST /v1/delegations` · `GET /v1/delegations/{id}` · `POST …/revoke` |
| 생애주기 | `POST /v1/action-requests` · `POST …/{id}/plan` · `/evaluate` · `/approve` · `/reject` · `/execute` |
| 증거 | `GET /v1/traces/{trace_id}` · `GET /v1/receipts/{id}` · `/json` |
| 보안 랩 | `GET /v1/security/scenarios` · `POST …/{id}/run` |
| 운영 | `GET /v1/operator/events` · `/incidents` · `/incidents/{id}` · `POST …/interventions` |

변이 엔드포인트는 `Idempotency-Key`를 받고, 모든 응답은 `request_id`를 포함하며, 오류 본문은
표시 안전한 타입 구조입니다. 실행 엔드포인트는 현재 정책 평가와(해당 시) 유효한 승인 근거를 요구합니다.

## 정책 결정과 위험도

각 규칙은 기계 판독 근거 + 소비자/운영자용 평문 메시지를 반환합니다. 위험 점수(0–100)는
설명용이며 단독 인가 수단이 아닙니다 — 하드 정책 위반이 우선합니다.

## 품질 게이트

```bash
ruff check .              # 린트 + 임포트 정렬
mypy app benchmark        # strict 타이핑
pytest                    # 단위 · 통합 · 스키마 적합성 · 보안 회귀 · 벤치마크
python -m benchmark.runner   # 60케이스 벤치마크 실행 및 결과 export
```

**벤치마크(`benchmark/`)**: 20 허용 · 10 승인 · 10 차단 · 10 인젝션 · 5 유출 · 5 재사용 = 60
합성 케이스를 정책 엔진에 직접 통과시켜 지표를 산출합니다. 목표이자 현재 결과는
**정확도 100% · 오허용 0 · 공격 차단율 100%**. 결과는 `benchmark/results/`에 JSON·Markdown으로 저장됩니다.

## 구조

```text
app/
  config.py        # 타입드 설정 (환경변수)
  db/              # SQLAlchemy 엔진·세션·ORM 모델
  schemas/         # Pydantic v2 경계 모델 (schemas/*.json 미러)
  domain/
    orchestrator/  # 결정론적 mock 플래너
    policy/        # 20개 순서 규칙 · 위험 점수 · 결정 우선순위
    gateway/       # 허용목록 + JSON Schema 검증 도구 게이트웨이
    adapters/      # 시뮬레이션 실행 어댑터
    trace/         # 정규 JSON + SHA-256 해시 체인 (추가 전용)
    receipt/       # 증거 기반 결정론적 영수증
    scenarios.py   # 보안 랩 시나리오 러너
    lifecycle.py   # 서버 강제 상태 머신
  security/        # 인젝션 / 유출 / 경계 탐지기
  routers/         # 엔드포인트 (docs/12_API_CONTRACT.md 기준)
benchmark/         # 60케이스 정책 벤치마크 + export
schemas/           # 정본 JSON Schema (계약 원천 · 적합성 테스트)
fixtures/          # 합성 · 데모 표기 시드 데이터
tests/             # pytest
```

## 계약

`schemas/`의 JSON Schema가 단일 원천입니다. `tests/test_schema_conformance.py`는 픽스처가
스키마에서 벗어나면 실패합니다. 웹 저장소는 이를 Zod 검증기로 미러링합니다.

## 배포

Railway(+ 관리형 PostgreSQL)에 배포합니다. 절차와 환경변수(`TRACE_HASH_SECRET`,
`ALLOWED_ORIGINS` 등)는 [`DEPLOYMENT.md`](./DEPLOYMENT.md)를 참조하세요.

## 연구 기반 및 고지

본 서비스의 추적·통제 구조는 **WAIFC Young Academic Award 2026 Top 3 Finalist**로 선정된
저자의 연구 「Supervisory Observability for Agentic Finance」의 CSOL·MSTS를 제품 환경에 맞게
재설계한 것입니다. WAIFC는 논문을 선정했을 뿐 본 제품을 평가·보증하지 않았습니다. 본 MVP는
합성 데이터와 시뮬레이션 어댑터를 사용하며 실제 금융거래를 수행하지 않습니다.
