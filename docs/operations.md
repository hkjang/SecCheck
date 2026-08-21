# SecCheck 운영 가이드

## 구성

```text
사용자 / Keycloak
        │ HTTPS
Reverse Proxy (TLS, allowlist)
        │
SecCheck container ───── PostgreSQL
        │
encrypted evidence volume
```

Redis나 외부 CDN은 필요하지 않습니다. UI, 한글 PDF 글꼴, 기본 workbook과 migration이 이미지에 포함됩니다.

## 첫 구동

1. PostgreSQL DB와 전용 최소권한 계정을 생성합니다.
2. 네 환경변수만 구성하고 `seccheck:v<version>`을 시작합니다.
3. `/ready`가 200인지 확인하고 bootstrap 관리자로 로그인합니다.
4. 관리자 설정에서 Keycloak Issuer, Client ID, Client Secret, Callback URL을 입력한 뒤 Discovery Test를 실행합니다.
5. OIDC 관리자를 확인한 다음 필요하면 bootstrap 계정을 비활성화합니다.
6. TLS 환경에서는 Secure Cookie를 활성화합니다.

## 백업과 복구 훈련

- PostgreSQL: 일간 Full + PITR/WAL, 백업 자체 암호화
- `/app/data`: DB 복구 시점과 일치하는 증적 암호문 백업
- `ENCRYPTION_KEY`: 데이터와 별도 보관, 이중 통제
- 관리자 설정: DB 백업에 포함
- 복구 훈련: 격리 환경에서 실제 로그인, 목록, 증적 다운로드와 SHA-256, PDF/Excel Export까지 확인

복구 성공 여부만 기록하지 말고 백업 식별자, 목표/실제 RPO·RTO, 검증한 심의/증적 ID, 해시 결과, 수행자와 승인자를 기록합니다.

## 관측과 장애 대응

- `/health`: 프로세스 생존
- `/ready`: DB 연결 포함 준비 상태
- `/metrics`: API 요청·지연·오류, DB 연결, 로그인, 활성 세션, 잠긴 계정, 증적 저장량·검사, 제출 실패, 알림 Job Prometheus 지표
- 관리자 > 서버 로그: 요청 ID 기반 구조화 로그
- 관리자 > 감사로그: 주요 행위와 체인 검증

OIDC 장애 시 기존 세션은 만료까지 동작합니다. 비활성화된 bootstrap 계정을 사용할 필요가 있으면 이중 승인으로 일시 활성화하고, 사용 후 세션 종료·재비활성화 및 감사 이벤트를 확인합니다.

이메일 알림은 SMTP Adapter와 PostgreSQL `FOR UPDATE SKIP LOCKED` 큐로 전송합니다. 최대 5회 지수형 재시도 후 `FAILED`가 되며 관리자 서버 로그와 `seccheck_jobs_failed` 지표에서 확인합니다. 인터넷이 없는 내부 SMTP 환경에서도 동작하며 가능한 경우 STARTTLS 또는 implicit TLS를 사용합니다.

## 계정 잠금과 로그인 보호

관리자 설정 > 접근 보안에서 조정합니다.

| 설정 | 기본값 | 설명 |
|---|---|---|
| `login_rate_limit_per_minute` | 10 | IP별 분당 비밀번호 로그인 시도 |
| `max_login_failures` | 5 | 계정 잠금까지 허용할 연속 실패 횟수. 0이면 잠금 미사용 |
| `lockout_minutes` | 15 | 자동 잠금 유지 시간 |
| `idle_timeout_minutes` | 0 | 유휴 세션 만료. 0이면 세션 시간까지 유지 |
| `trusted_proxies` | (비어 있음) | X-Forwarded-For를 신뢰할 Reverse Proxy IP/CIDR |

Reverse Proxy 뒤에 배치하는 구성에서는 `trusted_proxies`를 반드시 설정합니다. 비워 두면 모든 요청이 Proxy 한 IP로 집계되어 분당 요청 제한과 로그인 시도 제한, 감사로그의 접속 IP가 조직 전체 단위로 묶입니다. 설정된 Proxy에서 온 요청만 X-Forwarded-For를 오른쪽에서 왼쪽으로 따라가며 실제 클라이언트를 판별하므로, 클라이언트가 헤더를 위조해 제한을 우회할 수 없습니다.

잠금은 `LOGIN_LOCKED` 감사 이벤트로 남고 `seccheck_accounts_locked` 지표로 관측합니다. 잠금 시간 경과를 기다리지 않으려면 관리자 > 사용자 및 역할에서 해제하며, 해제도 감사로그에 기록됩니다. 잠금은 신규 로그인만 차단하고 이미 열려 있는 세션은 종료하지 않으므로, 제3자가 잠금을 이용해 사용자를 강제 로그아웃시킬 수 없습니다.

## 데이터 보존 자동 정리

서비스가 시작 1분 뒤부터 매시간 다음을 5,000행 단위로 정리합니다. 별도 cron이 필요하지 않습니다.

- 만료된 세션과 OIDC state
- `COMPLETED` 7일, `FAILED` 90일 경과 알림 Job
- 일반 설정 `retention_days`(기본 1825일)가 지난 서버 로그와 인앱 알림
- 잠금 시간이 지난 계정의 실패 카운터

감사로그는 해시 체인 검증을 위해 자동 삭제하지 않습니다. 정리 결과는 `maintenance` component 서버 로그에서 확인합니다.

## 업그레이드와 롤백

1. DB와 증적 볼륨을 함께 백업합니다.
2. 새 `seccheck:v<version>` image를 별도 검증 환경에서 시작합니다.
3. `/ready`, 로그인, 템플릿 Snapshot 불변성, 증적 다운로드를 확인합니다.
4. 운영 이미지만 교체합니다. migration은 시작 시 멱등 적용됩니다.
5. 애플리케이션 롤백 전에는 해당 버전이 이미 적용된 DB schema를 읽을 수 있는지 release note를 확인합니다.
