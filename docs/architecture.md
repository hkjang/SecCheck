# SecCheck 시스템 아키텍처 및 보안 설계 (Architecture)

`SecCheck`는 오프라인 폐쇄망에서 단일 바이너리와 PostgreSQL만으로 영구 지속되는 안정성을 보장하도록 설계되었습니다.

---

## 1. 시스템 아키텍처 다이어그램

```
      ┌─────────────────────────────────────────────────────────────┐
      │           Web Browser / Keycloak OIDC Client                │
      │        - React + TypeScript + Lucide UI                     │
      │        - Checklist Editor with Auto-Save & Evidence Upload  │
      │        - Hash Chain Verification & Multi-format Export      │
      └──────────────┬──────────────────────────────▲───────────────┘
                     │ REST API (/api/v1)           │ Static Assets &
                     │ JSON-RPC 2.0 (/mcp)          │ OpenAPI Spec
      ┌──────────────▼──────────────────────────────┴───────────────┐
      │                  SecCheck Daemon (Go 1.26)                  │
      │  - HTTP Server & Static Bundle Embed                        │
      │  - Rule Engine (Service Characteristic Evaluation)          │
      │  - Evidence Encryption Engine (AES-256-GCM Envelope)        │
      │  - Hash-Chaining Audit Engine (SHA-256 Immutability)        │
      │  - Background SMTP Worker (SKIP LOCKED Queue)               │
      └──────────────┬──────────────────────────────┬───────────────┘
                     │                              │
                     ▼                              ▼
      ┌─────────────────────────────┐┌──────────────────────────────┐
      │     PostgreSQL Database     ││   Encrypted Evidence Store   │
      │ - review_requests / items   ││ - UUID Filename Storage      │
      │ - templates / controls      ││ - Magic/MIME Validated       │
      │ - audit_logs (hash chained) ││ - AES-256-GCM Encrypted      │
      │ - notify_jobs (SKIP LOCKED) ││ - Multi-versioned            │
      └─────────────────────────────┘└──────────────────────────────┘
```

---

## 2. 핵심 보안 및 설계 불변 원칙

### 1. 템플릿-버전-스냅샷 3계층 분리 불변 모델
- **Template**: 체크리스트의 최상위 컨테이너
- **Version**: 게시(`PUBLISHED`) 시점의 불변 체크리스트 버전
- **Snapshot (Review Items)**: 심의 생성 시점에 배정된 항목들은 템플릿 원본이 추후 변경되더라도 결코 바뀌지 않는 독립 스냅샷으로 영구 보존됩니다.

### 2. 증적 파일 암호화 파이프라인 (Evidence Encryption)
1. **Magic/MIME 교차 검증**: 파일의 실제 바이트 헤더를 검사하여 확장자 변조 방지
2. **SHA-256 해시 계산**: 무결성 검증을 위한 해시 생성
3. **AES-256-GCM 봉투 암호화**: 사용자의 개인 데이터 키(`user_data_keys`)로 암호화 후 디스크에 UUID로 저장
4. **무중단 키 회전**: 개인 암호화 키를 회전해도 이전 버전 증적은 계속 안전하게 복호화 지원

### 3. 암호학적 해시 체인 감사로그 (Cryptographic Hash Chaining)
- 모든 행위는 `SHA256(prev_hash + event_id + timestamp + actor + payload)` 형식으로 연결되어 저장됩니다.
- DB 직접 변조 시 체인이 즉시 파손되어 무결성 검증 단계에서 적발됩니다.
