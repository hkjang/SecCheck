// Screen captures for docs/USER_GUIDE.md and docs/ADMIN_GUIDE.md.
//
// Every picture in the guides is taken here, from a running SecCheck, so the
// guide never shows a screen that does not exist. The script seeds fake data
// (demo company, example.com addresses) so nothing real is in the frame.
//
// It is meant for a throwaway install. It creates users and reviews it does
// not delete, and it changes two settings for the duration of the run:
// workflow.allow_self_review and workflow.approval_enabled (so the single
// capture account can request, review and sign, and so the approval screens
// exist to be captured) and security.rate_limit_per_minute (a few dozen page
// loads in a row would otherwise trip the per-IP limit). Both are read first
// and put back, field for field, when the run ends -- even on failure.
//
// Usage (all four variables are required; none has a default):
//   SECCHECK_CAPTURE_URL=http://127.0.0.1:8080 \
//   SECCHECK_CAPTURE_USER=admin \
//   SECCHECK_CAPTURE_PASSWORD=... \
//   SECCHECK_CAPTURE_SEED_PASSWORD=... \
//   PLAYWRIGHT_BROWSERS_PATH=... node scripts/capture_all.js
//
// The target must be a loopback address unless SECCHECK_CAPTURE_ALLOW_REMOTE=1
// is set, so it cannot be pointed at a real deployment by accident.
const fs = require('fs');
const path = require('path');
const { chromium } = require(path.join(__dirname, '..', 'web', 'node_modules', '@playwright', 'test'));

const SCREENSHOT_DIR = path.join(__dirname, '..', 'docs', 'screenshots');

function required(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`${name} 환경 변수가 필요합니다. 캡처는 버려도 되는 설치에서만 실행하세요.`);
    process.exit(2);
  }
  return value;
}

const BASE_URL = required('SECCHECK_CAPTURE_URL').replace(/\/+$/, '');
const USER = required('SECCHECK_CAPTURE_USER');
const PASSWORD = required('SECCHECK_CAPTURE_PASSWORD');
const SEED_PASSWORD = required('SECCHECK_CAPTURE_SEED_PASSWORD');

{
  const host = new URL(BASE_URL).hostname;
  if (!['127.0.0.1', 'localhost', '::1', '[::1]'].includes(host) && process.env.SECCHECK_CAPTURE_ALLOW_REMOTE !== '1') {
    console.error(`${BASE_URL} 은 loopback 주소가 아닙니다. 실제 배포를 가리키는 것이 아닌지 확인하고 SECCHECK_CAPTURE_ALLOW_REMOTE=1 로 다시 실행하세요.`);
    process.exit(2);
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// A 1x1 PNG used as evidence on items that require an attachment.
const TINY_PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');

async function main() {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox', '--font-render-hinting=none'] });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR' });
  const page = await context.newPage();

  const capture = async (filename, options = {}) => {
    await sleep(options.wait ?? 700);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, filename), fullPage: options.fullPage ?? false });
    console.log(`📸 ${filename}`);
  };
  const goto = async (route, selector, options) => {
    await page.goto(`${BASE_URL}${route}`);
    await page.waitForSelector(selector, { timeout: 15000 });
    await page.waitForLoadState('networkidle').catch(() => undefined);
    if (options?.wait) await sleep(options.wait);
  };

  // ---- Sign in through the real form so the login screen is captured as-is.
  await page.goto(`${BASE_URL}/login`);
  await page.waitForSelector('text=SecCheck');
  await capture('login.png');
  await page.locator('input:not([type="password"])').first().fill(USER);
  await page.locator('input[type="password"]').fill(PASSWORD);
  await page.click('button:has-text("로그인")');
  await page.waitForSelector('text=안녕하세요', { timeout: 15000 });

  // ---- API client on the browser's session.
  const cookies = await context.cookies();
  const headers = { Cookie: cookies.map((c) => `${c.name}=${c.value}`).join('; ') };
  const me = await (await fetch(`${BASE_URL}/api/v1/me`, { headers })).json();
  headers['X-CSRF-Token'] = me.csrf_token;
  const api = async (method, route, body) => {
    const init = { method, headers: { ...headers } };
    if (body instanceof FormData) init.body = body;
    else if (body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
    let res = await fetch(`${BASE_URL}${route}`, init);
    // The per-IP limit is raised below, but the calls before that -- and the
    // restore after it -- run at the default. Wait the limit out rather than
    // fail with the settings half-restored.
    for (let attempt = 0; res.status === 429 && attempt < 8; attempt++) {
      await sleep(10000);
      res = await fetch(`${BASE_URL}${route}`, init);
    }
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON */ }
    if (!res.ok) {
      const err = new Error(`${method} ${route} → ${res.status} ${text.slice(0, 300)}`);
      err.status = res.status;
      throw err;
    }
    return json;
  };
  const tolerate = async (fn) => { try { return await fn(); } catch (e) { if (e.status === 409 || e.status === 422) return null; throw e; } };

  // ---- Read the settings before touching them; restored in finally.
  const settings = await api('GET', '/api/v1/admin/settings');
  const original = Object.fromEntries(['workflow', 'security'].map((key) => [key, settings.find((s) => s.key === key)?.value || {}]));
  const restoreSettings = async () => {
    for (const key of Object.keys(original)) await api('PUT', `/api/v1/admin/settings/${key}`, original[key]);
    console.log('↩ workflow·security 설정을 원래대로 되돌렸습니다.');
  };

  try {
    await api('PUT', '/api/v1/admin/settings/workflow', { ...original.workflow, allow_self_review: true, approval_enabled: true });
    await api('PUT', '/api/v1/admin/settings/security', { ...original.security, rate_limit_per_minute: 2000 });

    // ---- Seed users. Names, e-mails and departments are all made up.
    const users = [
      { username: 'hong', display_name: '홍길동', email: 'hong@example.com', department: '플랫폼개발팀', roles: ['REQUESTER'] },
      { username: 'kim', display_name: '김보안', email: 'kim@example.com', department: '정보보호팀', roles: ['SECURITY_REVIEWER', 'TEMPLATE_ADMIN'] },
      { username: 'lee', display_name: '이승인', email: 'lee@example.com', department: '정보보호팀', roles: ['APPROVER'] },
      { username: 'park', display_name: '박감사', email: 'park@example.com', department: '감사실', roles: ['AUDITOR'] },
    ];
    for (const u of users) await tolerate(() => api('POST', '/api/v1/admin/users', { ...u, password: SEED_PASSWORD }));
    // The capture account itself should not look like a bare bootstrap login.
    await api('PATCH', '/api/v1/me', { display_name: '데모 관리자', email: 'admin@example.com', department: '정보보호팀' });

    // ---- Seed reviews in every state the guide talks about. Approval is on,
    // so every review needs a named approver before it can be submitted; the
    // capture account takes that seat too (allowed by allow_self_review).
    const base = { builder_id: me.user.id, developer_id: me.user.id, approver_id: me.user.id, change_type: 'NEW' };
    const reviews = {
      approved: await api('POST', '/api/v1/review-requests', { ...base, service_name: '데모 회사 모바일 앱 푸시 서버', department: '모바일플랫폼팀', description: '앱 푸시 발송을 담당하는 내부 서버. 외부 푸시 게이트웨이와 연동합니다.', service_type: 'INTERNAL', exposure: 'INTERNAL', business_criticality: 'MEDIUM', planned_open_date: '2026-10-05', uses_cloud: true, uses_docker: true, external_integration: true }),
      reviewing: await api('POST', '/api/v1/review-requests', { ...base, service_name: '데모 회사 고객 포털 개편', department: '플랫폼개발팀', description: '대고객 웹 포털을 신규 구축합니다. 회원 가입·로그인, 개인정보 조회, 결제 내역 확인을 제공합니다.', service_type: 'EXTERNAL', exposure: 'EXTERNAL', business_criticality: 'CRITICAL', planned_open_date: '2026-11-02', has_admin_page: true, processes_personal_data: true, processes_credit_data: true, external_customer_service: true, uses_cloud: true, uses_docker: true, uses_kubernetes: true, external_integration: true, internet_access: true }),
      submitted: await api('POST', '/api/v1/review-requests', { ...base, service_name: '데모 회사 배치 정산 시스템 변경', department: '정산운영팀', description: '월 정산 배치의 데이터 소스를 신규 DW로 변경합니다.', service_type: 'BATCH', change_type: 'CHANGE', exposure: 'INTERNAL', business_criticality: 'HIGH', planned_open_date: '2026-10-20', uses_cloud: true }),
      draft: await api('POST', '/api/v1/review-requests', { ...base, service_name: '데모 회사 사내 인사 시스템 클라우드 이전', department: '인사기획팀', description: '온프레미스 인사 시스템을 퍼블릭 클라우드로 이전합니다. 임직원 개인정보를 처리합니다.', service_type: 'INTERNAL', change_type: 'CHANGE', exposure: 'INTERNAL', business_criticality: 'HIGH', planned_open_date: '2026-12-01', has_admin_page: true, processes_personal_data: true, uses_cloud: true, uses_kubernetes: true }),
      pending: await api('POST', '/api/v1/review-requests', { ...base, service_name: '데모 회사 파트너 정산 API', department: '제휴사업팀', description: '제휴 파트너사에 정산 내역을 제공하는 대외 API 입니다. 파트너별 API 키로 인증합니다.', service_type: 'EXTERNAL', exposure: 'EXTERNAL', business_criticality: 'HIGH', planned_open_date: '2026-10-28', external_customer_service: true, uses_cloud: true, uses_docker: true, external_integration: true, internet_access: true }),
      rejected: await api('POST', '/api/v1/review-requests', { ...base, service_name: '데모 회사 협력사 파일 전송 게이트웨이', department: '구매지원팀', description: '협력사와 견적·계약 문서를 주고받는 파일 전송 서비스입니다.', service_type: 'EXTERNAL', exposure: 'EXTERNAL', business_criticality: 'MEDIUM', planned_open_date: '2026-10-15', external_customer_service: true, external_integration: true, internet_access: true }),
    };

    const items = async (id) => api('GET', `/api/v1/review-requests/${id}/items`);
    const fillAll = async (review) => {
      const list = await items(review.id);
      await api('POST', `/api/v1/review-requests/${review.id}/responses/bulk`, {
        item_ids: list.map((i) => i.id), applicability: 'Y', self_assessment: 'COMPLIANT', overwrite: true,
        current_state: '사내 표준 보안 가이드에 따라 적용했으며 개발 환경에서 검증을 마쳤습니다.', action_plan: '운영 배포 전 보안 관제 로그 연동을 마무리할 예정입니다.',
      });
      for (const item of list.filter((i) => i.evidence_required)) {
        const form = new FormData();
        form.append('file', new Blob([TINY_PNG], { type: 'image/png' }), 'security-setting-screenshot.png');
        form.append('description', '설정 화면 캡처');
        await api('POST', `/api/v1/review-requests/${review.id}/items/${item.id}/evidences`, form);
      }
      return list;
    };
    const submit = (review) => api('POST', `/api/v1/review-requests/${review.id}/submit`, {});

    // Draft: a few items answered, one N/A, the rest untouched.
    {
      const list = await items(reviews.draft.id);
      await api('POST', `/api/v1/review-requests/${reviews.draft.id}/responses/bulk`, { item_ids: list.slice(0, 4).map((i) => i.id), applicability: 'Y', self_assessment: 'COMPLIANT', current_state: '사내 SSO(OIDC)와 역할 기반 접근 통제를 적용했습니다.', action_plan: '' });
      await api('PUT', `/api/v1/review-requests/${reviews.draft.id}/responses/${list[4].id}`, { applicability: 'N/A', self_assessment: 'N/A', na_reason: '이 시스템은 결제 정보를 다루지 않아 해당 요건이 적용되지 않습니다.', current_state: '', action_plan: '', answer: {} });
      await api('POST', `/api/v1/review-requests/${reviews.draft.id}/items/${list[0].id}/comments`, { body: '접근 통제 설계서 v2를 증적으로 첨부했습니다. 확인 부탁드립니다.' }).catch(() => undefined);
    }

    // Submitted: complete and waiting in the queue.
    await fillAll(reviews.submitted);
    await submit(reviews.submitted);

    // Reviewing: submitted, review begun, most items judged, one change request open.
    {
      const list = await fillAll(reviews.reviewing);
      await submit(reviews.reviewing);
      await api('POST', `/api/v1/review-requests/${reviews.reviewing.id}/begin-review`, {});
      await api('POST', `/api/v1/review-requests/${reviews.reviewing.id}/review-results/bulk`, { item_ids: list.slice(3).map((i) => i.id), result: 'COMPLIANT', evidence_adequacy: 'ADEQUATE', opinion: '증적으로 적용 사실을 확인했습니다.' });
      await api('PUT', `/api/v1/review-requests/${reviews.reviewing.id}/review-results/${list[0].id}`, { result: 'CONDITIONAL', evidence_adequacy: 'PARTIAL', opinion: '관리자 페이지 접근이 IP로 제한되어 있으나 2단계 인증이 아직 없습니다.', follow_up: '관리자 계정에 2단계 인증을 적용하고 결과를 보고합니다.', follow_up_due_date: '2026-12-15' });
      await api('PUT', `/api/v1/review-requests/${reviews.reviewing.id}/review-results/${list[1].id}`, { result: 'INSUFFICIENT', evidence_adequacy: 'INADEQUATE', opinion: '첨부된 캡처만으로는 암호화 알고리즘을 확인할 수 없습니다. 설정 파일 또는 코드 발췌를 첨부하세요.' });
      await api('POST', `/api/v1/review-requests/${reviews.reviewing.id}/change-requests`, { item_id: list[1].id, reason: '저장 데이터 암호화에 사용한 알고리즘과 키 길이를 확인할 수 있는 증적(설정 파일 발췌)을 추가해 주세요.', due_date: '2026-10-10' });
    }

    // Approved: the whole path to a decision. With approval_enabled on,
    // complete-review parks the review at APPROVAL_PENDING and the approver's
    // signature ends it.
    {
      const list = await fillAll(reviews.approved);
      await submit(reviews.approved);
      await api('POST', `/api/v1/review-requests/${reviews.approved.id}/begin-review`, {});
      await api('POST', `/api/v1/review-requests/${reviews.approved.id}/review-results/bulk`, { item_ids: list.map((i) => i.id), result: 'COMPLIANT', evidence_adequacy: 'ADEQUATE', opinion: '적용 사실을 확인했습니다.' });
      await api('POST', `/api/v1/review-requests/${reviews.approved.id}/complete-review`, { final_result: 'APPROVED', final_opinion: '전 항목 적합. 운영 배포를 승인합니다.' });
      await api('POST', `/api/v1/review-requests/${reviews.approved.id}/approve`, { comment: '검토 결과를 확인했습니다. 운영 배포를 승인합니다.' });
    }

    // Pending: reviewed with two conditions, waiting on the approver's desk.
    {
      const list = await fillAll(reviews.pending);
      await submit(reviews.pending);
      await api('POST', `/api/v1/review-requests/${reviews.pending.id}/begin-review`, {});
      await api('POST', `/api/v1/review-requests/${reviews.pending.id}/review-results/bulk`, { item_ids: list.slice(2).map((i) => i.id), result: 'COMPLIANT', evidence_adequacy: 'ADEQUATE', opinion: '적용 사실을 확인했습니다.' });
      await api('PUT', `/api/v1/review-requests/${reviews.pending.id}/review-results/${list[0].id}`, { result: 'CONDITIONAL', evidence_adequacy: 'PARTIAL', opinion: '파트너 API 키에 만료 기한이 없습니다.', follow_up: 'API 키에 유효기간(최대 1년)을 두고 만료 전 갱신 절차를 마련합니다.', follow_up_due_date: '2026-12-31' });
      await api('PUT', `/api/v1/review-requests/${reviews.pending.id}/review-results/${list[1].id}`, { result: 'CONDITIONAL', evidence_adequacy: 'PARTIAL', opinion: '정산 조회 API 의 호출 횟수 제한이 아직 적용되지 않았습니다.', follow_up: '파트너별 분당 호출 제한을 적용하고 초과 시 감사로그를 남깁니다.', follow_up_due_date: '2026-11-30' });
      await api('POST', `/api/v1/review-requests/${reviews.pending.id}/complete-review`, { final_result: 'CONDITIONAL', final_opinion: '조건부 승인. API 키 유효기간과 호출 제한을 기한 내 적용하는 조건입니다.' });
    }

    // Rejected: the approver sent it back.
    {
      const list = await fillAll(reviews.rejected);
      await submit(reviews.rejected);
      await api('POST', `/api/v1/review-requests/${reviews.rejected.id}/begin-review`, {});
      await api('POST', `/api/v1/review-requests/${reviews.rejected.id}/review-results/bulk`, { item_ids: list.slice(2).map((i) => i.id), result: 'COMPLIANT', evidence_adequacy: 'ADEQUATE', opinion: '적용 사실을 확인했습니다.' });
      await api('PUT', `/api/v1/review-requests/${reviews.rejected.id}/review-results/${list[0].id}`, { result: 'NON_COMPLIANT', evidence_adequacy: 'INADEQUATE', opinion: '전송 구간이 평문 FTP 입니다. 협력사 문서에는 계약 금액이 포함됩니다.' });
      await api('PUT', `/api/v1/review-requests/${reviews.rejected.id}/review-results/${list[1].id}`, { result: 'INSUFFICIENT', evidence_adequacy: 'INADEQUATE', opinion: '업로드 파일에 대한 악성코드 검사 증적이 없습니다.' });
      await api('POST', `/api/v1/review-requests/${reviews.rejected.id}/complete-review`, { final_result: 'REJECTED', final_opinion: '전송 구간 암호화와 업로드 파일 검사가 확인되지 않아 반려합니다.' });
      await api('POST', `/api/v1/review-requests/${reviews.rejected.id}/reject`, { comment: '평문 전송은 허용할 수 없습니다. SFTP 또는 HTTPS 로 전환한 뒤 재심의를 요청하세요.' });
    }

    // Keys and a control so the admin screens are not empty.
    await tolerate(() => api('POST', '/api/v1/me/api-keys', { name: 'CI 파이프라인 연동', scopes: ['read'] }));
    await tolerate(() => api('POST', '/api/v1/security-controls', { code: 'DEMO-AC-01', title: '관리자 페이지 2단계 인증', description: '관리자 화면 접근 시 비밀번호 외 일회용 코드를 추가로 요구한다.' }));

    // ---- User screens.
    await goto('/', 'text=안녕하세요', { wait: 1000 });
    await capture('dashboard.png');

    await goto('/reviews', '.page-title', { wait: 800 });
    await capture('reviews-list.png');

    await goto('/reviews/new', 'text=신규 보안성 심의 요청', { wait: 800 });
    await capture('review-new.png');

    await goto(`/reviews/${reviews.draft.id}`, '.review-layout', { wait: 1500 });
    await capture('review-detail.png');
    await page.locator('.checklist-summary').first().click();
    await capture('review-item-editor.png', { wait: 1000 });
    const precheck = page.locator('button:has-text("제출 전 점검")').first();
    if (await precheck.count()) {
      await precheck.click();
      await page.waitForSelector('.modal', { timeout: 5000 }).catch(() => undefined);
      await capture('review-precheck.png');
      await page.keyboard.press('Escape');
    }
    const ruleButton = page.locator('button:has-text("자동 배정 조정")').first();
    if (await ruleButton.count()) {
      await ruleButton.click();
      await page.waitForSelector('text=자동 배정 결과 조정', { timeout: 5000 }).catch(() => undefined);
      await capture('review-rule-override.png', { wait: 1000 });
      await page.keyboard.press('Escape');
    }

    await goto(`/reviews/${reviews.reviewing.id}`, '.review-layout', { wait: 1500 });
    await capture('review-detail-reviewing.png');
    await page.locator('.checklist-summary').nth(1).click();
    await page.waitForSelector('text=보안 담당자 검토', { timeout: 5000 }).catch(() => undefined);
    await page.locator('text=보안 담당자 검토').first().scrollIntoViewIfNeeded().catch(() => undefined);
    await capture('review-item-verdict.png', { wait: 1000 });

    // ---- The approver's desk: waiting, the brief above the two buttons, the
    // signature dialog, and what a rejection leaves behind.
    await goto(`/reviews/${reviews.pending.id}`, '.review-layout', { wait: 1500 });
    await capture('review-approval-pending.png');
    const brief = page.locator('text=결재 전 확인').first();
    if (await brief.count()) {
      await brief.scrollIntoViewIfNeeded();
      await capture('review-approval-brief.png', { wait: 500 });
      await page.evaluate(() => window.scrollTo(0, 0));
    }
    const approveButton = page.locator('button:has-text("최종 승인")').first();
    if (await approveButton.count()) {
      await approveButton.click();
      await page.waitForSelector('.modal', { timeout: 5000 }).catch(() => undefined);
      await page.locator('.modal textarea').first().fill('후속조치 기한을 확인했습니다. 조건부로 승인합니다.').catch(() => undefined);
      await capture('review-approval-modal.png', { wait: 500 });
      await page.keyboard.press('Escape');
    }

    await goto(`/reviews/${reviews.rejected.id}`, '.review-layout', { wait: 1500 });
    const outcome = page.locator('text=심의 결론').first();
    if (await outcome.count()) await outcome.scrollIntoViewIfNeeded();
    await capture('review-detail-rejected.png', { wait: 500 });

    await goto('/security', '.page-title', { wait: 800 });
    await capture('security-queue.png');

    await goto('/notifications', 'text=알림', { wait: 800 });
    await capture('notifications.png');

    await goto('/profile', 'text=개인 프로필', { wait: 600 });
    await capture('profile.png');
    await goto('/profile/security', 'text=계정 보안', { wait: 600 });
    await capture('profile-security.png');
    await goto('/profile/keys', 'text=개인 키 관리', { wait: 600 });
    await capture('profile-keys.png');

    await goto('/reports', 'text=심의 리포트', { wait: 1200 });
    await capture('reports.png');

    // ---- Checklist administration.
    await goto('/templates', '.page-title', { wait: 800 });
    await capture('templates-list.png');
    const templates = await api('GET', '/api/v1/templates');
    const first = Array.isArray(templates) ? templates[0] : templates?.items?.[0];
    if (first) {
      await goto(`/templates/${first.id}`, '.page-title', { wait: 1200 });
      await capture('template-detail.png');
    }
    await goto('/templates/import', 'text=Excel', { wait: 800 });
    await capture('templates-import.png');
    await goto('/templates/rules', 'text=Rule Engine 시뮬레이터', { wait: 800 });
    await capture('templates-rules.png');
    await goto('/controls', 'text=통합 Security Controls', { wait: 800 });
    await capture('controls.png');
    await goto('/integrations', 'text=API · MCP 연계', { wait: 800 });
    await capture('integrations.png');

    // ---- Administration.
    await goto('/admin/users', 'text=사용자 및 역할', { wait: 800 });
    await capture('admin-users.png');

    await goto('/admin/settings', 'text=서비스 관리자 설정', { wait: 800 });
    await capture('admin-settings-general.png');
    for (const [label, file] of [['검토·승인', 'admin-settings-workflow.png'], ['Keycloak OIDC', 'admin-settings-oidc.png'], ['파일 보안', 'admin-settings-upload.png'], ['접근 보안', 'admin-settings-security.png'], ['알림', 'admin-settings-notification.png']]) {
      const tab = page.locator(`button.tab:has-text("${label}")`).first();
      if (await tab.count()) { await tab.click(); await capture(file, { wait: 500 }); }
    }

    await goto('/admin/audit', 'text=감사로그', { wait: 1000 });
    await capture('admin-audit.png');
    await goto('/admin/logs', 'text=서버 로그', { wait: 1000 });
    await capture('admin-logs.png');
    await goto('/admin/jobs', 'text=작업 큐', { wait: 800 });
    await capture('admin-jobs.png');
    await goto('/admin/api-keys', 'text=API 키', { wait: 800 });
    await capture('admin-api-keys.png');
    await goto('/admin/system', 'text=시스템 정보', { wait: 1000 });
    await capture('admin-system.png');
  } finally {
    await restoreSettings().catch((e) => console.error('설정 복원 실패:', e.message));
    await browser.close();
  }
  console.log('🎉 캡처가 끝났습니다:', SCREENSHOT_DIR);
}

main().catch((err) => {
  console.error('❌ 캡처 실패:', err);
  process.exit(1);
});
