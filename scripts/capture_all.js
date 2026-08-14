const fs = require('fs');
const path = require('path');
const { chromium } = require(path.join(__dirname, '..', 'web', 'node_modules', '@playwright', 'test'));

const SCREENSHOT_DIR = path.join(__dirname, '..', 'docs', 'screenshots');
if (!fs.existsSync(SCREENSHOT_DIR)) {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
}

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function capture(page, filename, options = {}) {
  const filepath = path.join(SCREENSHOT_DIR, filename);
  await sleep(600);
  await page.screenshot({ path: filepath, fullPage: options.fullPage ?? false });
  console.log(`📸 Captured: ${filename}`);
}

async function main() {
  console.log('🚀 Starting SecCheck Automated E2E CRU Testing & Screenshot Pipeline...');

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--font-render-hinting=none'],
  });

  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    locale: 'ko-KR',
  });

  const page = await context.newPage();
  const BASE_URL = 'http://127.0.0.1:8080';

  // 1. Login Page
  console.log('--- 1. Login Page ---');
  await page.goto(`${BASE_URL}/login`);
  await page.waitForSelector('text=SecCheck');
  await capture(page, '01_login.png');

  // Perform Login
  await page.locator('input[autoComplete="username"], input:not([type="password"])').first().fill('admin');
  await page.locator('input[type="password"]').fill('admin12345678');
  await page.click('button:has-text("로그인")');
  await page.waitForSelector('text=안녕하세요', { timeout: 10000 });
  await sleep(1000);

  // Setup rich initial seed data via API
  console.log('--- Setting up Seed Data via API ---');
  const cookies = await context.cookies();
  const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
  const authHeaders = { Cookie: cookieHeader, 'Content-Type': 'application/json' };

  // Fetch CSRF token
  const meRes = await (await fetch(`${BASE_URL}/api/v1/me`, { headers: authHeaders })).json();
  const csrfToken = meRes.csrf_token;
  authHeaders['X-CSRF-Token'] = csrfToken;

  // Create Review Request 1
  const review1Res = await (await fetch(`${BASE_URL}/api/v1/review-requests`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      service_name: '2026 하반기 신규 AI 대고객 상담 서비스',
      department: 'AI혁신플랫폼팀',
      description: '사내 LLM Gateway 및 대고객 모바일 챗봇 인터페이스를 연동하는 2026 핵심 비즈니스 서비스입니다.',
      service_type: 'EXTERNAL',
      change_type: 'NEW',
      builder_id: meRes.user.id,
      developer_id: meRes.user.id,
      planned_open_date: '2026-09-30',
      exposure: 'EXTERNAL',
      business_criticality: 'CRITICAL',
      has_admin_page: true,
      processes_personal_data: true,
      processes_credit_data: true,
      external_customer_service: true,
      uses_cloud: true,
      uses_docker: true,
      uses_kubernetes: true,
      external_integration: true,
      internet_access: true,
    }),
  })).json();
  const reviewId = review1Res.id;

  // Create Review Request 2
  await fetch(`${BASE_URL}/api/v1/review-requests`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      service_name: '엔터프라이즈 클라우드 네이티브 마이크로서비스 인프라',
      department: '인프라보안운영팀',
      description: '사내 쿠버네티스 멀티클러스터 기반 코어 백엔드 및 서비스 메시 인프라입니다.',
      service_type: 'INTERNAL',
      change_type: 'NEW',
      builder_id: meRes.user.id,
      developer_id: meRes.user.id,
      planned_open_date: '2026-10-15',
      exposure: 'INTERNAL',
      business_criticality: 'HIGH',
      has_admin_page: true,
      uses_cloud: true,
      uses_docker: true,
      uses_kubernetes: true,
    }),
  });

  // Seed response on some checklist items in Review 1
  if (reviewId) {
    const items = await (await fetch(`${BASE_URL}/api/v1/review-requests/${reviewId}/items`, { headers: authHeaders })).json();
    if (Array.isArray(items) && items.length > 0) {
      // Fill Item 0
      await fetch(`${BASE_URL}/api/v1/review-requests/${reviewId}/responses/${items[0].id}`, {
        method: 'PUT',
        headers: authHeaders,
        body: JSON.stringify({
          applicability: 'Y',
          self_assessment: 'COMPLIANT',
          current_state: '사내 SSO 및 OAuth2 PKCE 표준 인증 흐름을 적용 완료하였으며 테스트 검증을 완료했습니다.',
          action_plan: '운영 배포 전 보안 관제 로그 연동 예정',
          na_reason: '',
          answer: {},
        }),
      });

      // Fill Item 1 (N/A)
      if (items[1]) {
        await fetch(`${BASE_URL}/api/v1/review-requests/${reviewId}/responses/${items[1].id}`, {
          method: 'PUT',
          headers: authHeaders,
          body: JSON.stringify({
            applicability: 'N/A',
            self_assessment: 'N/A',
            current_state: '해당 서비스는 신용카드 번호를 직접 저장하지 않고 PG사 토큰 방식을 사용함.',
            na_reason: 'PG사 토큰 기반 결제로 사내 DB에 신용카드 원문 번호 저장이 불필요함.',
            action_plan: '',
            answer: {},
          }),
        });
      }
    }
  }

  // 2. Dashboard
  console.log('--- 2. Dashboard ---');
  await page.goto(`${BASE_URL}/`);
  await page.waitForSelector('text=안녕하세요');
  await sleep(1000);
  await capture(page, '02_dashboard.png');

  // 3. Reviews List
  console.log('--- 3. Reviews List ---');
  await page.goto(`${BASE_URL}/reviews`);
  await page.waitForSelector('text=심의 목록');
  await sleep(1000);
  await capture(page, '03_reviews_list.png');

  // 4. New Review Form
  console.log('--- 4. New Review Form ---');
  await page.goto(`${BASE_URL}/reviews/new`);
  await page.waitForSelector('text=신규 보안성 심의 요청');
  await sleep(1000);
  await capture(page, '04_new_review_form.png');

  // 5. Review Detail & Checklist
  console.log('--- 5. Review Detail & Checklist ---');
  if (reviewId) {
    await page.goto(`${BASE_URL}/reviews/${reviewId}`);
    await page.waitForSelector('.review-layout');
    await sleep(1500);
    await capture(page, '05_review_detail_checklist.png');

    // 6. Review Item Editor (Expanded)
    console.log('--- 6. Review Item Editor ---');
    const firstItem = page.locator('.checklist-summary').first();
    await firstItem.click();
    await sleep(1000);
    await capture(page, '06_review_item_editor.png');

    // 7. Rule Override Modal
    console.log('--- 7. Rule Override Modal ---');
    const ruleBtn = page.locator('button:has-text("자동 배정 조정")').first();
    if (await ruleBtn.count() > 0) {
      await ruleBtn.click();
      await page.waitForSelector('.modal');
      await capture(page, '09_review_rule_override_modal.png');
      await page.keyboard.press('Escape');
      await sleep(500);
    }
  }

  // 8. Security Reviews Queue
  console.log('--- 8. Security Reviews Queue ---');
  await page.goto(`${BASE_URL}/security`);
  await page.waitForSelector('text=보안 검토 Queue');
  await sleep(1000);
  await capture(page, '10_security_reviews.png');

  // 9. Unified Security Controls
  console.log('--- 9. Unified Security Controls ---');
  await page.goto(`${BASE_URL}/controls`);
  await page.waitForSelector('text=통합 Security Controls');
  await sleep(1000);
  await capture(page, '11_controls_catalog.png');

  // 10. Templates List
  console.log('--- 10. Templates List ---');
  await page.goto(`${BASE_URL}/templates`);
  await page.waitForSelector('text=체크리스트 템플릿');
  await sleep(1000);
  await capture(page, '12_templates_list.png');

  // 11. Template Detail
  console.log('--- 11. Template Detail ---');
  const templates = await (await fetch(`${BASE_URL}/api/v1/templates`, { headers: authHeaders })).json();
  if (Array.isArray(templates) && templates[0]) {
    await page.goto(`${BASE_URL}/templates/${templates[0].id}`);
    await page.waitForSelector('.page-title');
    await sleep(1200);
    await capture(page, '13_template_detail.png');
  }

  // 12. Excel Import Wizard
  console.log('--- 12. Excel Import Wizard ---');
  await page.goto(`${BASE_URL}/templates/import`);
  await page.waitForSelector('text=Excel 가져오기');
  await sleep(1000);
  await capture(page, '14_excel_import_wizard.png');

  // 13. Personal Profile
  console.log('--- 13. Personal Profile ---');
  await page.goto(`${BASE_URL}/profile`);
  await page.waitForSelector('text=개인 프로필');
  await sleep(1000);
  await capture(page, '15_personal_profile.png');

  // 14. API Keys & Encryption Keys
  console.log('--- 14. API Keys & Encryption Keys ---');
  await page.goto(`${BASE_URL}/profile/keys`);
  await page.waitForSelector('text=개인 키 관리');
  await sleep(1000);
  await capture(page, '16_api_keys_and_encryption.png');

  // 15. In-App Notifications
  console.log('--- 15. In-App Notifications ---');
  await page.goto(`${BASE_URL}/notifications`);
  await page.waitForSelector('text=알림');
  await sleep(1000);
  await capture(page, '17_notifications.png');

  // 16. Integrations & MCP
  console.log('--- 16. Integrations & MCP ---');
  await page.goto(`${BASE_URL}/integrations`);
  await page.waitForSelector('text=API · MCP 연계');
  await sleep(1000);
  await capture(page, '18_integrations_mcp.png');

  // 17. Admin: Users
  console.log('--- 17. Admin: Users ---');
  await page.goto(`${BASE_URL}/admin/users`);
  await page.waitForSelector('text=사용자 및 역할');
  await sleep(1000);
  await capture(page, '19_admin_users.png');

  // 18. Admin: Settings (All Tabs)
  console.log('--- 18. Admin: Settings ---');
  await page.goto(`${BASE_URL}/admin/settings`);
  await page.waitForSelector('text=서비스 관리자 설정');
  await capture(page, '20_admin_settings_general.png');

  // Tab: Workflow
  const wfTab = page.locator('button.tab:has-text("검토·승인")').first();
  if (await wfTab.count() > 0) {
    await wfTab.click();
    await sleep(500);
    await capture(page, '23_admin_settings_workflow.png');
  }

  // Tab: OIDC
  const oidcTab = page.locator('button.tab:has-text("Keycloak OIDC")').first();
  if (await oidcTab.count() > 0) {
    await oidcTab.click();
    await sleep(500);
    await capture(page, '21_admin_settings_oidc.png');
  }

  // Tab: Upload
  const uploadTab = page.locator('button.tab:has-text("파일 보안")').first();
  if (await uploadTab.count() > 0) {
    await uploadTab.click();
    await sleep(500);
    await capture(page, '24_admin_settings_upload.png');
  }

  // Tab: Security
  const secTab = page.locator('button.tab:has-text("접근 보안")').first();
  if (await secTab.count() > 0) {
    await secTab.click();
    await sleep(500);
    await capture(page, '22_admin_settings_security.png');
  }

  // Tab: Notification (SMTP)
  const notiTab = page.locator('button.tab:has-text("알림")').first();
  if (await notiTab.count() > 0) {
    await notiTab.click();
    await sleep(500);
    await capture(page, '22_admin_settings_smtp.png');
  }

  // 19. Admin: Hash Chain Audit Logs
  console.log('--- 19. Admin: Hash Chain Audit Logs ---');
  await page.goto(`${BASE_URL}/admin/audit`);
  await page.waitForSelector('text=감사로그');
  await sleep(1000);
  await capture(page, '25_admin_audit_hashchain.png');

  // 20. Admin: Server Logs
  console.log('--- 20. Admin: Server Logs ---');
  await page.goto(`${BASE_URL}/admin/logs`);
  await page.waitForSelector('text=서버 로그');
  await sleep(1000);
  await capture(page, '26_admin_logs.png');

  await browser.close();
  console.log('🎉 SecCheck Full Screenshot Pipeline Completed Successfully!');
}

main().catch((err) => {
  console.error('❌ Automation script failed:', err);
  process.exit(1);
});
