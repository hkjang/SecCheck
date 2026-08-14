const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { chromium } = require(path.join(__dirname, '..', 'web', 'node_modules', '@playwright', 'test'));

const VIDEO_TMP_DIR = path.join(__dirname, '..', 'tmp_video_record');
const OUTPUT_MP4 = path.join(__dirname, '..', 'docs', 'seccheck_overview.mp4');
const FFMPEG_BIN = path.join(__dirname, '..', 'bin', 'ffmpeg');

if (!fs.existsSync(VIDEO_TMP_DIR)) {
  fs.mkdirSync(VIDEO_TMP_DIR, { recursive: true });
}

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function setSubtitle(page, stepNum, title, desc) {
  await page.evaluate(({ stepNum, title, desc }) => {
    let el = document.getElementById('seccheck-video-subtitle');
    if (!el) {
      el = document.createElement('div');
      el.id = 'seccheck-video-subtitle';
      el.style.position = 'fixed';
      el.style.bottom = '28px';
      el.style.left = '50%';
      el.style.transform = 'translateX(-50%)';
      el.style.background = 'rgba(4, 47, 46, 0.94)';
      el.style.backdropFilter = 'blur(16px)';
      el.style.border = '2px solid #0f766e';
      el.style.borderRadius = '16px';
      el.style.padding = '14px 32px';
      el.style.color = '#ffffff';
      el.style.boxShadow = '0 16px 48px rgba(0, 0, 0, 0.6)';
      el.style.zIndex = '999999';
      el.style.maxWidth = '960px';
      el.style.width = '85%';
      el.style.textAlign = 'center';
      el.style.fontFamily = "'Pretendard', sans-serif";
      el.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
      document.body.appendChild(el);
    }
    el.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:4px;">
        <span style="background:#2dd4bf;color:#042f2e;font-weight:900;font-size:12px;padding:2px 8px;border-radius:6px;">${stepNum}</span>
        <span style="font-size:19px;font-weight:850;color:#2dd4bf;letter-spacing:-0.3px;">${title}</span>
      </div>
      <div style="font-size:15px;color:#ccfbf1;font-weight:550;line-height:1.5;">${desc}</div>
    `;
  }, { stepNum, title, desc });
}

async function smoothScroll(page, distance, steps = 10) {
  for (let i = 0; i < steps; i++) {
    await page.evaluate((d) => window.scrollBy(0, d), distance / steps);
    await sleep(60);
  }
}

async function main() {
  console.log('🎬 Starting SecCheck Playwright High-Definition 3-Minute Video Recording...');
  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--font-render-hinting=none'],
  });

  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    recordVideo: {
      dir: VIDEO_TMP_DIR,
      size: { width: 1920, height: 1080 },
    },
    locale: 'ko-KR',
  });

  const page = await context.newPage();
  const BASE_URL = 'http://127.0.0.1:8080';

  // SCENE 1: Intro Slide (12s)
  console.log('🎥 Scene 1: Intro Slide...');
  const introPath = 'file://' + path.join(__dirname, 'video_slides', 'intro.html');
  await page.goto(introPath);
  await sleep(12000);

  // SCENE 2: Login Page (10s)
  console.log('🎥 Scene 2: Login Page...');
  await page.goto(`${BASE_URL}/login`);
  await setSubtitle(
    page,
    '01 / 08',
    '인증 및 엔터프라이즈 SSO (Authentication & OIDC)',
    '부트스트랩 관리자 인증 및 Keycloak OIDC Discovery 기반 SSO를 지원합니다.'
  );
  await sleep(3500);
  await page.locator('input[autoComplete="username"], input:not([type="password"])').first().fill('admin');
  await sleep(1200);
  await page.locator('input[type="password"]').fill('admin12345678');
  await sleep(1200);
  await page.click('button:has-text("로그인")');
  await page.waitForSelector('text=안녕하세요', { timeout: 10000 });
  await sleep(1500);

  // Find active review
  const cookies = await context.cookies();
  const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
  const authHeaders = { Cookie: cookieHeader, 'Content-Type': 'application/json' };
  const reviewsRes = await (await fetch(`${BASE_URL}/api/v1/review-requests`, { headers: authHeaders })).json();
  const targetReviewId = Array.isArray(reviewsRes) && reviewsRes[0]?.id;

  // SCENE 3: Dashboard (22s)
  console.log('🎥 Scene 3: Dashboard...');
  await page.goto(`${BASE_URL}/`);
  await page.waitForSelector('text=안녕하세요');
  await setSubtitle(
    page,
    '02 / 08',
    '보안 심의 현황 대시보드 & 4단계 Snapshot 흐름',
    '진행 중 심의, 미처리 보완 요청, 오픈 예정 통계를 실시간으로 확인합니다.'
  );
  await sleep(8000);
  await smoothScroll(page, 200, 8);
  await sleep(6000);

  // SCENE 4: New Review Request with Rule Engine (25s)
  console.log('🎥 Scene 4: New Review Form & Rule Engine...');
  await page.goto(`${BASE_URL}/reviews/new`);
  await page.waitForSelector('text=신규 보안성 심의 요청');
  await setSubtitle(
    page,
    '03 / 08',
    'Rule Engine 기반 신규 보안성 심의 요청',
    '개인정보, 클라우드, K8s 등 9대 적용 조건을 평가하여 체크리스트를 불변 스냅샷으로 자동 배정합니다.'
  );
  await sleep(8000);
  await smoothScroll(page, 250, 8);
  await sleep(6000);

  // SCENE 5: Checklist Workspace & Evidence Encryption (35s)
  console.log('🎥 Scene 5: Checklist & Evidence...');
  if (targetReviewId) {
    await page.goto(`${BASE_URL}/reviews/${targetReviewId}`);
    await page.waitForSelector('.review-layout');
    await setSubtitle(
      page,
      '04 / 08',
      '체크리스트 작업 공간 & 실시간 자동 저장',
      '작성 진행률(%) 집계와 실시간 자동 저장, N/A 필수 사유 검증으로 결함을 방지합니다.'
    );
    await sleep(8000);

    // Expand item
    const firstItem = page.locator('.checklist-summary').first();
    await firstItem.click();
    await setSubtitle(
      page,
      '04 / 08',
      'AES-256-GCM 증적 파일 봉투 암호화 & 무중단 키 회전',
      '증적 파일은 Magic MIME 검증 후 개인 데이터 키로 암호화되어 안전하게 보관됩니다.'
    );
    await sleep(8000);

    // Open Rule Override Modal
    const ruleBtn = page.locator('button:has-text("자동 배정 조정")').first();
    if (await ruleBtn.count() > 0) {
      await ruleBtn.click();
      await page.waitForSelector('.modal');
      await setSubtitle(
        page,
        '04 / 08',
        '자동 배정 결과 조정 & 감사 추적 (Rule Override)',
        '수동 변경 사유와 작업자가 감사로그에 영구 기록되어 완벽한 추적성을 보장합니다.'
      );
      await sleep(7000);
      await page.keyboard.press('Escape');
      await sleep(1500);
    }
  }

  // SCENE 6: Security Reviews Queue & Change Requests (26s)
  console.log('🎥 Scene 6: Security Review Queue...');
  await page.goto(`${BASE_URL}/security`);
  await page.waitForSelector('text=보안 검토 Queue');
  await setSubtitle(
    page,
    '05 / 08',
    '보안 담당자 전용 검토 Queue & 항목별 보완 요청',
    '적합/조건부/미흡/N/A인정 판정과 무제한 보완 요청 및 조치 검증 루프를 지원합니다.'
  );
  await sleep(9000);
  await smoothScroll(page, 180, 8);
  await sleep(6000);

  // SCENE 7: Unified Security Controls (18s)
  console.log('🎥 Scene 7: Security Controls Catalog...');
  await page.goto(`${BASE_URL}/controls`);
  await page.waitForSelector('text=통합 Security Controls');
  await setSubtitle(
    page,
    '06 / 08',
    '통합 Security Controls & 영향 범위 (Blast Radius) 추적',
    '표준 보안 통제 카탈로그를 관리하고 템플릿 및 적용 심의 건수 영향을 추적합니다.'
  );
  await sleep(8000);

  // SCENE 8: Templates & Excel Import Wizard (20s)
  console.log('🎥 Scene 8: Templates & Excel Wizard...');
  await page.goto(`${BASE_URL}/templates`);
  await page.waitForSelector('text=체크리스트 템플릿');
  await setSubtitle(
    page,
    '07 / 08',
    '체크리스트 템플릿 & Excel 가져오기 마법사',
    '기존 엑셀 점검표를 지능형 컬럼 매핑으로 변환하고 템플릿 버전을 안전하게 게시합니다.'
  );
  await sleep(8000);

  await page.goto(`${BASE_URL}/templates/import`);
  await page.waitForSelector('text=Excel 가져오기');
  await sleep(5000);

  // SCENE 9: Admin Settings & Hash Chain Audit (25s)
  console.log('🎥 Scene 9: Admin & Hash Chain Audit...');
  await page.goto(`${BASE_URL}/admin/settings`);
  await page.waitForSelector('text=서비스 관리자 설정');
  await setSubtitle(
    page,
    '08 / 08',
    'Keycloak SSO, SMTP 알림, ClamAV 안티바이러스 설정',
    '4대 환경변수 외 모든 운영 정책을 관리자 화면에서 런타임으로 즉시 구성합니다.'
  );
  await sleep(7000);

  await page.goto(`${BASE_URL}/admin/audit`);
  await page.waitForSelector('text=감사로그');
  await setSubtitle(
    page,
    '08 / 08',
    'SHA-256 암호학적 해시 체인 불변 감사로그',
    '이전 이벤트 해시를 연결하여 위변조를 원천 차단하고 원클릭으로 무결성을 전수 검증합니다.'
  );
  await sleep(8000);

  // SCENE 10: Outro Slide (14s)
  console.log('🎥 Scene 10: Outro Slide...');
  const outroPath = 'file://' + path.join(__dirname, 'video_slides', 'outro.html');
  await page.goto(outroPath);
  await sleep(14000);

  // Close browser to flush video
  console.log('💾 Closing browser and finalizing video stream...');
  const video = page.video();
  await browser.close();

  if (video) {
    const videoPath = await video.path();
    console.log(`Original video saved to: ${videoPath}`);

    // Transcode to clean MP4 using ffmpeg
    console.log(`Transcoding to 1080p MP4: ${OUTPUT_MP4}...`);
    const ffmpegCmd = `"${FFMPEG_BIN}" -y -i "${videoPath}" -c:v libx264 -preset slow -crf 20 -pix_fmt yuv420p -r 30 "${OUTPUT_MP4}"`;
    execSync(ffmpegCmd, { stdio: 'inherit' });
    console.log(`✅ MP4 Video generated successfully: ${OUTPUT_MP4}`);

    // Clean up temporary video dir
    fs.rmSync(VIDEO_TMP_DIR, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error('❌ Video generation failed:', err);
  process.exit(1);
});
