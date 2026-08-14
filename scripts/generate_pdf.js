const fs = require('fs');
const path = require('path');
const { marked } = require(path.join(__dirname, '..', 'web', 'node_modules', 'marked'));
const { chromium } = require(path.join(__dirname, '..', 'web', 'node_modules', '@playwright', 'test'));

const DOCS_DIR = path.join(__dirname, '..', 'docs');
const PDF_DIR = path.join(DOCS_DIR, 'pdf');

if (!fs.existsSync(PDF_DIR)) {
  fs.mkdirSync(PDF_DIR, { recursive: true });
}

const HTML_TEMPLATE = (title, content, date = '2026. 08') => `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>${title}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Pretendard:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    @page {
      size: A4;
      margin: 18mm 16mm 20mm 16mm;
      @bottom-right {
        content: counter(page);
        font-family: 'Pretendard', sans-serif;
        font-size: 10px;
        color: #64748b;
      }
    }
    * {
      box-sizing: border-box;
    }
    body {
      font-family: 'Pretendard', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 13.5px;
      line-height: 1.65;
      color: #1e293b;
      background: #ffffff;
      margin: 0;
      padding: 0;
    }

    /* Cover / Header Banner */
    .doc-header {
      border-bottom: 3px solid #0f766e;
      padding-bottom: 16px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }
    .brand-box {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .logo-badge {
      background: #0f766e;
      color: #ffffff;
      font-weight: 900;
      font-size: 16px;
      width: 32px;
      height: 32px;
      border-radius: 8px;
      display: grid;
      place-items: center;
    }
    .brand-name {
      font-size: 24px;
      font-weight: 900;
      color: #134e4a;
      letter-spacing: -0.5px;
    }
    .doc-meta {
      font-size: 11px;
      color: #64748b;
      text-align: right;
    }

    /* Headings */
    h1 {
      font-size: 22px;
      font-weight: 850;
      color: #134e4a;
      border-left: 5px solid #0f766e;
      padding-left: 12px;
      margin-top: 28px;
      margin-bottom: 14px;
      page-break-after: avoid;
    }
    h2 {
      font-size: 17px;
      font-weight: 800;
      color: #0f766e;
      border-bottom: 1.5px solid #e2e8f0;
      padding-bottom: 6px;
      margin-top: 22px;
      margin-bottom: 12px;
      page-break-after: avoid;
    }
    h3 {
      font-size: 14.5px;
      font-weight: 750;
      color: #1e293b;
      margin-top: 18px;
      margin-bottom: 8px;
      page-break-after: avoid;
    }
    p {
      margin-bottom: 10px;
    }

    /* Lists */
    ul, ol {
      margin-top: 4px;
      margin-bottom: 12px;
      padding-left: 20px;
    }
    li {
      margin-bottom: 4px;
    }

    /* Tables */
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 14px 0;
      font-size: 12px;
      page-break-inside: avoid;
    }
    th {
      background: #134e4a;
      color: #ffffff;
      font-weight: 750;
      text-align: left;
      padding: 8px 10px;
      border: 1px solid #134e4a;
    }
    td {
      padding: 7px 10px;
      border: 1px solid #e2e8f0;
      vertical-align: middle;
    }
    tr:nth-child(even) td {
      background: #f8fafc;
    }

    /* Code & Pre */
    code {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11.5px;
      background: #f0fdfa;
      color: #0f766e;
      padding: 2px 5px;
      border-radius: 4px;
      border: 1px solid #ccfbf1;
    }
    pre {
      background: #0f172a;
      color: #f8fafc;
      padding: 12px 14px;
      border-radius: 8px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      line-height: 1.5;
      overflow-x: auto;
      margin: 12px 0;
      border: 1px solid #334155;
      page-break-inside: avoid;
    }
    pre code {
      background: transparent;
      color: inherit;
      padding: 0;
      border: none;
      font-size: inherit;
    }

    /* Images */
    img {
      max-width: 100%;
      height: auto;
      border-radius: 6px;
      border: 1px solid #cbd5e1;
      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.08);
      margin: 10px 0;
      display: block;
      page-break-inside: avoid;
    }

    /* Blockquotes & Callouts */
    blockquote {
      margin: 12px 0;
      padding: 10px 14px;
      background: #f0fdfa;
      border-left: 4px solid #0f766e;
      color: #115e59;
      border-radius: 0 6px 6px 0;
      font-size: 12.5px;
      page-break-inside: avoid;
    }
    blockquote p {
      margin: 0;
    }

    /* Page Break Utility */
    .page-break {
      page-break-before: always;
    }
    hr {
      border: 0;
      border-top: 1px solid #e2e8f0;
      margin: 20px 0;
    }
  </style>
</head>
<body>
  <div class="doc-header">
    <div class="brand-box">
      <div class="logo-badge">SC</div>
      <div class="brand-name">SecCheck</div>
    </div>
    <div class="doc-meta">
      <strong>${title}</strong><br>
      Security Review Platform · v0.1.0 (${date})
    </div>
  </div>
  ${content}
</body>
</html>`;

function resolveImages(html, baseDir) {
  return html.replace(/src="([^"]+)"/g, (match, src) => {
    if (src.startsWith('http://') || src.startsWith('https://') || src.startsWith('data:')) {
      return match;
    }
    let localPath = path.resolve(baseDir, src);
    if (fs.existsSync(localPath)) {
      const ext = path.extname(localPath).slice(1) || 'png';
      const base64 = fs.readFileSync(localPath).toString('base64');
      return `src="data:image/${ext};base64,${base64}"`;
    }
    return match;
  });
}

const DOCS_TO_BUILD = [
  {
    src: path.join(DOCS_DIR, 'features.md'),
    outPdf: path.join(DOCS_DIR, 'seccheck_features_guide.pdf'),
    title: 'SecCheck 기능 및 화면 가이드 (Features & UI Guide)',
  },
  {
    src: path.join(DOCS_DIR, 'user-guide.md'),
    outPdf: path.join(DOCS_DIR, 'seccheck_user_guide.pdf'),
    title: 'SecCheck 사용자 실무 가이드 (User Guide)',
  },
  {
    src: path.join(DOCS_DIR, 'admin-guide.md'),
    outPdf: path.join(DOCS_DIR, 'seccheck_admin_guide.pdf'),
    title: 'SecCheck 관리자 운영 가이드 (Admin Guide)',
  },
  {
    src: path.join(DOCS_DIR, 'api-guide.md'),
    outPdf: path.join(DOCS_DIR, 'seccheck_api_guide.pdf'),
    title: 'SecCheck API & MCP 연계 가이드 (API & MCP Guide)',
  },
  {
    src: path.join(DOCS_DIR, 'architecture.md'),
    outPdf: path.join(DOCS_DIR, 'seccheck_architecture.pdf'),
    title: 'SecCheck 시스템 아키텍처 및 보안 설계 (Architecture)',
  },
];

async function main() {
  console.log('📄 Starting High-Quality PDF Generation for SecCheck with Playwright...');
  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  const page = await browser.newPage();

  let completeManualContent = '';

  for (const doc of DOCS_TO_BUILD) {
    if (!fs.existsSync(doc.src)) continue;
    console.log(`Generating PDF for: ${path.basename(doc.src)} -> ${path.basename(doc.outPdf)}...`);

    const mdContent = fs.readFileSync(doc.src, 'utf-8');
    completeManualContent += `\n\n<div class="page-break"></div>\n\n` + mdContent;

    let rawHtml = marked(mdContent);
    let resolvedHtml = resolveImages(rawHtml, path.dirname(doc.src));
    let fullHtml = HTML_TEMPLATE(doc.title, resolvedHtml);

    await page.setContent(fullHtml, { waitUntil: 'networkidle' });
    await page.pdf({
      path: doc.outPdf,
      format: 'A4',
      printBackground: true,
      margin: {
        top: '18mm',
        bottom: '20mm',
        left: '16mm',
        right: '16mm',
      },
    });

    fs.copyFileSync(doc.outPdf, path.join(PDF_DIR, path.basename(doc.outPdf)));
  }

  // Generate Consolidated Complete Technical Manual PDF
  console.log('Generating Consolidated Complete Manual PDF: seccheck_complete_manual.pdf...');
  let masterRawHtml = marked(completeManualContent);
  let masterResolvedHtml = resolveImages(masterRawHtml, DOCS_DIR);
  let masterFullHtml = HTML_TEMPLATE('SecCheck 종합 기술 매뉴얼 완본 (Complete Technical Manual)', masterResolvedHtml);

  const masterOutPdf = path.join(DOCS_DIR, 'seccheck_complete_manual.pdf');
  await page.setContent(masterFullHtml, { waitUntil: 'networkidle' });
  await page.pdf({
    path: masterOutPdf,
    format: 'A4',
    printBackground: true,
    margin: {
      top: '18mm',
      bottom: '20mm',
      left: '16mm',
      right: '16mm',
    },
  });
  fs.copyFileSync(masterOutPdf, path.join(PDF_DIR, 'seccheck_complete_manual.pdf'));

  await browser.close();
  console.log('🎉 All SecCheck PDFs generated successfully in docs/ and docs/pdf/!');
}

main().catch((err) => {
  console.error('❌ PDF generation failed:', err);
  process.exit(1);
});
