import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { chromium } from 'file:///C:/Users/ruel3/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright/index.mjs';

const browser = await chromium.launch({ headless: true, executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe' });
const results = [];
const title = "The Quantum Clock Is Ticking. Your Security Can't Stand Still.";
const paragraphs = [
  "What protects your enterprise today could become tomorrow's greatest vulnerability.",
  'The quantum threat is approaching, and the time to prepare is now.',
  'Qguard Helix helps you uncover hidden cryptographic risks, identify vulnerable encryption, and accelerate your transition to quantum-resistant security.',
  'Discover. Assess. Strategize. Migrate. Validate. Govern.',
  'From TLS and VPNs to SSH, certificates, and code signing, gain complete visibility and control over your cryptographic infrastructure through one intelligent, unified Post-Quantum Cyber Defense platform.',
  "Stay ahead of the quantum threat. Protect what matters. Prepare for what's next.",
  'Qguard Helix — Your Bridge to the Quantum-Safe Future.',
];
try {
  for (const [width, height] of [[1440, 1000], [1024, 768], [768, 1024], [390, 844], [320, 740]]) {
    const page = await browser.newPage({ viewport: { width, height }, reducedMotion: 'reduce' });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto('http://localhost:3000/', { waitUntil: 'networkidle', timeout: 60000 });
    await page.getByRole('heading', { level: 1, name: title, exact: true }).waitFor();
    assert.deepEqual(await page.locator('.hero-message p').allTextContents().then(texts => texts.map(text => text.replace(/\s+/g, ' ').trim())), paragraphs);
    assert.equal(await page.locator('#hero a[href="/auth"]').count(), 1);
    assert.equal(await page.locator('.hero-title__ticking--armed').count(), 1);
    await page.locator('.hero-intel-frame').scrollIntoViewIfNeeded();
    await page.waitForTimeout(1100);
    await page.locator('.hero-alert-card').scrollIntoViewIfNeeded();
    await page.waitForTimeout(600);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.waitForTimeout(200);
    const layout = await page.locator('#hero').evaluate(hero => {
      const elements = [...hero.querySelectorAll('h1, .hero-title__typed, .hero-title__continuation, .hero-message p, .hero-alert-badge, .hero-primary-cta, .hero-intel-frame')];
      return {
        clipped: elements.filter(el => { const box = el.getBoundingClientRect(); return box.left < -1 || box.right > innerWidth + 1; }).map(el => el.className),
        overflowingText: elements.filter(el => el.scrollWidth > el.clientWidth + 2).map(el => el.className),
        tickingAnimation: getComputedStyle(hero.querySelector('.hero-title__ticking--armed')).animationName,
        heroHeight: hero.clientHeight,
      };
    });
    assert.deepEqual(layout.clipped, [], `${width}: clipped elements`);
    assert.deepEqual(layout.overflowingText, [], `${width}: overflowing text`);
    assert.equal(layout.tickingAnimation, 'none');
    assert.deepEqual(errors, []);
    await page.locator('#hero').screenshot({ path: `artifacts/homepage-tagline/hero-${width}.png` });
    results.push({ width, height, ...layout, errors });
    await page.close();
  }
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'no-preference' });
  await page.goto('http://localhost:3000/', { waitUntil: 'domcontentloaded' });
  await page.locator('.hero-title__ticking--armed').waitFor({ timeout: 15000 });
  const ticking = page.locator('.hero-title__ticking--armed');
  const animation = await ticking.evaluate(el => ({ names: getComputedStyle(el).animationName, states: el.getAnimations().map(animation => animation.playState), text: el.textContent.trim() }));
  assert.match(animation.names, /hero-timebomb-tick/);
  assert.match(animation.names, /hero-timebomb-glow/);
  assert.ok(animation.states.every(state => state === 'running'));
  assert.equal(animation.text, 'TICKING');
  assert.equal(await page.locator('.hero-title__cursor').count(), 0);
  const clockBefore = await page.locator('.quantum-countdown__value').last().textContent();
  await page.waitForTimeout(1200);
  const clockAfter = await page.locator('.quantum-countdown__value').last().textContent();
  assert.notEqual(clockBefore, clockAfter);
  await page.screenshot({ path: 'artifacts/homepage-tagline/final-desktop.png' });
  results.push({ motion: animation, countdownAdvances: true });
  await writeFile('artifacts/homepage-tagline/verification.json', JSON.stringify(results, null, 2));
  console.log(JSON.stringify(results, null, 2));
} finally {
  await browser.close();
}
