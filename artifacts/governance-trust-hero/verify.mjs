import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import { chromium } from 'file:///C:/Users/ruel3/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright/index.mjs';

const out = 'artifacts/governance-trust-hero';
await fs.mkdir(out, { recursive: true });
const browser = await chromium.launch({ headless: true, executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe' });
const report = [];
const consoleErrors = [];
const sizes = [
  { name: 'desktop', width: 1440, height: 1000 },
  { name: 'desktop-short', width: 1440, height: 900 },
  { name: 'tablet', width: 1024, height: 768 },
  { name: 'mobile', width: 390, height: 844 },
  { name: 'mobile-375', width: 375, height: 812 },
  { name: 'mobile-320', width: 320, height: 740 },
];
function watch(page) {
  page.on('pageerror', error => consoleErrors.push({ type: 'pageerror', message: error.message }));
  page.on('console', message => {
    if (message.type() === 'error') consoleErrors.push({ type: 'console', text: message.text(), location: message.location() });
  });
}
async function ready(page) {
  await page.goto('http://localhost:3000/quantum-trust-governance-center', { waitUntil: 'networkidle', timeout: 60000 });
  await page.waitForFunction(() => document.querySelector('.gth-renderer')?.getAttribute('data-renderer') === 'webgl', { timeout: 60000 });
    await page.waitForTimeout(300);
}
try {
  for (const spec of sizes) {
    const page = await browser.newPage({ viewport: { width: spec.width, height: spec.height }, reducedMotion: 'reduce' });
    page.setDefaultTimeout(60000);
    watch(page);
    await ready(page);
    const host = page.locator('.gth-renderer');
    const frame = await host.getAttribute('data-scene-state');
    await page.waitForTimeout(350);
    assert.equal(await host.getAttribute('data-scene-state'), frame, 'Reduced motion must be stable');
    assert.equal(await host.getAttribute('data-motion'), 'reduced');
    const metrics = await page.evaluate(() => ({
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth,
      heroHeight: document.querySelector('.governance-trust-hero').getBoundingClientRect().height,
      primaryBottom: document.querySelector('.gth-primary').getBoundingClientRect().bottom,
      description: getComputedStyle(document.querySelector('.gth-description')).color,
      background: getComputedStyle(document.querySelector('.governance-trust-hero')).backgroundColor,
      headerBackground: getComputedStyle(document.querySelector('header')).backgroundColor,
      focus: getComputedStyle(document.querySelector('.gth-primary')).outlineColor,
      titleFont: getComputedStyle(document.querySelector('h1')).fontFamily,
    }));
    assert.equal(metrics.horizontalOverflow, false, spec.name + ' overflow');
    assert(metrics.primaryBottom < spec.height, spec.name + ' primary CTA must be in first viewport');
    await page.screenshot({ path: out + '/final-' + spec.name + '.png', timeout: 60000 });
    await page.locator('.governance-trust-hero').screenshot({ path: out + '/final-' + spec.name + '-hero.png', style: 'header {visibility:hidden!important}', timeout: 60000 });
    report.push({ viewport: spec, renderer: 'webgl', reducedMotionStable: true, ...metrics });
    console.log('Verified viewport:', spec.name);
    await page.close();
  }

  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
  page.setDefaultTimeout(60000);
  watch(page);
  await ready(page);
  const host = page.locator('.gth-renderer');
  const buttons = page.getByRole('group', { name: 'Explore governance capabilities' }).getByRole('button');
  for (let index = 0; index < 4; index++) {
    await buttons.nth(index).click();
    await page.waitForFunction(index => document.querySelector('.gth-renderer')?.getAttribute('data-scene-state')?.startsWith(index + ':'), index);
    assert.equal(await buttons.nth(index).getAttribute('aria-pressed'), 'true');
    assert.equal(await page.locator('.gth-domain[aria-pressed="true"]').count(), 1);
    if (index === 3) {
      assert.match(await page.locator('#gth-domain-detail').innerText(), /proof trail/);
      await page.screenshot({ path: out + '/final-evidence-selected.png', timeout: 60000 });
    }
  }
  await buttons.nth(0).focus();
  await page.keyboard.press('Tab');
  assert.equal(await buttons.nth(1).evaluate(el => el === document.activeElement), true, 'Native keyboard order');
  await page.keyboard.press('Enter');
  assert.equal(await buttons.nth(1).getAttribute('aria-pressed'), 'true');
  await page.screenshot({ path: out + '/final-keyboard-focus.png', timeout: 60000 });
  assert.match(await page.locator('.gth-primary').getAttribute('href'), /checkout\?plan=Elite&cycle=yearly/);
  assert.equal(await page.locator('.gth-secondary').getAttribute('href'), '#capabilities');
  assert.equal(await page.locator('#capabilities').count(), 1);

  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.evaluate(() => scrollTo(0, 0));
  await page.waitForTimeout(1800);
  const moving1 = await host.getAttribute('data-scene-state');
  await page.waitForTimeout(450);
  const moving2 = await host.getAttribute('data-scene-state');
  assert.notEqual(moving1, moving2, 'Ambient motion must advance');
  await page.getByRole('button', { name: 'Pause hero animation' }).click();
  await page.waitForTimeout(150);
  const paused1 = await host.getAttribute('data-scene-state');
  await page.waitForTimeout(450);
  assert.equal(await host.getAttribute('data-scene-state'), paused1, 'Pause must freeze');
  await page.screenshot({ path: out + '/final-paused-motion.png', timeout: 60000 });
  await page.getByRole('button', { name: 'Play hero animation' }).click();
  await page.waitForTimeout(350);
  assert.notEqual(await host.getAttribute('data-scene-state'), paused1, 'Resume must advance');

  const scrollStates = [];
  for (const y of [0, 140, 280, 420, 560, 700]) {
    await page.evaluate(y => scrollTo(0, y), y);
    await page.waitForTimeout(400);
    scrollStates.push({ y, state: await host.getAttribute('data-scene-state') });
    await page.locator('.gth-motion-toggle').evaluate(el => el.click());
    await page.waitForTimeout(80);
    await page.screenshot({ path: out + '/scroll-' + y + '.png', timeout: 60000 });
    await page.locator('.gth-motion-toggle').evaluate(el => el.click());
  }
  const expansions = scrollStates.map(entry => Number(entry.state.split(':')[2]));
  assert(expansions[3] > expansions[0] + .05, 'Scroll must open layers');
  await page.evaluate(() => scrollTo(0, 1300));
  await page.waitForTimeout(400);
  const offscreen = await host.getAttribute('data-scene-state');
  await page.waitForTimeout(350);
  assert.equal(await host.getAttribute('data-scene-state'), offscreen, 'Offscreen scene must stop');
  await page.evaluate(() => scrollTo(0, 0));
  await page.waitForTimeout(400);
  await page.getByRole('button', { name: 'Pause hero animation' }).click();
  await page.locator('.gth-renderer canvas').evaluate(canvas => canvas.getContext('webgl2').getExtension('WEBGL_lose_context').loseContext());
  await page.waitForFunction(() => document.querySelector('.gth-renderer')?.getAttribute('data-renderer') === 'fallback');
  assert.equal(await page.locator('.gth-fallback').evaluate(el => el.complete && el.naturalWidth > 0), true);
  await page.screenshot({ path: out + '/final-context-loss-fallback.png', timeout: 60000 });
  await page.getByRole('button', { name: /Audit evidence/ }).click();
  assert.match(await page.locator('#gth-domain-detail').innerText(), /proof trail/);
  await page.locator('.gth-secondary').click();
  await page.waitForTimeout(300);
  assert((await page.locator('#capabilities').boundingBox()).y < 200, 'Capability anchor navigates');
  await page.getByRole('navigation').getByRole('link', { name: 'Home', exact: true }).click();
  await page.waitForTimeout(300);
  assert.equal(await page.locator('.gth-renderer').count(), 0, 'Route cleanup');
  report.push({ interactions: 'four selections, keyboard, anchors, pause/resume, context loss, route cleanup', scrollStates, ambientAdvances: true, pausedStable: true, offscreenStopped: true });
  await page.close();

  const relevantErrors = consoleErrors.filter(error => error.location?.url !== 'http://localhost:3000/favicon.ico' && !/WebGL: CONTEXT_LOST/.test(error.text ?? ''));
  report.push({ consoleErrors, relevantErrors });
  await fs.writeFile(out + '/verification.json', JSON.stringify(report, null, 2));
  assert.equal(relevantErrors.length, 0, 'Unexpected console errors');
  console.log(JSON.stringify(report, null, 2));
} finally {
  await browser.close();
}
