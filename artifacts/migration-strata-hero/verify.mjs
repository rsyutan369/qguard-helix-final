import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import { chromium } from 'file:///C:/Users/ruel3/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright/index.mjs';

const out = 'artifacts/migration-strata-hero';
const browser = await chromium.launch({ headless: true, executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe' });
const report = [];
const errors = [];
const url = 'http://localhost:3000/post-quantum-migration-platform';
async function save() { await fs.writeFile(out + '/verification.json', JSON.stringify({ report, errors }, null, 2)); }
async function open(spec, reduced = 'reduce') {
  const page = await browser.newPage({ viewport: { width: spec.width, height: spec.height }, reducedMotion: reduced, ...(spec.mobile ? { isMobile: true, hasTouch: true } : {}) });
  page.setDefaultTimeout(60000);
  page.on('pageerror', error => errors.push({ type: 'pageerror', message: error.message }));
  page.on('console', message => { if (message.type() === 'error') errors.push({ type: 'console', text: message.text(), location: message.location() }); });
  const response = await page.goto(url, { waitUntil: 'networkidle' });
  assert.equal(response.status(), 200);
  await page.evaluate(() => document.fonts.ready);
  return page;
}
try {
  for (const spec of [
    { name: 'desktop', width: 1440, height: 900 },
    { name: 'tablet', width: 1024, height: 768 },
    { name: 'mobile', width: 390, height: 844, mobile: true },
    { name: 'small', width: 320, height: 740, mobile: true },
  ]) {
    const page = await open(spec);
    const metrics = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth > innerWidth,
      heroHeight: document.querySelector('.migration-strata-hero').getBoundingClientRect().height,
      primaryBottom: document.querySelector('.ms-primary').getBoundingClientRect().bottom,
      headlineLinesFit: [...document.querySelectorAll('.ms-title-mask > span')].every(el => el.scrollWidth <= el.clientWidth + 1),
      fonts: [...document.fonts].filter(font => font.family.includes('Migration')).map(font => ({ family: font.family, status: font.status })),
    }));
    assert.equal(metrics.overflow, false);
    assert.equal(metrics.headlineLinesFit, true);
    assert(metrics.primaryBottom < spec.height);
    if (!spec.mobile) assert(metrics.heroHeight <= spec.height + 1, 'Desktop hero should fit one screen');
    assert(metrics.fonts.every(font => font.status === 'loaded'));
    assert.equal(await page.locator('.ms-film').getAttribute('src'), null);
    await page.screenshot({ path: out + '/final-' + spec.name + '.png', timeout: 60000 });
    await page.locator('.migration-strata-hero').screenshot({ path: out + '/final-' + spec.name + '-hero.png', style: 'header,.ms-mobile-toggle {visibility:hidden!important}', timeout: 60000 });
    await page.getByRole('button', { name: /Validation & recovery/ }).click();
    assert.equal(await page.locator('.migration-strata-hero').getAttribute('data-path'), 'recovery');
    assert.match(await page.locator('#ms-path-detail').innerText(), /recovery path/);
    assert.equal(await page.getByRole('button', { name: /Validation & recovery/ }).getAttribute('aria-pressed'), 'true');
    assert.equal(await page.locator('.ms-process a.is-highlighted').innerText(), 'Cutover');
    assert(Number(await page.locator('.ms-beam--recovery').evaluate(el => getComputedStyle(el).opacity)) > .7);
    await page.screenshot({ path: out + '/final-' + spec.name + '-recovery.png', timeout: 60000 });
    await page.getByRole('button', { name: /Migration planning/ }).focus();
    await page.keyboard.press('Enter');
    assert.equal(await page.locator('.migration-strata-hero').getAttribute('data-path'), 'plan');
    assert.equal(await page.locator('.ms-process a.is-highlighted').innerText(), 'Plan');
    assert.equal(await page.locator('.ms-process a').count(), 6);
    assert.equal(await page.locator('.ms-primary').getAttribute('href'), '/checkout?plan=Pro&cycle=yearly');
    assert.equal(await page.locator('.ms-secondary').getAttribute('href'), '#lifecycle');
    for (const id of ['lifecycle', 'capabilities', 'included']) assert.equal(await page.locator('#' + id).count(), 1);
    if (spec.mobile) {
      await page.evaluate(() => scrollTo(0, 0));
      const toggle = page.getByRole('button', { name: 'Open migration menu' });
      await toggle.tap();
      assert.equal(await page.getByRole('navigation', { name: 'Migration navigation' }).count(), 1);
      assert.equal(await page.getByRole('navigation', { name: 'Migration navigation' }).getByRole('link', { name: 'Overview', exact: true }).evaluate(el => el === document.activeElement), true);
      await page.screenshot({ path: out + '/final-' + spec.name + '-menu.png', timeout: 60000 });
      await page.keyboard.press('Escape');
      assert.equal(await page.locator('#ms-mobile-menu').count(), 0);
      assert.equal(await toggle.evaluate(el => el === document.activeElement), true);
      await toggle.tap();
      await page.locator('.ms-capability-proof').tap();
      assert.equal(await page.locator('#ms-mobile-menu').count(), 0, 'Outside tap closes menu');
      await toggle.tap();
      await page.getByRole('navigation', { name: 'Migration navigation' }).getByRole('link', { name: 'Lifecycle', exact: true }).tap();
      assert.equal(await page.locator('#ms-mobile-menu').count(), 0);
      await page.waitForTimeout(200);
      assert((await page.locator('#lifecycle').boundingBox()).y < 200);
      await page.evaluate(() => scrollTo(0, 0));
    }
    report.push({ viewport: spec, ...metrics, planAndRecoverySelection: true, keyboardSelection: true, reducedStill: true, mobileMenu: spec.mobile ? 'open, focus, escape, outside tap and anchor verified' : 'hidden' });
    await save();
    console.log('Verified layout:', spec.name);
    await page.close();
  }

  const page = await open({ width: 1440, height: 900 }, 'no-preference');
  await page.waitForFunction(() => { const video = document.querySelector('.ms-film'); return video.readyState >= 2 && !video.paused; });
  await page.waitForTimeout(1600);
  const film = page.locator('.ms-film');
  const sample = () => film.evaluate(el => ({ time: el.currentTime, frames: el.getVideoPlaybackQuality().totalVideoFrames, width: el.videoWidth, height: el.videoHeight, duration: el.duration, paused: el.paused, muted: el.muted }));
  const first = await sample();
  const dash1 = await page.locator('.ms-beam--plan').evaluate(el => getComputedStyle(el).strokeDashoffset);
  await page.waitForTimeout(650);
  const second = await sample();
  const dash2 = await page.locator('.ms-beam--plan').evaluate(el => getComputedStyle(el).strokeDashoffset);
  assert.notEqual(first.time, second.time);
  assert(second.frames > first.frames, 'The real video decoder must advance');
  assert.notEqual(dash1, dash2);
  assert.equal(second.muted, true);
  await page.getByRole('button', { name: 'Pause migration animation' }).click();
  await page.waitForTimeout(120);
  const paused = await sample();
  await page.waitForTimeout(350);
  assert.equal((await sample()).time, paused.time);
  assert.equal(await page.locator('.ms-beam--plan').evaluate(el => getComputedStyle(el).animationPlayState), 'paused');
  await page.screenshot({ path: out + '/final-normal-motion-paused.png', timeout: 60000 });
  await page.getByRole('button', { name: 'Play migration animation' }).click();
  await page.waitForTimeout(400);
  assert.equal((await sample()).paused, false);
  assert.notEqual((await sample()).time, paused.time);
  const scrollStates = [];
  for (const y of [0, 120, 240, 360, 480, 600]) {
    await page.evaluate(y => scrollTo(0, y), y);
    await page.waitForTimeout(450);
    const depth = await page.locator('.migration-strata-hero').evaluate(el => ({ y: getComputedStyle(el).getPropertyValue('--ms-media-y'), scale: getComputedStyle(el).getPropertyValue('--ms-media-scale') }));
    scrollStates.push({ scroll: y, ...depth });
    await page.locator('.ms-motion-toggle').evaluate(el => el.click());
    await page.screenshot({ path: out + '/scroll-' + y + '.png', timeout: 60000 });
    await page.locator('.ms-motion-toggle').evaluate(el => el.click());
  }
  assert(parseFloat(scrollStates.at(-1).y) < parseFloat(scrollStates[0].y) - 10);
  await page.evaluate(() => scrollTo(0, 1600));
  await page.waitForTimeout(300);
  assert.equal((await sample()).paused, true, 'Offscreen video should pause');
  await page.evaluate(() => scrollTo(0, 0));
  await page.waitForTimeout(300);
  assert.equal((await sample()).paused, false);
  await page.evaluate(() => { Object.defineProperty(document, 'hidden', { configurable: true, get: () => true }); document.dispatchEvent(new Event('visibilitychange')); });
  await page.waitForTimeout(150);
  assert.equal((await sample()).paused, true);
  await page.evaluate(() => { delete document.hidden; document.dispatchEvent(new Event('visibilitychange')); });
  await page.waitForTimeout(150);
  assert.equal((await sample()).paused, false);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.waitForTimeout(150);
  assert.equal(await film.getAttribute('src'), null);
  assert.equal(await page.locator('.migration-strata-hero').getAttribute('data-running'), 'false');
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.waitForTimeout(200);
  const activeEntrances = await page.locator('[data-ms-line]').evaluateAll(elements => elements.flatMap(el => el.getAnimations()).filter(animation => animation.playState === 'running').length);
  assert.equal(activeEntrances, 0, 'Preference changes should not replay the intro');
  report.push({ playback: { first, second }, decodedVideoAdvances: true, dashedPathAdvances: true, pauseResume: true, scrollStates, offscreenPauses: true, hiddenPauses: true, liveReducedMotion: true, entranceDoesNotReplay: true });
  await page.close();

  const fallback = await browser.newPage({ viewport: { width: 1440, height: 900 }, reducedMotion: 'no-preference' });
  await fallback.route('**/migration-hero/strata/glass-layers.mp4', route => route.abort());
  await fallback.goto(url, { waitUntil: 'networkidle' });
  await fallback.waitForTimeout(1700);
  assert.equal(await fallback.locator('.ms-poster').evaluate(el => el.complete && el.naturalWidth === 1200), true);
  assert.equal(await fallback.locator('.ms-film').evaluate(el => getComputedStyle(el).opacity), '0');
  await fallback.getByRole('button', { name: /Validation & recovery/ }).click();
  assert.match(await fallback.locator('#ms-path-detail').innerText(), /recovery path/);
  await fallback.screenshot({ path: out + '/final-media-fallback.png', timeout: 60000 });
  report.push({ mediaFailurePoster: true, fallbackControlsWork: true });
  await fallback.close();
  const unexpected = errors.filter(error => error.location?.url !== 'http://localhost:3000/favicon.ico');
  assert.equal(unexpected.length, 0, JSON.stringify(unexpected));
  console.log('All migration hero layout, playback, motion, fallback, menu and selection checks passed.');
} finally { await save(); await browser.close(); }
