import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import * as THREE from 'three';
import { chromium } from 'file:///C:/Users/ruel3/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright/index.mjs';

const out = 'artifacts/governance-trust-hero/white-glass';
await fs.mkdir(out, { recursive: true });
const browser = await chromium.launch({ headless: true, executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe' });
const report = [];
const errors = [];
const labels = ['Key management', 'Crypto policy', 'Continuous trust', 'Audit evidence'];
const points = [[-2.65, .02, -.55], [.55, .02, -2.65], [2.65, .02, .55], [-.55, .02, 2.65]];

async function save() { await fs.writeFile(out + '/verification.json', JSON.stringify({ report, errors }, null, 2)); }
async function open(spec) {
  const page = await browser.newPage({ viewport: { width: spec.width, height: spec.height }, reducedMotion: 'reduce', ...(spec.mobile ? { isMobile: true, hasTouch: true } : {}) });
  page.setDefaultTimeout(60000);
  page.on('pageerror', error => { errors.push({ type: 'page', message: error.message }); console.log('PAGE ERROR', error.message); });
  page.on('console', message => { if (message.type() === 'error') errors.push({ type: 'console', text: message.text(), location: message.location() }); });
  await page.goto('http://localhost:3000/quantum-trust-governance-center', { waitUntil: 'networkidle' });
  await page.waitForFunction(() => document.querySelector('.gth-renderer')?.dataset.renderer === 'webgl', undefined, { timeout: 60000 });
  await page.waitForTimeout(300);
  return page;
}
async function project(page, point) {
  const bounds = await page.locator('.gth-renderer canvas').boundingBox();
  const state = (await page.locator('.gth-renderer').getAttribute('data-scene-state')).split(':');
  const camera = new THREE.PerspectiveCamera(33, bounds.width / bounds.height, .1, 80);
  camera.position.set(8.5, 8, 10.5).normalize().multiplyScalar(camera.aspect < 1.1 ? 15.2 : 13.2);
  camera.lookAt(0, .4, 0); camera.updateProjectionMatrix(); camera.updateMatrixWorld();
  const position = point.clone().applyAxisAngle(new THREE.Vector3(0, 1, 0), Number(state[1])).project(camera);
  return { x: bounds.x + (position.x + 1) * .5 * bounds.width, y: bounds.y + (1 - position.y) * .5 * bounds.height };
}
async function selectGeometry(page, index, path = false) {
  if (await page.getByRole('dialog').count()) await page.keyboard.press('Escape');
  await page.locator('.gth-scene').scrollIntoViewIfNeeded();
  const active = Number((await page.locator('.gth-renderer').getAttribute('data-scene-state')).split(':')[0]);
  const location = new THREE.Vector3(...points[index]);
  let point;
  if (path) {
    const end = location.clone().multiplyScalar(.37).setY(.68);
    const mid = location.clone().multiplyScalar(.72).setY(.5);
    point = new THREE.CatmullRomCurve3([location.clone().setY(.39), mid, end]).getPoint(.48);
  } else {
    point = location.clone();
    const outward = location.clone().setY(0).normalize().multiplyScalar(.14);
    point.add(outward).setY(.32 + (index === active ? .16 : 0));
  }
  const screen = await project(page, point);
  await page.mouse.click(screen.x, screen.y);
  await page.waitForTimeout(100);
  assert.equal(await page.getByRole('dialog').getAttribute('aria-labelledby'), 'gth-feature-title');
  assert.equal(await page.locator('#gth-feature-title').innerText(), labels[index], (path ? 'Path' : 'Node') + ' ' + index);
  report.push({ geometry: path ? 'path' : 'node', index, screen, selected: labels[index] });
  await page.keyboard.press('Escape');
}

try {
  for (const spec of [
    { name: 'desktop', width: 1440, height: 1000 },
    { name: 'tablet', width: 1024, height: 768 },
    { name: 'mobile', width: 390, height: 844, mobile: true },
    { name: 'mobile-small', width: 320, height: 740, mobile: true },
  ]) {
    const page = await open(spec);
    const metrics = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth > innerWidth,
      background: getComputedStyle(document.querySelector('.governance-trust-hero')).backgroundColor,
      headline: getComputedStyle(document.querySelector('h1')).color,
      primaryBottom: document.querySelector('.gth-primary').getBoundingClientRect().bottom,
    }));
    assert.equal(metrics.background, 'rgb(255, 255, 255)');
    assert.equal(metrics.overflow, false);
    assert(metrics.primaryBottom < spec.height);
    const static1 = await page.locator('.gth-renderer').getAttribute('data-scene-state');
    await page.waitForTimeout(300);
    assert.equal(await page.locator('.gth-renderer').getAttribute('data-scene-state'), static1);
    await page.screenshot({ path: out + '/' + spec.name + '.png', timeout: 60000 });
    await page.locator('.governance-trust-hero').screenshot({ path: out + '/' + spec.name + '-hero.png', style: 'header {visibility:hidden!important}', timeout: 60000 });
    const nodeButtons = page.locator('.gth-node-label');
    for (let index = 0; index < 4; index++) {
      const button = nodeButtons.nth(index);
      if (spec.mobile) await button.tap(); else await button.click();
      assert.equal(await page.locator('#gth-feature-title').innerText(), labels[index]);
      assert.equal(await button.getAttribute('aria-expanded'), 'true');
      assert.equal(await page.getByRole('dialog').evaluate(el => el === document.activeElement), true);
      const bounds = await page.getByRole('dialog').boundingBox();
      assert(bounds.x >= 0 && bounds.x + bounds.width <= spec.width);
      if (spec.mobile) assert(bounds.y >= 64 && bounds.y + bounds.height <= spec.height, 'Mobile details must fit below navigation');
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
      if (index === 3) await page.screenshot({ path: out + '/' + spec.name + '-details.png', timeout: 60000 });
      if (spec.mobile) await page.getByRole('button', { name: 'Close feature details' }).tap();
      else await page.keyboard.press('Escape');
      assert.equal(await page.getByRole('dialog').count(), 0);
      assert.equal(await button.evaluate(el => el === document.activeElement), true, 'Focus should return to feature');
    }
    if (spec.name === 'desktop') {
      await page.evaluate(() => scrollTo(0, 0));
      for (let index = 0; index < 4; index++) await selectGeometry(page, index);
      for (const index of [2, 3]) await selectGeometry(page, index, true);
      await nodeButtons.nth(0).focus(); await page.keyboard.press('Enter');
      assert.equal(await page.locator('#gth-feature-title').innerText(), labels[0]);
      await page.keyboard.press('Escape');
      await page.emulateMedia({ reducedMotion: 'no-preference' });
      await page.evaluate(() => scrollTo(0, 0));
      await page.waitForTimeout(1800);
      const first = await page.locator('.gth-renderer').getAttribute('data-scene-state');
      await page.locator('.gth-scene').screenshot({ path: out + '/flow-a.png', timeout: 60000 });
      await page.waitForTimeout(450);
      const second = await page.locator('.gth-renderer').getAttribute('data-scene-state');
      assert.notEqual(first, second, 'Flow should advance');
      await page.locator('.gth-scene').screenshot({ path: out + '/flow-b.png', timeout: 60000 });
      await page.getByRole('button', { name: 'Pause hero animation' }).click();
      await page.waitForTimeout(120);
      const paused = await page.locator('.gth-renderer').getAttribute('data-scene-state');
      await page.waitForTimeout(350);
      assert.equal(await page.locator('.gth-renderer').getAttribute('data-scene-state'), paused);
      await page.screenshot({ path: out + '/desktop-paused.png', timeout: 60000 });
      await page.getByRole('button', { name: 'Play hero animation' }).click();
      await page.waitForTimeout(300);
      assert.notEqual(await page.locator('.gth-renderer').getAttribute('data-scene-state'), paused);
      await page.emulateMedia({ reducedMotion: 'reduce' });
      await page.waitForTimeout(150);
      await page.locator('.gth-renderer canvas').evaluate(canvas => canvas.getContext('webgl2').getExtension('WEBGL_lose_context').loseContext());
      await page.waitForFunction(() => document.querySelector('.gth-renderer')?.dataset.renderer === 'fallback');
      assert.equal(await page.locator('.gth-renderer canvas').evaluate(el => getComputedStyle(el).display), 'none');
      await nodeButtons.nth(1).click();
      assert.equal(await page.locator('#gth-feature-title').innerText(), labels[1]);
      await page.keyboard.press('Escape');
      await page.screenshot({ path: out + '/fallback.png', timeout: 60000 });
      report.push({ movingLightStreams: true, pauseStable: true, resumeWorks: true, fallbackInteractive: true, keyboardActivation: true });
    }
    report.push({ viewport: spec, ...metrics, fourFeaturePopovers: true, escapeAndClose: true, focusRestored: true, reducedStable: true });
    await save();
    console.log('Verified:', spec.name);
    await page.close();
  }
  const unexpected = errors.filter(error => error.location?.url !== 'http://localhost:3000/favicon.ico');
  assert.equal(unexpected.length, 0, JSON.stringify(unexpected));
  console.log('All white-glass, geometry selection, flow, popup and accessibility checks passed.');
} finally { await save(); await browser.close(); }
