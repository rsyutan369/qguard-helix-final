import { createRequire } from 'node:module';
const require = createRequire('C:/Users/ruel3/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/_entry.cjs');
const { chromium } = require('playwright');
const browser = await chromium.launch({channel:'chrome', headless:true});
const page = await browser.newPage({viewport:{width:1440,height:1000}});
await page.goto('http://localhost:3000/quantum-trust-governance-center');
await page.waitForTimeout(2500);
await page.screenshot({path:'artifacts/governance-hero/before.png'});
await browser.close();
