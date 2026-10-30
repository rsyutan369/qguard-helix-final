import {createRequire} from 'node:module';
const require=createRequire('C:/Users/ruel3/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/_entry.cjs');
const {chromium}=require('playwright');
const browser=await chromium.launch({channel:'chrome'}); const page=await browser.newPage();
await page.goto('http://localhost:3000/quantum-trust-governance-center'); await page.waitForTimeout(1500);
console.log(await page.evaluate(()=>[...document.images].map(i=>({src:i.getAttribute('src'),alt:i.alt,width:i.naturalWidth,height:i.naturalHeight,complete:i.complete})))); await browser.close();
