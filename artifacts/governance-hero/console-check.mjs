import { createRequire } from 'node:module';
const require=createRequire('C:/Users/ruel3/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/_entry.cjs');
const {chromium}=require('playwright');
const browser=await chromium.launch({channel:'chrome'});
const page=await browser.newPage(); const errors=[]; page.on('response',r=>{if(r.status()>=400)console.log(r.status(),r.url());});
page.on('console',m=>{if(m.type()==='error')errors.push({text:m.text(),location:m.location()});});
await page.goto('http://localhost:3000/quantum-trust-governance-center');
await page.waitForTimeout(2500);
console.log(JSON.stringify({consoleErrors:errors}));
await browser.close();


