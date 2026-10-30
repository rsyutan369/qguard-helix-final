import {createRequire} from 'node:module';
import {writeFileSync} from 'node:fs';
const require=createRequire('C:/Users/ruel3/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/_entry.cjs');
const {chromium}=require('playwright'); const browser=await chromium.launch({channel:'chrome'}); const results={};
for(const [name,width,height] of [['desktop',1440,1000],['mobile',390,844]]) {
 const page=await browser.newPage({viewport:{width,height}}); const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://localhost:3000/quantum-trust-governance-center');
 for(const asset of ['estate-governance','policy-enforcement','audit-evidence']) {
  const img=page.locator(`img[src='/governance/${asset}.webp']`);
  await img.scrollIntoViewIfNeeded();await img.evaluate(i=>i.decode()); await page.waitForTimeout(1000);
  await img.screenshot({path:`artifacts/governance-hero/${name}-${asset}.png`});
 }
 results[name]=await page.evaluate(()=>({brokenImages:[...document.images].filter(i=>i.complete&&i.naturalWidth===0).map(i=>i.src),overflow:document.documentElement.scrollWidth>innerWidth,generated:[...document.querySelectorAll('img[src^="/governance/"]')].map(i=>({src:i.getAttribute('src'),width:i.naturalWidth,height:i.naturalHeight}))}));results[name].errors=errors;await page.close();
}
console.log(JSON.stringify(results,null,2));writeFileSync('artifacts/governance-hero/image-qa.json',JSON.stringify(results,null,2));await browser.close();
