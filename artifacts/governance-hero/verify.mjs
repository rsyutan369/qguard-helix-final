import { createRequire } from 'node:module';
import { writeFileSync } from 'node:fs';
const require=createRequire('C:/Users/ruel3/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/_entry.cjs');
const {chromium}=require('playwright');
const browser=await chromium.launch({channel:'chrome',headless:true});
const results={};
for(const [name,width,height,reduced] of [['desktop',1440,1000,false],['mobile',390,844,false],['tablet',768,1024,false],['reduced',1440,900,true]]){
 const page=await browser.newPage({viewport:{width,height},reducedMotion:reduced?'reduce':'no-preference'});
 const errors=[]; page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://localhost:3000/quantum-trust-governance-center');
 await page.waitForSelector('.governance-photonic-hero');
 await page.waitForTimeout(5000);
 await page.screenshot({path:`artifacts/governance-hero/${name}.png`});
 results[name]=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth,heading:document.querySelector('h1')?.innerText,canvas:!!document.querySelector('.governance-photonic-field canvas'),video:{ready:document.querySelector('video').readyState,paused:document.querySelector('video').paused,time:document.querySelector('video').currentTime,error:document.querySelector('video').error?.message},heroHeight:document.querySelector('.governance-photonic-hero').getBoundingClientRect().height,links:[...document.querySelectorAll('.governance-photonic-hero a')].map(a=>a.getAttribute('href'))}));
 results[name].errors=errors;
 if(!reduced){
  await page.getByRole('button',{name:'Pause light animation'}).click();
  await page.waitForTimeout(200);
  const t=await page.locator('video').evaluate(v=>v.currentTime);
  await page.waitForTimeout(350);
  results[name].pauseWorks=await page.locator('video').evaluate((v,t)=>v.paused&&v.currentTime===t,t);
  await page.getByRole('button',{name:'Play light animation'}).click();
  await page.waitForTimeout(400);
  results[name].resumeWorks=await page.locator('video').evaluate(v=>!v.paused);
  await page.getByRole('link',{name:'Explore capabilities'}).click();
  results[name].anchor=await page.evaluate(()=>location.hash);
 }
 await page.close();
}
writeFileSync('artifacts/governance-hero/qa.json',JSON.stringify(results,null,2)); console.log(JSON.stringify(results,null,2)); await browser.close();
