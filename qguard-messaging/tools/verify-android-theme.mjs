import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
const output=path.resolve('artifacts/android-premium');await fs.mkdir(output,{recursive:true});
const browser=await chromium.launch({headless:true,channel:'msedge'});
const result={screens:[],checks:[],errors:[],contrast:[]};
const base=(process.env.QGUARD_PREVIEW_URL||'http://127.0.0.1:5174').replace(/\/$/,'');
const url=(screen,extra='')=>`${base}/tools/android-theme-preview.html?page=${screen}${extra}`;
const screens=['dashboard','chat','contacts','calls','vault','quantum','settings','unlock','login','keys','devices','verification','audit','call-display'];
for(const theme of ['light','dark']){
 const context=await browser.newContext({viewport:{width:393,height:852},isMobile:true,hasTouch:true,colorScheme:theme});
 await context.addInitScript(t=>localStorage.setItem('qguard-messaging-theme',t),theme);
 // These are unauthenticated design previews; do not call a production service.
 await context.route('**/*',r=>['document','script','stylesheet','image','font'].includes(r.request().resourceType()) && r.request().url().startsWith(base+'/') ? r.continue() : r.abort());
 const page=await context.newPage();page.on('pageerror',e=>result.errors.push({theme,error:e.message}));
 for(const screen of screens){
  await page.goto(url(screen));await page.locator('body > #root > *').waitFor();await page.evaluate(()=>document.fonts.ready);await page.waitForTimeout(650);
  assert((await page.locator('body').innerText()).length>0,`${screen} renders`);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`${theme} ${screen}: no page overflow`);
  const file=`${theme}-${screen}.png`;await page.screenshot({path:path.join(output,file),animations:'disabled'});result.screens.push(file);
  if(screen==='dashboard'){
   assert.equal(await page.locator('.qg-card').first().evaluate(e=>getComputedStyle(e).borderRadius),'20px');
   for(const name of ['Switch to','Open all security modules']){
    const bounds=await page.getByRole('button',{name:new RegExp(name)}).filter({visible:true}).boundingBox();assert(bounds.width>=48&&bounds.height>=48,'48px masthead targets');
   }
   const samples=await page.evaluate(()=>{
    const style=getComputedStyle(document.documentElement), keys=['--qg-text','--qg-text-2','--qg-text-3','--m-accent-text','--qgp-blue','--qgp-success','--qgp-warning','--qgp-danger'];
    const probe=document.createElement('span');document.body.append(probe);
    const rgb=v=>{probe.style.color=v;return getComputedStyle(probe).color.match(/[\d.]+/g).slice(0,3).map(Number);};
    const lum=c=>c.map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4;}).reduce((v,x,i)=>v+x*[.2126,.7152,.0722][i],0);
    const bg=lum(rgb(style.getPropertyValue('--m-bg')));
    const out=keys.map(k=>{const fg=lum(rgb(style.getPropertyValue(k)));return {token:k,ratio:(Math.max(bg,fg)+.05)/(Math.min(bg,fg)+.05)};});probe.remove();return out;
   });for(const sample of samples){assert(sample.ratio>=4.5,`${theme} ${sample.token} contrast`);result.contrast.push({theme,...sample});}
   await page.getByRole('button',{name:'Open all security modules'}).filter({visible:true}).click();await page.waitForTimeout(300);
   await page.screenshot({path:path.join(output,`${theme}-modules.png`),animations:'disabled'});
   await page.keyboard.press('Escape');
  }
  if(['vault','settings','quantum'].includes(screen)){
   const main=page.locator('main');await main.evaluate(e=>e.scrollTo(0,e.scrollHeight));await page.waitForTimeout(100);
   await page.screenshot({path:path.join(output,`${theme}-${screen}-lower.png`),animations:'disabled'});
  }
  if(screen==='vault'){
   await page.getByRole('tab',{name:'Encrypt & Decrypt Tools',exact:true}).click();await page.waitForTimeout(300);
   await page.screenshot({path:path.join(output,`${theme}-vault-tools.png`),animations:'disabled'});
  }
  if(screen==='login'){
   await page.getByRole('button',{name:/Need an account/}).click();await page.waitForTimeout(200);
   await page.screenshot({path:path.join(output,`${theme}-signup.png`),animations:'disabled'});
   assert(await page.getByLabel('Full name').count()||await page.getByLabel('Name',{exact:true}).count(),'registration fields preserved');
  }
 }
 await context.close();
}
const context=await browser.newContext({viewport:{width:393,height:852},isMobile:true,hasTouch:true});
await context.route('**/*',r=>['document','script','stylesheet','image','font'].includes(r.request().resourceType()) && r.request().url().startsWith(base+'/') ? r.continue() : r.abort());
const page=await context.newPage();page.on('pageerror',e=>result.errors.push({phase:'interaction',error:e.message}));
await page.goto(url('dashboard'));
await page.getByRole('button',{name:'Switch to dark mode',exact:true}).filter({visible:true}).click();
await page.waitForFunction(()=>document.documentElement.classList.contains('theme-dark'));
assert.equal(await page.evaluate(()=>localStorage.getItem('qguard-messaging-theme')),'dark');
await page.reload();await page.getByRole('button',{name:'Switch to light mode',exact:true}).filter({visible:true}).click();
await page.waitForFunction(()=>document.documentElement.classList.contains('theme-light'));
result.checks.push('Masthead theme toggle persists dark mode through reload and returns to light.');
await page.goto(url('settings'));await page.getByRole('button',{name:'Toggle Theme',exact:true}).click();
await page.waitForFunction(()=>document.documentElement.classList.contains('theme-dark'));
result.checks.push('Existing Settings theme action also remains functional.');
for(const size of [{width:320,height:568},{width:360,height:640},{width:852,height:393},{width:768,height:1024}]){
 await page.setViewportSize(size);
 for(const screen of ['dashboard','chat','vault','settings','unlock','login']){
  await page.goto(url(screen));await page.waitForTimeout(150);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`${screen} ${size.width}: horizontal overflow`);
  if(await page.locator('.qg-nav').count()){
   const rect=await page.locator('.qg-nav').boundingBox();assert(rect.y>=0&&rect.y+rect.height<=size.height+1,'bottom navigation fits');
   const main=page.locator('main');await main.evaluate(e=>e.scrollTo(0,e.scrollHeight));
   assert.equal(await main.evaluate(e=>e.scrollLeft),0);
  }
 }
 result.checks.push(`Six primary surfaces fit ${size.width}×${size.height} without horizontal page overflow; bottom navigation stays visible.`);
}
await page.setViewportSize({width:393,height:852});await page.goto(url('dashboard'));await page.emulateMedia({reducedMotion:'reduce'});
assert.equal(await page.locator('.qg-rise').first().evaluate(e=>getComputedStyle(e).animationName),'none');
assert.equal(await page.locator('.qgm-core-mark svg').evaluate(e=>getComputedStyle(e).animationName),'none');
result.checks.push('Reduced motion removes entrances and continuous decorative animation.');
await page.emulateMedia({reducedMotion:'no-preference'});
await page.goto(url('login','&desktop=1'));await page.waitForTimeout(1000);
const appearance=()=>page.locator('.qg-login,.qg-shell,input,.qg-cta').evaluateAll(nodes=>nodes.map(e=>{const s=getComputedStyle(e);return [s.color,s.background,s.borderRadius,s.fontFamily,s.boxShadow];}));
const before=await appearance();await page.evaluate(()=>document.querySelector('style[data-vite-dev-id$="/android-premium.css"]').remove());assert.deepEqual(await appearance(),before);
result.checks.push('Premium stylesheet has no effect outside the Android skin boundary.');
await context.close();
assert.deepEqual(result.errors,[],'no React/page errors');
await fs.writeFile(path.join(output,'verification.json'),JSON.stringify(result,null,2));
console.log(JSON.stringify(result,null,2));await browser.close();
