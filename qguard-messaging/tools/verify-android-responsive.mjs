import assert from 'node:assert/strict';import fs from 'node:fs/promises';import path from 'node:path';
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
const base='http://127.0.0.1:5175';const out=path.resolve('artifacts/android-responsive');
const browser=await chromium.launch({headless:true,channel:'msedge'});
const result={checks:[],screens:[],pageErrors:[],layouts:[]};
const enlarge=async(page,factor)=>{if(factor===1)return;await page.evaluate(f=>{const nodes=[...document.querySelectorAll('body *')].filter(e=>['INPUT','TEXTAREA','SELECT'].includes(e.tagName)||[...e.childNodes].some(n=>n.nodeType===Node.TEXT_NODE&&n.textContent.trim()));const sizes=nodes.map(e=>parseFloat(getComputedStyle(e).fontSize)*f);nodes.forEach((e,i)=>e.style.setProperty('font-size',sizes[i]+'px','important'));},factor);};
const verify=async(page,label)=>{
 const checks=await page.evaluate(()=>{
 const issues=[];const visible=e=>e.getClientRects().length&&getComputedStyle(e).visibility!=='hidden';
 const main=document.querySelector('main'),nav=document.querySelector('nav.mobile-safe-bottom');
 if(document.documentElement.scrollWidth>innerWidth)issues.push('page overflow');
 if(main&&nav&&main.getBoundingClientRect().bottom>nav.getBoundingClientRect().top+1)issues.push('navigation overlays content');
 const nodes=document.querySelectorAll('.workspace-lock-card,.workspace-unlock-methods,input:not([type="hidden"]),textarea,.qg-chat-compose-row');
 for(const e of nodes){if(!visible(e))continue;const r=e.getBoundingClientRect();if(r.left< -1||r.right>innerWidth+1)issues.push(e.tagName+' outside width');}
 for(const b of document.querySelectorAll('.workspace-unlock-methods button,.workspace-lock-actions button')){
 const r=document.createRange();r.selectNodeContents(b);const text=r.getBoundingClientRect(),box=b.getBoundingClientRect();if(text.left<box.left-1||text.right>box.right+1)issues.push('button text overflow: '+b.textContent);
 }
 const buttons=[...document.querySelectorAll('.workspace-unlock-methods button')];for(let i=1;i<buttons.length;i++){const a=buttons[i-1].getBoundingClientRect(),b=buttons[i].getBoundingClientRect();if(Math.abs(a.y-b.y)<2&&a.right>b.left+1)issues.push('overlapping tabs');}
 return issues;
 });assert.deepEqual(checks,[],label);result.layouts.push(label);
};
try{
 for(const theme of ['light','dark']){
 const ctx=await browser.newContext({viewport:{width:320,height:740},isMobile:true,hasTouch:true,colorScheme:theme});await ctx.addInitScript(t=>localStorage.setItem('qguard-messaging-theme',t),theme);
 await ctx.route('**/*',r=>['document','script','stylesheet','image','font'].includes(r.request().resourceType())&&r.request().url().startsWith(base+'/')?r.continue():r.abort());
 const p=await ctx.newPage();p.on('pageerror',e=>result.pageErrors.push(e.message));
 for(const screen of ['vault-setup','chat-setup','vault-unlock','chat-unlock','login','settings','quantum','chat-layout']){
 await p.goto(base+'/tools/android-theme-preview.html?page='+screen,{waitUntil:'domcontentloaded'});await p.locator('#root > *').waitFor();await p.evaluate(()=>document.fonts.ready);await p.waitForTimeout(150);
 if(screen==='chat-layout'){await p.getByRole('button',{name:/Layout test contact/}).first().click();await p.locator('.qg-chat-compose-row').waitFor();}
 await verify(p,`${theme} ${screen} 320px`);
 if(screen.includes('setup')){
 for(const method of await p.getByRole('radio').all()){
 await method.click();await verify(p,`${theme} ${screen} ${await method.innerText()}`);
 if((await method.innerText())==='Pattern'){
 const file=`${theme}-${screen}-pattern.png`;await p.screenshot({path:path.join(out,file),animations:'disabled'});result.screens.push(file);
 }
 }
 await p.getByRole('radio',{name:'Password',exact:true}).click();
 const main=p.locator('main');await main.evaluate(e=>e.scrollTop=0);
 }
 const file=`${theme}-${screen}.png`;await p.screenshot({path:path.join(out,file),animations:'disabled'});result.screens.push(file);
 if(screen.includes('setup')){
 await p.locator('main').evaluate(e=>e.scrollTop=e.scrollHeight);const action=p.getByRole('button',{name:'Set password',exact:true});const rect=await action.boundingBox(),nav=await p.locator('nav').boundingBox();assert(rect.y>=0&&rect.y+rect.height<=nav.y+1,'bottom action can be scrolled above navigation');
 await p.screenshot({path:path.join(out,`${theme}-${screen}-bottom.png`),animations:'disabled'});
 }
 }
 for(const size of [{width:320,height:568},{width:360,height:640},{width:375,height:812},{width:412,height:915},{width:740,height:360}]){
 await p.setViewportSize(size);
 for(const screen of ['vault-setup','chat-setup','login','settings','quantum','chat-layout']){
 await p.goto(base+'/tools/android-theme-preview.html?page='+screen,{waitUntil:'domcontentloaded'});await p.locator('#root > *').waitFor();
 if(screen==='chat-layout'){await p.getByRole('button',{name:/Layout test contact/}).first().click();await p.locator('.qg-chat-compose-row').waitFor();}
 await verify(p,`${theme} ${screen} ${size.width}x${size.height}`);
 }
 }
 await p.setViewportSize({width:320,height:740});
 for(const factor of [1.3,2])for(const screen of ['vault-setup','chat-setup','login','settings','quantum','chat-layout']){
 await p.goto(base+'/tools/android-theme-preview.html?page='+screen,{waitUntil:'domcontentloaded'});await p.locator('#root > *').waitFor();
 if(screen==='chat-layout'){await p.getByRole('button',{name:/Layout test contact/}).first().click();await p.locator('.qg-chat-compose-row').waitFor();}
 await enlarge(p,factor);await verify(p,`${theme} ${screen} text ${factor*100}%`);
 if(screen.includes('setup'))for(const method of await p.getByRole('radio').all()){await method.click();await verify(p,`${theme} ${screen} ${await method.innerText()} text ${factor*100}%`);}
 if(screen==='vault-setup')await p.screenshot({path:path.join(out,`${theme}-vault-text-${factor}.png`),animations:'disabled'});
 }
 await ctx.close();
 }
 assert.deepEqual(result.pageErrors,[]);
 result.checks.push('No horizontal escape, tab overlap or overflowing tab labels across compact/landscape screens and simulated 130%/200% text.','Bottom navigation reserves its real height; bottom setup actions remain reachable.','Actual protected password/PIN/pattern forms and the actual empty chat composer covered in both themes.','All native/account network operations blocked by preview CSP and test routing.');
 await fs.writeFile(path.join(out,'responsive-verification.json'),JSON.stringify(result,null,2));console.log(JSON.stringify({checks:result.checks,layouts:result.layouts.length,errors:result.pageErrors},null,2));
}finally{await browser.close();}
