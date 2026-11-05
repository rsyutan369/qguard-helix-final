import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';import assert from 'node:assert/strict';
const args=process.argv.slice(2),arg=(key,fallback)=>args.includes('--'+key)?args[args.indexOf('--'+key)+1]:fallback;
const app=path.resolve(arg('app','src-tauri/target/onboarding-android/release/qguard-messaging.exe'));
const setup=path.resolve(arg('setup','src-tauri/target/onboarding-android/release/bundle/nsis/QGuard Messaging_1.5.0_x64-setup.exe'));
const output=path.resolve(arg('output','artifacts/final-logo-release-20261105/windows-verification.json'));
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const ico=fs.readFileSync('src-tauri/icons/icon.ico'),expectedIcons=[];
assert.equal(ico.readUInt16LE(2),1);for(let i=0;i<ico.readUInt16LE(4);i++){const e=6+i*16,len=ico.readUInt32LE(e+8),off=ico.readUInt32LE(e+12);expectedIcons.push({size:ico[e]||256,sha256:hash(ico.subarray(off,off+len))});}
function inspectPe(file){
 const bytes=fs.readFileSync(file);assert.equal(bytes.toString('ascii',0,2),'MZ');const pe=bytes.readUInt32LE(60);assert.equal(bytes.toString('binary',pe,pe+4),'PE\x00\x00');const machine=bytes.readUInt16LE(pe+4),count=bytes.readUInt16LE(pe+6),opt=pe+24,magic=bytes.readUInt16LE(opt),dd=opt+(magic===0x20b?112:96),resourceRva=bytes.readUInt32LE(dd+16);assert(resourceRva>0,'No native resources');
 const sections=[];for(let i=0,off=opt+bytes.readUInt16LE(pe+20);i<count;i++,off+=40)sections.push({rva:bytes.readUInt32LE(off+12),size:Math.max(bytes.readUInt32LE(off+8),bytes.readUInt32LE(off+16)),raw:bytes.readUInt32LE(off+20)});
 const offset=rva=>{const sec=sections.find(s=>rva>=s.rva&&rva<s.rva+s.size);assert(sec,'Resource RVA outside PE sections');return sec.raw+rva-sec.rva;};
 const root=offset(resourceRva),resources=[];
 const walk=(relative,ids=[])=>{assert(ids.length<5,'Invalid resource depth');const d=root+relative,total=bytes.readUInt16LE(d+12)+bytes.readUInt16LE(d+14);for(let i=0;i<total;i++){const e=d+16+i*8,name=bytes.readUInt32LE(e),next=bytes.readUInt32LE(e+4),id=name&0x80000000?'named':name;if(next&0x80000000)walk(next&0x7fffffff,[...ids,id]);else{const data=root+next,rva=bytes.readUInt32LE(data),size=bytes.readUInt32LE(data+4),start=offset(rva);assert(start+size<=bytes.length);resources.push({ids:[...ids,id],data:bytes.subarray(start,start+size)});}}};walk(0);
 const nativeIcons=resources.filter(r=>r.ids[0]===3).map(r=>hash(r.data));for(const icon of expectedIcons)assert(nativeIcons.includes(icon.sha256),path.basename(file)+': final icon missing at '+icon.size+'px');
 return {file,bytes:bytes.length,sha256:hash(bytes),machine:machine===0x8664?'x86_64':machine===0x14c?'x86':machine.toString(16),finalIconSizesVerified:expectedIcons.map(i=>i.size),nativeIconResources:nativeIcons.length,raw:bytes};
}
const appReport=inspectPe(app),setupReport=inspectPe(setup);assert.equal(appReport.machine,'x86_64');
const html=fs.readFileSync('dist/index.html','utf8'),assets=[...html.matchAll(/\/assets\/([^"\s]+)/g)].map(m=>m[1]);for(const asset of assets)assert(appReport.raw.includes(Buffer.from(asset)),'Stale Windows UI: '+asset);assert(fs.statSync(app).mtimeMs>=fs.statSync('dist/index.html').mtimeMs,'Windows executable older than UI');
const config=JSON.parse(fs.readFileSync('src-tauri/tauri.conf.json','utf8'));
const decodeText=s=>s.trim().startsWith('untrusted comment:')?s.trim():Buffer.from(s.trim(),'base64').toString('utf8').trim();
const publicLines=decodeText(config.plugins.updater.pubkey).split(/\r?\n/),pubPacket=Buffer.from(publicLines[1],'base64');assert.equal(pubPacket.length,42);
const sigFile=setup+'.sig',lines=decodeText(fs.readFileSync(sigFile,'utf8')).split(/\r?\n/),sigPacket=Buffer.from(lines[1],'base64'),globalSignature=Buffer.from(lines[3],'base64');assert.equal(sigPacket.length,74);assert.equal(globalSignature.length,64);assert(lines[2].startsWith('trusted comment: '));assert(pubPacket.subarray(2,10).equals(sigPacket.subarray(2,10)),'Updater key ID mismatch');
const algorithm=sigPacket.toString('ascii',0,2);assert(['ED','Ed'].includes(algorithm));const key=crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),pubPacket.subarray(10)]),format:'der',type:'spki'});
const signature=sigPacket.subarray(10),payload=algorithm==='ED'?crypto.createHash('blake2b512').update(setupReport.raw).digest():setupReport.raw;
assert(crypto.verify(null,payload,key,signature),'Installer updater signature invalid');assert(crypto.verify(null,Buffer.concat([signature,Buffer.from(lines[2].slice(17))]),key,globalSignature),'Updater trusted-comment signature invalid');
const tampered=Buffer.from(payload);tampered[0]^=1;assert.equal(crypto.verify(null,tampered,key,signature),false,'Tampering not rejected');
delete appReport.raw;delete setupReport.raw;
const result={application:appReport,installer:setupReport,uiAssets:assets,updaterSignatureVerified:true,updaterPublicKeyMatchesAppConfig:true,updaterTrustedCommentVerified:true,tamperingRejected:true,signatureAlgorithm:algorithm==='ED'?'Ed25519 with BLAKE2b-512':'Ed25519',version:config.version};fs.writeFileSync(output,JSON.stringify(result,null,2));console.log(JSON.stringify(result,null,2));
