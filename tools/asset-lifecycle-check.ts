/** Run with tsx. Exercises the scanner router and SSE against a local storage fixture. */
import assert from 'node:assert/strict'
import express from 'express'
import { createServer } from 'node:http'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'

const owner = randomUUID()
const other = randomUUID()
const asset = {id: randomUUID(), user_id: owner, name:'fixture-owned', status:'active',type:'server',metadata:{}}
const another = {id: randomUUID(), user_id: other, name:'fixture-other',status:'active',type:'server',metadata:{}}
const assets = [asset, another]
const audits: object[] = []
const db = createServer(async (req,res) => {
  const url = new URL(req.url!, 'http://localhost')
  res.setHeader('content-type','application/json')
  if (url.pathname === '/auth/v1/user') {
    const jwt = req.headers.authorization?.split(' ')[1]
    const userId = jwt === a ? owner : jwt === b ? other : null
    res.statusCode = userId ? 200 : 401
    res.end(JSON.stringify(userId ? {id:userId, aud:'authenticated',role:'authenticated',app_metadata:{},user_metadata:{}} : {}))
    return
  }
  const body = []
  for await (const bytes of req) body.push(bytes)
  const table = url.pathname.split('/').at(-1)
  const userId = url.searchParams.get('user_id')?.replace(/^eq\./,'')
  if (table === 'assets') {
    let rows = assets.filter((item) => item.user_id === userId)
    const ids = url.searchParams.get('id')?.slice(4,-1).split(',')
    if (ids) rows = rows.filter((item) => ids.includes(item.id))
    if (url.searchParams.get('status') === 'eq.archived') rows = rows.filter((item) => item.status === 'archived')
    if (req.method === 'PATCH') {
      assert.equal(req.headers.authorization, 'Bearer '+a)
      for (const row of rows) if (row.status !== 'deleted') Object.assign(row,JSON.parse(Buffer.concat(body).toString()))
    }
    res.end(JSON.stringify(rows))
  } else {
    if (table === 'audit_logs' && req.method === 'POST') audits.push(JSON.parse(Buffer.concat(body).toString()))
    res.end('[]')
  }
})
const jwt = (id:string) => [JSON.stringify({alg:'HS256',typ:'JWT'}), JSON.stringify({sub:id,exp:Math.floor(Date.now()/1000)+300}), 'fixture'].map(x=>Buffer.from(x).toString('base64url')).join('.')
const a = jwt(owner), b = jwt(other)
db.listen(0,'127.0.0.1')
await once(db,'listening')
process.env.VITE_SUPABASE_URL = 'http://127.0.0.1:'+ (db.address() as {port:number}).port
process.env.VITE_SUPABASE_ANON_KEY='isolated-fixture-key'
process.env.SUPABASE_SERVICE_ROLE_KEY=''
const { default: router } = await import('../src/api-server/scanner')
const app = express()
app.use(express.json())
app.use(router)
const server = app.listen(0,'127.0.0.1')
await once(server,'listening')
const base = 'http://127.0.0.1:'+(server.address() as {port:number}).port
const headers = { Authorization:'Bearer '+a, 'Content-Type':'application/json'}
const controller = new AbortController()
const mutate = async (action:string, ids:string[], auth=headers) => {
 const result = await fetch(base+'/assets/lifecycle',{method:'POST',body:JSON.stringify({action,ids}),headers:auth})
 assert.equal(result.status,200)
 return (await result.json()).data
}
try {
 const denied = await fetch(base+'/assets/lifecycle',{method:'POST'})
 assert.equal(denied.status, 401)
 const response = await fetch(base+'/intelligence/stream',{headers,signal:controller.signal})
 assert.equal(response.status,200)
 const reader = response.body!.pipeThrough(new TextDecoderStream()).getReader()
 let buffer = ''
 async function snapshot() {
   const end = Date.now()+5000
   while (Date.now()<end) {
     while (buffer.includes('\n\n')) {
       const delimiter=buffer.indexOf('\n\n')
       const frame=buffer.slice(0,delimiter)
       buffer=buffer.slice(delimiter+2)
       if (frame.startsWith('event: scanner-intelligence\n')) return JSON.parse(frame.split('\ndata: ')[1])
     }
     const {value, done} = await Promise.race([reader.read(), new Promise<never>((_,rej)=>setTimeout(()=>rej(Error('SSE timed out')),5000))])
     assert(!done)
     buffer += value
   }
   throw Error('No snapshot')
 }
 assert.deepEqual((await snapshot()).assets.assets.map((row:{id:string})=>row.id),[asset.id])
 assert.deepEqual(await mutate('archive',[asset.id,another.id]),{updatedIds:[asset.id],skipped:1})
 assert.equal(another.status,'active')
 const archived = await snapshot()
 assert.equal(archived.assets.assets.length,0)
 assert.equal(archived.assets.archived[0].id,asset.id)
 assert.deepEqual(await mutate('restore',[asset.id]),{updatedIds:[asset.id],skipped:0})
 assert.equal((await snapshot()).assets.assets.length,1)
 assert.deepEqual(await mutate('remove',[asset.id]),{updatedIds:[asset.id],skipped:0})
 const removed = await snapshot()
 assert.equal(removed.assets.assets.length,0)
 assert.equal(removed.assets.archived.length,0)
 assert.deepEqual(await mutate('restore',[asset.id]),{updatedIds:[],skipped:1})
 assert.equal(audits.length,3)
 console.log('PASS API: authenticated archive, restore, remove, audit, cross-tenant refusal, and immediate persisted SSE snapshots')
} finally { controller.abort(); server.closeAllConnections(); server.close();db.closeAllConnections();db.close() }
