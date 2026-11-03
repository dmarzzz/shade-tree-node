import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {getEventListeners} from 'node:events';
import {Browsers,runNode,loadChromium} from './lib/clients.mjs';
import {classify} from './lib/classify.mjs';
import {buildReport} from './lib/report.mjs';
const listen=async s=>{await new Promise(r=>s.listen(0,'127.0.0.1',r));return s.address().port;};
const dir=await mkdtemp(join(tmpdir(),'egress-cancel-'));
const sockets=new Set();
let child, sent=0, watchdog;
const server=net.createServer(s=>{
  sockets.add(s);s.on('close',()=>sockets.delete(s));
  s.once('data',()=>{sent=Date.now();child.kill('SIGTERM');});
});
try {
  const port=await listen(server);
  await writeFile(join(dir,'sites.txt'),`web local none https://127.0.0.1:${port}/ local-ok\n`);
  child=spawn(process.execPath,['bench/egress/run.mjs','--label','cancel','--kind','other','--sites',join(dir,'sites.txt'),'--clients','node','--passes','1','--timeout','3','--out',join(dir,'out.jsonl')],{cwd:new URL('../../',import.meta.url),env:{...process.env,CI:'1'},stdio:'ignore'});
  watchdog=setTimeout(()=>child.kill('SIGKILL'),8000);
  const [code,signal]=await new Promise(r=>child.once('exit',(...args)=>r(args)));
  const elapsed=Date.now()-sent;
  assert.equal(signal,null);assert.equal(code,130);assert.ok(sent);assert.ok(elapsed<1000,`SIGTERM exit took ${elapsed}ms`);
  const row=(await readFile(join(dir,'out.jsonl'),'utf8')).trim().split('\n').map(JSON.parse).find(r=>r.type!=='meta');
  assert.equal(row.outcome,'cancelled');assert.equal(row.err,'error:cancelled');
  assert.match(buildReport({rows:[row]}),/can/);
  assert.match(buildReport({rows:[row]}),/operator interruptions/);
  console.log('silent TLS real CLI SIGTERM:',elapsed,'ms, cancelled artifact/report');
} finally {
  clearTimeout(watchdog);if(child?.exitCode===null)child.kill('SIGKILL');
  for(const s of sockets)s.destroy();await new Promise(r=>server.close(r));await rm(dir,{recursive:true,force:true});
}
const closedPeer=net.createServer(s=>s.once('data',()=>s.end()));
try {
  const port=await listen(closedPeer);const start=Date.now();
  const r=await runNode({type:'direct'},{url:`https://127.0.0.1:${port}/`},{timeoutS:3});
  assert.match(r.transport,/^error:(tls-closed|ECONNRESET)$/);assert.ok(Date.now()-start<1000);
  console.log('TLS peer close settles without waiting for deadline');
} finally {await new Promise(r=>closedPeer.close(r));}
const origin=http.createServer((q,r)=>{r.writeHead(200);r.write('<title>local-ok</title>');if(q.url!=='/stall')r.end();});
const port=await listen(origin);
try {
  const ac=new AbortController();const timer=setTimeout(()=>ac.abort(),100);const t=Date.now();
  const result=await runNode({type:'direct'},{url:`http://127.0.0.1:${port}/stall`},{timeoutS:3,signal:ac.signal});clearTimeout(timer);
  assert.equal(result.transport,'error:cancelled');assert.ok(Date.now()-t<1000);assert.equal(getEventListeners(ac.signal,'abort').length,0);
  console.log('HTTP incomplete response cancellation: prompt, no abort listener');
  const chromium=await loadChromium();
  if(!chromium && process.env.REQUIRE_BROWSERS)assert.fail('Chromium required');
  if(chromium)for(const mode of ['headless','headed']){
    if(mode==='headed'&&!process.env.DISPLAY){if(process.env.REQUIRE_BROWSERS)assert.fail('DISPLAY required');continue;}
    const b=await new Browsers({exit:{type:'direct'},modes:[mode],navTimeoutMs:3000,settleMs:2000}).start();
    try {
      await b.startMode(mode);assert.ok(b.browsers.has(mode));
      const c=new AbortController();const timer=setTimeout(()=>c.abort(),100);const start=Date.now();
      const r=await b.run(mode,{url:`http://127.0.0.1:${port}/`},{signal:c.signal,localOnly:true});clearTimeout(timer);
      assert.equal(r.transport,'error:cancelled');assert.equal(classify(r).outcome,'cancelled');assert.ok(Date.now()-start<1000);
      assert.equal(getEventListeners(c.signal,'abort').length,0);
      console.log(mode,'active cancellation:',Date.now()-start,'ms');
    } finally {await b.close();}
  }
} finally {origin.closeAllConnections();await new Promise(r=>origin.close(r));}
for(const mode of ['headless','headed']){
  let closed=0;let release;const launched=new Promise(r=>{release=r;});
  const b=await new Browsers({exit:{type:'direct'},modes:[mode],navTimeoutMs:3000,chromium:{launch:()=>launched}}).start();
  const c=new AbortController();const pending=b.run(mode,{url:'http://127.0.0.1/'},{signal:c.signal});
  c.abort();const start=Date.now();const r=await pending;
  assert.equal(r.transport,'error:cancelled');assert.ok(Date.now()-start<1000);await b.close();
  release({close:async()=>closed++});await new Promise(r=>setTimeout(r,20));
  // Headed launch is intentionally unavailable without DISPLAY in optional-browser runs.
  assert.equal(closed,mode==='headed'&&!process.env.DISPLAY?0:1);
  assert.equal(b.browsers.size,0);console.log(mode,'launch cancellation and late cleanup passed');
}
