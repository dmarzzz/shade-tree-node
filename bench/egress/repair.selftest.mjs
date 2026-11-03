import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import {gzipSync} from 'node:zlib';
import {spawn} from 'node:child_process';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runCurl,runNode,Browsers} from './lib/clients.mjs';
import {buildMeta} from './lib/meta.mjs';
import {probe} from './lib/dial.mjs';
import {validateCohorts} from './lib/report.mjs';
import {parseIpInfo} from './lib/meta.mjs';
assert.equal(parseIpInfo('{"ip":"ecae"}').ip,null);
assert.equal(parseIpInfo('{"ip":"2001:db8::1"}').ip,'2001:db8::1');
const cell={run:'r',exit:'e',client:'node',tier:'web',site:'s',url:'http://127.0.0.1/',pass:1};
assert.throws(()=>validateCohorts([cell,cell],[]),/duplicate/);
assert.throws(()=>validateCohorts([cell,{...cell,run:'r2'}],[]),/mixed/);
assert.match(validateCohorts([cell],[{run:'r',exit:'e',passes:2,clients:['node'],sites:{count:1}}]).join(),/Incomplete/);
let lateClosed = false;
const delayed = await new Browsers({exit:{type:'direct'},modes:['headless'],navTimeoutMs:30,
  chromium:{launch:async()=>{await new Promise(r=>setTimeout(r,100));return {close:async()=>{lateClosed=true;}};}}}).start();
const delayedResult = await delayed.run('headless',{url:'http://127.0.0.1/'});
assert.equal(delayedResult.transport,'timeout');
await new Promise(r=>setTimeout(r,120));assert.equal(lateClosed,true);await delayed.close();
const listen=async s=>{await new Promise(r=>s.listen(0,'127.0.0.1',r));return s.address().port};
const bomb=gzipSync(Buffer.alloc(13*1024*1024,65));
const origin=http.createServer((q,r)=>{
  if(q.url==='/big'){r.setHeader('content-encoding','gzip');r.end(bomb);return;}
  r.statusCode=q.url==='/fail'?503:200;r.end('<title>local-ok</title>');
});
const port=await listen(origin);const site={url:`http://127.0.0.1:${port}/`,okMarker:'local-ok'};
let proxyHits=[];const proxy=http.createServer((q,r)=>{proxyHits.push(q.url);r.end('<title>proxy-ok</title>')});
proxy.on('connect',(q,s)=>{proxyHits.push(q.url);s.end('HTTP/1.1 502 Refused\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')});const pp=await listen(proxy);
const exit={type:'http',host:'127.0.0.1',port:pp};
for(const client of [runCurl,runNode]) {
  const big=await client({type:'direct'},{...site,url:`http://127.0.0.1:${port}/big`},{timeoutS:3});
  assert.match(big.transport,/error:(body-limit|bad-encoding)/);assert.ok(big.body.length<=12*1024*1024);
}
const old={...process.env};
process.env.http_proxy=`http://127.0.0.1:${pp}`;process.env.NO_PROXY='';process.env.no_proxy='';
let r=await runCurl({type:'direct'},site,{timeoutS:2});assert.match(r.body,/local-ok/);assert.equal(proxyHits.length,0);console.log('PASS direct curl ignores ambient http_proxy',proxyHits);
process.env.NO_PROXY='127.0.0.1';process.env.no_proxy='127.0.0.1';proxyHits=[];
r=await runCurl(exit,site,{timeoutS:2});assert.match(r.transport,/error/);assert.equal(proxyHits.length,1);console.log('PASS configured curl proxy ignores NO_PROXY');
for(const k of Object.keys(process.env))if(!(k in old))delete process.env[k];Object.assign(process.env,old);
const dir=await mkdtemp(join(tmpdir(),'pr402-audit-'));const sites=join(dir,'sites.txt');await writeFile(sites,`web local none ${site.url} local-ok\n`);
const cli=(args,env)=>new Promise((resolve,reject)=>{const c=spawn(process.execPath,['bench/egress/run.mjs',...args],{cwd:new URL('../../',import.meta.url),env});let text='';c.stdout.on('data',d=>text+=d);c.stderr.on('data',d=>text+=d);c.on('error',reject);c.on('close',code=>resolve({code,text}));});
proxyHits=[];r=await cli(['--label','audit','--kind','other','--sites',sites,'--clients','node','--passes','1','--gap','0','--out',join(dir,'out.jsonl'),'--exit',`http://127.0.0.1:${pp}`],{...process.env,CI:'1'});assert.equal(r.code,0);assert.ok(!proxyHits.includes('ipinfo.io:443'));console.log('FIX CI loopback CLI attempted external exit lookup (blocked locally)',proxyHits);
const m=buildMeta({args:['--exit','http://private-host.invalid:4444','--lookup-url','http://example.invalid/?token=SYNTHETIC'],exit:{type:'http',host:'private-host.invalid',port:4444}});assert.equal(m.exitSpec,'http://<redacted>');assert.ok(!JSON.stringify(m).includes('SYNTHETIC'));assert.ok(!JSON.stringify(m).includes('private-host.invalid'));console.log('FIX metadata args bypass exit redaction and retain query tokens');
const sockets=new Set();const silent=net.createServer(s=>{sockets.add(s);s.on('close',()=>sockets.delete(s))});const sp=await listen(silent);r=await runNode({type:'socks5',host:'127.0.0.1',port:sp},site,{timeoutS:.1});console.log('SOCKS timeout transport',r.transport);assert.equal(r.transport,'timeout');
const aborter=new AbortController();setTimeout(()=>aborter.abort(),30);
r=await runNode({type:'socks5',host:'127.0.0.1',port:sp},site,{timeoutS:5,signal:aborter.signal});assert.equal(r.transport,'error:cancelled');assert.ok(r.t<0.5);
for(const s of sockets)s.destroy();silent.close();
r=await probe({type:'direct'},site.url);assert.equal(r.error,'invalid-exit-ip');assert.equal(r.body,null);
r=await probe({type:'direct'},`http://127.0.0.1:${port}/fail`);assert.equal(r.code,503);assert.equal(r.error,'http-503');assert.equal(r.body,null);console.log('DIAL HTTP 503 correctly failed',JSON.stringify(r));
const b=await new Browsers({exit:{type:'direct'},modes:['headless','headed'],navTimeoutMs:1000,settleMs:1500}).start();
for(const mode of ['headless','headed']){r=await b.run(mode,site);console.log('BROWSER',mode,JSON.stringify({code:r.code,t:r.t,transport:r.transport}));if (r.transport?.startsWith('error:client-unavailable') && !process.env.REQUIRE_BROWSERS) {console.log(`SKIP ${mode}: ${r.transport}`);continue;}assert.equal(r.transport,'timeout');assert.ok(r.t<1.4)}await b.close();
await rm(dir,{recursive:true,force:true});origin.close();proxy.close();console.log('Repair regressions completed; no public endpoint contacted.');
