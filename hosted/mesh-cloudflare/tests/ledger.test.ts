import { describe, expect, test } from 'bun:test';
import { Database } from 'bun:sqlite';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { ChainStore, type Storage } from '../src/ledger';
import { canonical, digest, hex, signedResponse, validateRequest, verify, ZERO, type Body } from '../src/protocol';

const seed = '11'.repeat(32); // Synthetic test key, never a live identity.
const pkcs8 = '302e020100300506032b657004220420' + seed;
const priv = createPrivateKey({key: Buffer.from(pkcs8,'hex'),format:'der',type:'pkcs8'});
const pub = hex(createPublicKey(priv).export({format:'der',type:'spki'}).subarray(-32));
async function sign(body: Body): Promise<Body> {
  const key = await crypto.subtle.importKey('pkcs8', Buffer.from(pkcs8,'hex'), 'Ed25519', false, ['sign']);
  return {...body, signature: hex(await crypto.subtle.sign('Ed25519',key,new TextEncoder().encode(canonical(body))))};
}
async function block(height=1, previous=ZERO) {
  return sign({v:1, stream:pub, height, previous, nonce:'33'.repeat(12), ciphertext:'44'.repeat(32)});
}
async function request(b: Body, op='put') {
  return sign({v:1,stream:pub,op,height:b.height,nonce:'55'.repeat(16),...(op==='put'?{block:b}:{})});
}
function storage() {
  const db = new Database(':memory:');
  let syncs = 0;
  const value: Storage = {
    sql: {exec(sql,...args) {const rows=db.query(sql).all(...args);return {toArray:()=>rows};}},
    transactionSync: fn => db.transaction(fn)(),
    sync: async () => { syncs++; },
  };
  return {db,value,get syncs(){return syncs;}};
}

describe('hosted mesh integrity', () => {
  test('canonical Python wire subset and SHA-256 are stable', async () => {
    expect(canonical({z:null,a:{v:1,key:'abc'},b:false})).toBe('{"a":{"key":"abc","v":1},"b":false,"z":null}');
    expect(await digest({a:1})).toBe('015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862');
  });
  test('transactional append and duplicate retry preserve head', async () => {
    const s=storage(), ledger=new ChainStore(s.value,8192), b=await block();
    await ledger.append(b); await ledger.append(b);
    expect(s.syncs).toBe(2);
    expect(s.db.query('SELECT count(*) AS n FROM blocks').get()).toEqual({n:1});
    expect(await ledger.head(pub)).toEqual(b);
  });
  test('fork and gap fail without changing committed head', async () => {
    const s=storage(), ledger=new ChainStore(s.value,8192), b=await block();
    await ledger.append(b);
    const {signature,...unsigned}=b; const fork=await sign({...unsigned,nonce:'66'.repeat(12)});
    await expect(ledger.append(fork)).rejects.toThrow();
    await expect(ledger.append(await block(3,await digest(b)))).rejects.toThrow();
    expect(await ledger.head(pub)).toEqual(b);
  });
  test('capacity refusal preserves existing records', async () => {
    const s=storage(), ledger=new ChainStore(s.value,8192);
    const b=await sign({v:1,stream:pub,height:1,previous:ZERO,nonce:'33'.repeat(12),ciphertext:'44'.repeat(5000)});
    await expect(ledger.append(b)).rejects.toThrow();
    expect(await ledger.head(pub)).toBeNull();
  });
  test('interruption before metadata commit rolls back block insertion', async () => {
    const s=storage(); const normal=s.value.sql.exec;
    s.value.sql.exec=(sql,...args)=>{if(sql.startsWith('INSERT INTO chain'))throw Error('interrupted');return normal(sql,...args);};
    const ledger=new ChainStore(s.value,8192);
    await expect(ledger.append(await block())).rejects.toThrow();
    expect(s.db.query('SELECT count(*) AS n FROM blocks').get()).toEqual({n:0});
  });
  test('durability synchronization failure is not a successful receipt', async () => {
    const s=storage(), ledger=new ChainStore(s.value,8192);
    s.value.sync=async()=>{throw Error('durability unavailable');};
    await expect(ledger.append(await block())).rejects.toThrow();
    expect(s.syncs).toBe(0);
  });
  test('unenrolled producer and changed request cannot authorize storage', async () => {
    const b=await block(), req=await request(b);
    await expect(validateRequest(req,[])).rejects.toThrow();
    await expect(validateRequest({...req,nonce:'77'.repeat(16)},[pub])).rejects.toThrow();
    await validateRequest(req,[pub]);
  });
  test('signed response binds nonce, request digest and committed block', async () => {
    const b=await block(), req=await request(b);
    const res=await signedResponse(req,b,pkcs8,pub);
    await verify(res,pub);
    expect(res.nonce).toBe(req.nonce);
    expect(res.request).toBe(await digest(req));
    expect(res.digest).toBe(await digest(b));
    await expect(verify({...res,height:2},pub)).rejects.toThrow();
  });
  test('changed persisted bytes and missing blocks remain explicit', async () => {
    const s=storage(), ledger=new ChainStore(s.value,8192), b=await block();
    await ledger.append(b);
    s.db.query('UPDATE blocks SET data=? WHERE height=1').run(canonical({...b,nonce:'66'.repeat(12)}));
    await expect(ledger.head(pub)).rejects.toThrow();
    s.db.query('DELETE FROM blocks').run();
    await expect(ledger.get(1,pub)).rejects.toThrow();
  });
});
