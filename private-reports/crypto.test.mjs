import {test} from 'node:test';
import assert from 'node:assert/strict';
import {encryptPackage,decryptPackage} from './crypto.js';

const password='Only-a-test-password-not-used-for-a-real-report';
const plain=new TextEncoder().encode('Private test document with UTF-8: producción, € and 761.');
test('round trip preserves every byte with a fresh random envelope',async()=>{
  const a=await encryptPackage(plain,password), b=await encryptPackage(plain,password);
  assert.notDeepEqual(a,b);
  assert.deepEqual(await decryptPackage(a,password),plain);
  assert.deepEqual(await decryptPackage(b,password),plain);
  assert.ok(!Buffer.from(a).includes(Buffer.from('Private test document')));
});
test('wrong password never returns plaintext',async()=>{
  const envelope=await encryptPackage(plain,password);
  await assert.rejects(decryptPackage(envelope,password+'wrong'));
});
test('header, nonce, ciphertext and authentication tag tampering fail closed',async()=>{
  const envelope=await encryptPackage(plain,password);
  for(const offset of [0,8,24,36,envelope.length-1]){
    const damaged=envelope.slice();damaged[offset]^=1;
    await assert.rejects(decryptPackage(damaged,password));
  }
  await assert.rejects(decryptPackage(envelope.slice(0,35),password));
  await assert.rejects(decryptPackage(envelope.slice(0,-1),password));
});
