// All plaintext input paths and the password file must be outside this repository.
import {readFile, writeFile, mkdir, realpath} from 'node:fs/promises';
import {resolve, dirname, relative, isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {encryptPackage} from './crypto.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const [manifestFile, passwordFile, outputPath] = process.argv.slice(2);
if (!manifestFile || !passwordFile || !outputPath) {
  throw new Error('Usage: node private-reports/build.mjs PRIVATE_MANIFEST PRIVATE_PASSWORD_FILE REPORT_DIRECTORY');
}
const isWithin = (base, target) => { const rel=relative(base,target); return rel==='' || (!rel.startsWith('..') && !isAbsolute(rel)); };
async function requirePrivate(path) {
  const actual = await realpath(path);
  if (isWithin(root,actual)) throw new Error('Plaintext input must be outside the public repository');
  return actual;
}
const manifestPath = await requirePrivate(manifestFile);
const secretPath = await requirePrivate(passwordFile);
const output = resolve(outputPath);
if (!isWithin(resolve(root,'informes'),output) || output===resolve(root,'informes')) throw new Error('Output must be a subdirectory of informes');
const manifest = JSON.parse(await readFile(manifestPath,'utf8'));
const password = (await readFile(secretPath,'utf8')).trim();
if (password.length < 24) throw new Error('Use a newly generated password with at least 24 random characters');
const files = [];
const names = new Set();
for (const file of manifest.files) {
  if (!/^[\w. -]+$/.test(file.name) || names.has(file.name)) throw new Error('Invalid or duplicate file name');
  names.add(file.name);
  const source = await requirePrivate(file.source);
  files.push({name:file.name, type:file.type, data:(await readFile(source)).toString('base64')});
}
if (!names.has(manifest.entrypoint) || !names.has(manifest.download)) throw new Error('Missing entrypoint or download package');
const plaintext = new TextEncoder().encode(JSON.stringify({version:1, entrypoint:manifest.entrypoint, download:manifest.download, files}));
try {
  const encrypted = await encryptPackage(plaintext,password);
  await mkdir(output,{recursive:true});
  await writeFile(resolve(output,'bundle.enc'),encrypted);
  await writeFile(resolve(output,'index.html'),await readFile(resolve(root,'private-reports/template.html')));
  console.log(`Encrypted ${files.length} files into ${relative(root,output)}/bundle.enc (${encrypted.length} bytes).`);
} finally { plaintext.fill(0); }
