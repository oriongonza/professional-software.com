import {decryptPackage} from './crypto.js';

const get = id => document.getElementById(id);
const gate=get('gate'), form=get('unlock-form'), password=get('password'), button=get('unlock-button');
const status=get('status'), workspace=get('workspace'), viewer=get('viewer-host'), download=get('download-all');
const urls=new Set();
let busy=false, generation=0;

function objectURL(bytes,type) {
  const url=URL.createObjectURL(new Blob([bytes],{type}));
  urls.add(url); return url;
}
function clearSession() {
  generation++;
  viewer.replaceChildren();
  download.removeAttribute('href'); download.removeAttribute('download');
  urls.forEach(url=>URL.revokeObjectURL(url)); urls.clear();
  workspace.hidden=true; gate.hidden=false;
  document.body.classList.remove('is-unlocked');
  password.value=''; password.type='password'; password.disabled=false;
  get('toggle-password').setAttribute('aria-pressed','false');
  get('toggle-password').setAttribute('aria-label','Mostrar contraseña');
  get('toggle-password').textContent='Mostrar';
  button.disabled=!crypto?.subtle; busy=false; status.textContent='';
}
function decodeFile(file) {
  const binary=atob(file.data), bytes=new Uint8Array(binary.length);
  for(let i=0;i<binary.length;i++)bytes[i]=binary.charCodeAt(i);
  return bytes;
}
// Runs inside the opaque report iframe, so download URLs belong to that document.
function attachPrivateFiles() {
  const node=document.getElementById('private-attachments');
  const files=JSON.parse(node.textContent), links=new Map(), created=[];
  node.remove();
  for(const file of files){
    const raw=atob(file.data),bytes=new Uint8Array(raw.length);
    for(let i=0;i<raw.length;i++)bytes[i]=raw.charCodeAt(i);
    const url=URL.createObjectURL(new Blob([bytes],{type:file.type}));
    created.push(url);links.set(file.name,{url,type:file.type});
  }
  document.querySelectorAll('a[href]').forEach(anchor=>{
    const name=anchor.getAttribute('href'),file=links.get(name);
    if(!file)return;
    anchor.href=file.url;
    if(file.type==='application/pdf'){
      anchor.target='_blank';anchor.rel='noopener noreferrer';
    } else {anchor.download=name;}
  });
  window.addEventListener('pagehide',()=>created.forEach(url=>URL.revokeObjectURL(url)));
}
function openReport(pack) {
  if(pack.version!==1 || !Array.isArray(pack.files))throw new Error('Invalid package');
  const files=new Map(pack.files.map(file=>[file.name,file]));
  const entry=files.get(pack.entrypoint), archive=files.get(pack.download);
  if(!entry || entry.type!=='text/html' || !archive)throw new Error('Incomplete package');
  const doc=new DOMParser().parseFromString(new TextDecoder().decode(decodeFile(entry)),'text/html');
  // Self-contained authored reports only: never resolve private paths on the host.
  if(doc.querySelector('[src], [srcset], link[href], base, iframe, object, embed, form')) {
    throw new Error('The report must be self-contained');
  }
  if(/url\s*\(|@import/i.test(doc.querySelector('style')?.textContent??''))throw new Error('External styles are not allowed');
  doc.querySelectorAll('a[href]').forEach(anchor=>{
    const href=anchor.getAttribute('href');
    if(!href.startsWith('#') && !href.startsWith('https://') && !files.has(href))throw new Error('Unpackaged link');
  });
  const policy=doc.createElement('meta');
  policy.httpEquiv='Content-Security-Policy';
  policy.content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; connect-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-src 'none'";
  doc.head.prepend(policy);
  const attachments=doc.createElement('script');
  attachments.id='private-attachments';attachments.type='application/json';
  attachments.textContent=JSON.stringify(pack.files.filter(file=>file.name!==pack.entrypoint && file.name!==pack.download)).replaceAll('<','\\u003c');
  const setup=doc.createElement('script');setup.textContent=`(${attachPrivateFiles.toString()})();`;
  doc.body.append(attachments,setup);
  const frame=document.createElement('iframe');
  frame.title='Informe privado';
  frame.setAttribute('sandbox','allow-scripts allow-downloads allow-modals allow-popups allow-popups-to-escape-sandbox');
  frame.setAttribute('referrerpolicy','no-referrer');
  frame.src=objectURL(new TextEncoder().encode('<!doctype html>\n'+doc.documentElement.outerHTML),'text/html');
  viewer.replaceChildren(frame);
  download.href=objectURL(decodeFile(archive),archive.type); download.download=archive.name;
  password.value='';
  gate.hidden=true; workspace.hidden=false;
  document.body.classList.add('is-unlocked');
  window.scrollTo(0,0);
}
get('toggle-password').addEventListener('click',()=>{
  const show=password.type==='password';password.type=show?'text':'password';
  get('toggle-password').setAttribute('aria-pressed',String(show));
  get('toggle-password').setAttribute('aria-label',show?'Ocultar contraseña':'Mostrar contraseña');
  get('toggle-password').textContent=show?'Ocultar':'Mostrar';
});
get('lock-button').addEventListener('click',()=>{clearSession();password.focus()});
window.addEventListener('pagehide',clearSession);
form.addEventListener('submit',async event=>{
  event.preventDefault();
  if(busy || !crypto?.subtle)return;
  let secret=password.value.trim();
  if(!secret){password.focus();return;}
  const current=++generation;
  busy=true; button.disabled=true; password.disabled=true; status.textContent='Abriendo informe…';
  let plain;
  try {
    const response=await fetch('./bundle.enc',{credentials:'omit',referrerPolicy:'no-referrer'});
    if(!response.ok)throw new Error('Download failed');
    plain=await decryptPackage(await response.arrayBuffer(),secret);
    secret='';
    if(current!==generation)return;
    const pack=JSON.parse(new TextDecoder().decode(plain));
    openReport(pack); status.textContent='';
  } catch(error) {
    if(current!==generation)return;
    viewer.replaceChildren(); urls.forEach(url=>URL.revokeObjectURL(url));urls.clear();
    status.textContent='No se pudo abrir el informe. Comprueba la contraseña y tu conexión e inténtalo de nuevo.';
    password.disabled=false;password.focus();password.select();
  } finally {
    secret=''; if(plain)plain.fill(0);
    if(current===generation){busy=false;button.disabled=false;password.disabled=false;}
  }
});
if(window.isSecureContext && crypto?.subtle)button.disabled=false;
else status.textContent='Abre este enlace HTTPS en un navegador actualizado para acceder al informe.';
