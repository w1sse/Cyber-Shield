/* Cyber-Shield: компактный декодер QR-кодов (версии 1-10, режимы: цифры, буквы, байты).
   Без сторонних библиотек. Использование: CSQR.decode(imageData) -> строка или null. */
(function(g){"use strict";
/* ---------- GF(256) и Рид-Соломон ---------- */
const EXP=new Uint8Array(512),LOG=new Uint8Array(256);
{let v=1;for(let i=0;i<255;i++){EXP[i]=v;LOG[v]=i;v<<=1;if(v&256)v^=0x11d}for(let i=255;i<512;i++)EXP[i]=EXP[i-255]}
const mul=(a,b)=>a&&b?EXP[LOG[a]+LOG[b]]:0,inv=a=>EXP[255-LOG[a]];
function rsCorrect(cw,ec){
  const n=cw.length,S=new Array(ec).fill(0);let clean=true;
  for(let i=0;i<ec;i++){let s=0;for(let j=0;j<n;j++)s=mul(s,EXP[i])^cw[j];S[i]=s;if(s)clean=false}
  if(clean)return cw;
  let C=[1],B=[1],L=0,m=1,b=1;
  for(let k=0;k<ec;k++){
    let d=S[k];for(let i=1;i<=L;i++)d^=mul(C[i]||0,S[k-i]);
    if(!d){m++;continue}
    const T=C.slice(),coef=mul(d,inv(b)),sh=new Array(m).fill(0).concat(B.map(v=>mul(v,coef)));
    while(C.length<sh.length)C.push(0);for(let i=0;i<sh.length;i++)C[i]^=sh[i];
    if(2*L<=k){L=k+1-L;B=T;b=d;m=1}else m++}
  if(L>ec/2)return null;
  const out=cw.slice(),pos=[];
  for(let k=0;k<n;k++){let s=0;const xi=(255-k)%255;for(let i=0;i<=L;i++)s^=mul(C[i]||0,EXP[(xi*i)%255]);if(!s)pos.push(k)}
  if(pos.length!==L)return null;
  const O=new Array(ec).fill(0);for(let i=0;i<ec;i++){let s=0;for(let j=0;j<=i;j++)s^=mul(C[j]||0,S[i-j]);O[i]=s}
  for(const k of pos){const xi=(255-k)%255,X=EXP[k];let om=0,dl=0;
    for(let i=0;i<ec;i++)om^=mul(O[i],EXP[(xi*i)%255]);
    for(let i=1;i<=L;i+=2)dl^=mul(C[i]||0,EXP[(xi*(i-1))%255]);
    if(!dl)return null;out[n-1-k]^=mul(X,mul(om,inv(dl)))}
  for(let i=0;i<ec;i++){let s=0;for(let j=0;j<n;j++)s=mul(s,EXP[i])^out[j];if(s)return null}
  return out}
/* ---------- таблицы версий 1-10: по уровням L,M,Q,H: [EC на блок, блоков1, данных1, блоков2, данных2] ---------- */
const BLK={1:[[7,1,19],[10,1,16],[13,1,13],[17,1,9]],2:[[10,1,34],[16,1,28],[22,1,22],[28,1,16]],3:[[15,1,55],[26,1,44],[18,2,17],[22,2,13]],4:[[20,1,80],[18,2,32],[26,2,24],[16,4,9]],5:[[26,1,108],[24,2,43],[18,2,15,2,16],[22,2,11,2,12]],6:[[18,2,68],[16,4,27],[24,4,19],[28,4,15]],7:[[20,2,78],[18,4,31],[18,2,14,4,15],[26,4,13,1,14]],8:[[24,2,97],[22,2,38,2,39],[22,4,18,2,19],[26,4,14,2,15]],9:[[30,2,116],[22,3,36,2,37],[20,4,16,4,17],[24,4,12,4,13]],10:[[18,2,68,2,69],[26,4,43,1,44],[24,6,19,2,20],[28,6,15,2,16]]};
const ALIGN={2:[6,18],3:[6,22],4:[6,26],5:[6,30],6:[6,34],7:[6,22,38],8:[6,24,42],9:[6,26,46],10:[6,28,50]};
const ECIDX=[1,0,3,2],ALNUM="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
const MASKS=[(y,x)=>(y+x)%2===0,(y,x)=>y%2===0,(y,x)=>x%3===0,(y,x)=>(y+x)%3===0,(y,x)=>(((y>>1)+Math.floor(x/3))%2)===0,(y,x)=>((y*x)%2+(y*x)%3)===0,(y,x)=>(((y*x)%2+(y*x)%3)%2)===0,(y,x)=>((((y+x)%2)+((y*x)%3))%2)===0];
/* ---------- формат ---------- */
const FORMATS=[];for(let d=0;d<32;d++){let r=d<<10;for(let i=14;i>=10;i--)if(r&(1<<i))r^=0x537<<(i-10);FORMATS.push([(d<<10|r)^0x5412,d])}
const pop=v=>{let c=0;while(v){c++;v&=v-1}return c};
function readFormat(M,dim){
  const bit=(x,y)=>M[y*dim+x];let a=0,b=0;
  for(let i=0;i<6;i++)a=(a<<1)|bit(i,8);a=(a<<1)|bit(7,8);a=(a<<1)|bit(8,8);a=(a<<1)|bit(8,7);for(let j=5;j>=0;j--)a=(a<<1)|bit(8,j);
  for(let j=dim-1;j>=dim-7;j--)b=(b<<1)|bit(8,j);for(let i=dim-8;i<dim;i++)b=(b<<1)|bit(i,8);
  let best=null,bd=4;
  for(const [w,d] of FORMATS)for(const v of [a,b]){const h=pop(w^v);if(h<bd){bd=h;best=d}}
  return best===null?null:{ec:best>>3,mask:best&7}}
function funcMap(dim,ver){
  const F=new Uint8Array(dim*dim),set=(x,y)=>{if(x>=0&&y>=0&&x<dim&&y<dim)F[y*dim+x]=1};
  for(let y=0;y<9;y++)for(let x=0;x<9;x++)set(x,y);
  for(let y=0;y<9;y++)for(let x=dim-8;x<dim;x++)set(x,y);
  for(let y=dim-8;y<dim;y++)for(let x=0;x<9;x++)set(x,y);
  for(let i=0;i<dim;i++){set(i,6);set(6,i)}
  if(ver>=2){const p=ALIGN[ver];for(const cy of p)for(const cx of p){if((cx===6&&cy===6)||(cx===6&&cy===p[p.length-1])||(cy===6&&cx===p[p.length-1]))continue;
    for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)set(cx+dx,cy+dy)}}
  if(ver>=7){for(let i=0;i<6;i++)for(let j=0;j<3;j++){set(dim-11+j,i);set(i,dim-11+j)}}
  return F}
/* ---------- разбор матрицы ---------- */
function decodeMatrix(M,dim){
  const ver=(dim-17)/4;if(ver<1||ver>10||(dim-17)%4)return null;
  const fi=readFormat(M,dim);if(!fi)return null;
  const F=funcMap(dim,ver),mk=MASKS[fi.mask],bytes=[];let cur=0,nb=0,up=true;
  for(let j=dim-1;j>0;j-=2){if(j===6)j--;
    for(let c=0;c<dim;c++){const y=up?dim-1-c:c;
      for(let k=0;k<2;k++){const x=j-k;if(F[y*dim+x])continue;let bt=M[y*dim+x];if(mk(y,x))bt^=1;cur=(cur<<1)|bt;if(++nb===8){bytes.push(cur);cur=0;nb=0}}}
    up=!up}
  const sp=BLK[ver][ECIDX[fi.ec]],ecN=sp[0],blocks=[];
  for(let i=0;i<sp[1];i++)blocks.push({d:sp[2],data:[]});if(sp[3])for(let i=0;i<sp[3];i++)blocks.push({d:sp[4],data:[]});
  const maxD=Math.max(...blocks.map(b=>b.d));let p=0;
  for(let i=0;i<maxD;i++)for(const b of blocks)if(i<b.d)b.data.push(bytes[p++]);
  for(const b of blocks){b.ec=[];}
  for(let i=0;i<ecN;i++)for(const b of blocks)b.ec.push(bytes[p++]);
  const data=[];
  for(const b of blocks){const r=rsCorrect(b.data.concat(b.ec),ecN);if(!r)return null;for(let i=0;i<b.d;i++)data.push(r[i])}
  return parseBits(data,ver)}
function parseBits(data,ver){
  let pos=0;const total=data.length*8,rd=n=>{let v=0;for(let i=0;i<n;i++){if(pos>=total)return -1;v=(v<<1)|((data[pos>>3]>>(7-(pos&7)))&1);pos++}return v};
  const big=ver>=10,out=[];let text="",utf=[];
  const flush=()=>{if(utf.length){try{text+=new TextDecoder("utf-8",{fatal:true}).decode(new Uint8Array(utf))}catch(e){text+=String.fromCharCode(...utf)}utf=[]}};
  for(;;){const mode=rd(4);if(mode<=0)break;
    if(mode===4){const n=rd(big?16:8);if(n<0)return null;for(let i=0;i<n;i++){const c=rd(8);if(c<0)return null;utf.push(c)}}
    else if(mode===2){flush();let n=rd(big?11:9);if(n<0)return null;while(n>1){const v=rd(11);if(v<0)return null;text+=ALNUM[Math.floor(v/45)]+ALNUM[v%45];n-=2}if(n===1){const v=rd(6);if(v<0)return null;text+=ALNUM[v]}}
    else if(mode===1){flush();let n=rd(big?12:10);if(n<0)return null;while(n>=3){const v=rd(10);if(v<0)return null;text+=String(v).padStart(3,"0");n-=3}if(n===2){const v=rd(7);if(v<0)return null;text+=String(v).padStart(2,"0")}else if(n===1){const v=rd(4);if(v<0)return null;text+=String(v)}}
    else if(mode===7){const v=rd(8);if(v<0)return null;if(v&128){rd(8)}if((v&192)===192)rd(8)}
    else return null}
  flush();return text||null}
/* ---------- поиск QR на изображении ---------- */
function binarize(gray,w,h){
  const s=Math.max(15,Math.round(w/8))|1,half=s>>1,I=new Float64Array((w+1)*(h+1));
  for(let y=0;y<h;y++){let row=0;for(let x=0;x<w;x++){row+=gray[y*w+x];I[(y+1)*(w+1)+x+1]=I[y*(w+1)+x+1]+row}}
  const B=new Uint8Array(w*h);
  for(let y=0;y<h;y++){const y0=Math.max(0,y-half),y1=Math.min(h,y+half+1);
    for(let x=0;x<w;x++){const x0=Math.max(0,x-half),x1=Math.min(w,x+half+1),n=(x1-x0)*(y1-y0);
      const sum=I[y1*(w+1)+x1]-I[y0*(w+1)+x1]-I[y1*(w+1)+x0]+I[y0*(w+1)+x0];
      B[y*w+x]=gray[y*w+x]*n<sum*0.93?1:0}}
  return B}
function runsDir(B,w,h,x,y,dx,dy,sg){const o=[0,0,0];let st=0;
  for(let i=0;;i++){const xx=x+dx*sg*i,yy=y+dy*sg*i;if(xx<0||yy<0||xx>=w||yy>=h)break;const v=B[yy*w+xx],want=st===1?0:1;
    if(v===want)o[st]++;else{if(!o[st])return null;st++;if(st>2)break;o[st]=1}}
  return o}
function lineRuns(B,w,h,x,y,dx,dy){const a=runsDir(B,w,h,x,y,dx,dy,-1),b=runsDir(B,w,h,x,y,dx,dy,1);if(!a||!b)return null;
  return{r:[a[2],a[1],a[0]+b[0]-1,b[1],b[2]],off:(b[0]-a[0])/2}}
function ratio5(r,k){const t=r[0]+r[1]+r[2]+r[3]+r[4];const m=t/(4+k);if(m<1)return false;const tol=m*0.7;
  return Math.abs(r[0]-m)<tol&&Math.abs(r[1]-m)<tol&&Math.abs(r[2]-k*m)<k*tol&&Math.abs(r[3]-m)<tol&&Math.abs(r[4]-m)<tol}
function findFinders(B,w,h){
  const C=[],step=Math.max(1,Math.floor(h/300));
  for(let y=0;y<h;y+=step){let runs=[],c=B[y*w],s=0;
    for(let x=1;x<=w;x++){const v=x<w?B[y*w+x]:-1;if(v!==c){runs.push([s,x-s,c]);s=x;c=v}}
    for(let i=0;i+4<runs.length;i++){if(runs[i][2]!==1)continue;
      const r=[0,1,2,3,4].map(k=>runs[i+k][1]);if(!ratio5(r,3))continue;
      let cx=Math.floor(runs[i+2][0]+runs[i+2][1]/2),cy=y;
      const v1=lineRuns(B,w,h,cx,cy,0,1);if(!v1||!ratio5(v1.r,3))continue;cy=Math.round(cy+v1.off);
      const h1=lineRuns(B,w,h,cx,cy,1,0);if(!h1||!ratio5(h1.r,3))continue;cx=Math.round(cx+h1.off);
      const m=(v1.r.reduce((a,b)=>a+b)+h1.r.reduce((a,b)=>a+b))/14;
      const e=C.find(c=>Math.hypot(c.x-cx,c.y-cy)<Math.max(c.m,m)*1.5);
      if(e){e.x=(e.x*e.n+cx)/(e.n+1);e.y=(e.y*e.n+cy)/(e.n+1);e.m=(e.m*e.n+m)/(e.n+1);e.n++}else C.push({x:cx,y:cy,m,n:1})}}
  const strong=C.filter(c=>c.n>=2);return(strong.length>=3?strong:C).sort((a,b)=>b.n-a.n).slice(0,9)}
function triples(C){const T=[];
  for(let i=0;i<C.length;i++)for(let j=i+1;j<C.length;j++)for(let k=j+1;k<C.length;k++){
    const P=[C[i],C[j],C[k]],d=[Math.hypot(P[1].x-P[2].x,P[1].y-P[2].y),Math.hypot(P[0].x-P[2].x,P[0].y-P[2].y),Math.hypot(P[0].x-P[1].x,P[0].y-P[1].y)];
    const hi=d.indexOf(Math.max(...d)),tl=P[hi],A=P[(hi+1)%3],Bq=P[(hi+2)%3],l1=d[(hi+2)%3],l2=d[(hi+1)%3],hyp=d[hi];
    const lr=Math.abs(l1-l2)/Math.max(l1,l2),hr=Math.abs(hyp-Math.SQRT2*(l1+l2)/2)/hyp,mr=Math.max(P[0].m,P[1].m,P[2].m)/Math.min(P[0].m,P[1].m,P[2].m);
    if(lr>0.3||hr>0.25||mr>1.8)continue;
    const cr=(A.x-tl.x)*(Bq.y-tl.y)-(A.y-tl.y)*(Bq.x-tl.x);
    T.push({s:lr+hr+(mr-1)*0.5,tl,tr:cr>0?A:Bq,bl:cr>0?Bq:A})}
  return T.sort((a,b)=>a.s-b.s).slice(0,4)}
function homography(src,dst){const A=[];
  for(let i=0;i<4;i++){const [x,y]=src[i],[u,v]=dst[i];A.push([x,y,1,0,0,0,-u*x,-u*y,u]);A.push([0,0,0,x,y,1,-v*x,-v*y,v])}
  for(let c=0;c<8;c++){let p=c;for(let r=c+1;r<8;r++)if(Math.abs(A[r][c])>Math.abs(A[p][c]))p=r;if(Math.abs(A[p][c])<1e-12)return null;[A[c],A[p]]=[A[p],A[c]];
    for(let r=0;r<8;r++){if(r===c)continue;const f=A[r][c]/A[c][c];for(let k=c;k<9;k++)A[r][k]-=f*A[c][k]}}
  const H=A.map((r,i)=>r[8]/r[i]);return H}
const proj=(H,x,y)=>{const d=H[6]*x+H[7]*y+1;return[(H[0]*x+H[1]*y+H[2])/d,(H[3]*x+H[4]*y+H[5])/d]};
function alignOk(r){const m=(r[1]+r[2]+r[3])/3,t=m*0.6;return m>=1&&Math.abs(r[1]-m)<t&&Math.abs(r[2]-m)<t&&Math.abs(r[3]-m)<t&&r[0]>=m*0.5&&r[4]>=m*0.5}
function findAlign(B,w,h,ex,ey,m){const R=Math.ceil(m*5);let best=null,bd=1e9;
  for(let y=Math.max(0,Math.round(ey-R));y<=Math.min(h-1,Math.round(ey+R));y++)for(let x=Math.max(0,Math.round(ex-R));x<=Math.min(w-1,Math.round(ex+R));x++){
    if(!B[y*w+x])continue;const a=lineRuns(B,w,h,x,y,1,0),b=lineRuns(B,w,h,x,y,0,1);
    if(!a||!b||!alignOk(a.r)||!alignOk(b.r))continue;
    const cx=x+a.off,cy=y+b.off,d=Math.hypot(cx-ex,cy-ey);if(d<bd){bd=d;best=[cx,cy]}}
  return best&&bd<R?best:null}
function sample(B,w,h,t){
  const {tl,tr,bl}=t,m=(tl.m+tr.m+bl.m)/3,dt=Math.hypot(tr.x-tl.x,tr.y-tl.y),db=Math.hypot(bl.x-tl.x,bl.y-tl.y);
  let est=(dt+db)/2/m+7,dim=21+4*Math.round((est-21)/4);if(dim<21||dim>57)return null;
  const ver=(dim-17)/4,u=dim-7,vx=[(tr.x-tl.x)/u,(tr.y-tl.y)/u],vy=[(bl.x-tl.x)/u,(bl.y-tl.y)/u];
  const mp=(x,y)=>[tl.x+(x-3.5)*vx[0]+(y-3.5)*vy[0],tl.y+(x-3.5)*vx[1]+(y-3.5)*vy[1]];
  let br=mp(dim-6.5,dim-6.5),src=[[3.5,3.5],[dim-3.5,3.5],[3.5,dim-3.5]],dst=[[tl.x,tl.y],[tr.x,tr.y],[bl.x,bl.y]];
  if(ver>=2){const a=findAlign(B,w,h,br[0],br[1],dt/u);if(a)br=a;src.push([dim-6.5,dim-6.5]);dst.push(br)}
  else{src.push([dim-3.5,dim-3.5]);dst.push(mp(dim-3.5,dim-3.5))}
  const H=homography(src,dst);if(!H)return null;
  const M=new Uint8Array(dim*dim),o=0.22;
  for(let y=0;y<dim;y++)for(let x=0;x<dim;x++){let s=0;
    for(const [dx,dy] of [[0,0],[-o,0],[o,0],[0,-o],[0,o]]){const [px,py]=proj(H,x+0.5+dx,y+0.5+dy),ix=Math.round(px),iy=Math.round(py);
      if(ix>=0&&iy>=0&&ix<w&&iy<h)s+=B[iy*w+ix]}
    M[y*dim+x]=s>=3?1:0}
  return{M,dim}}
function tryBinary(B,w,h){
  for(const t of triples(findFinders(B,w,h))){const s=sample(B,w,h,t);if(!s)continue;
    let r=decodeMatrix(s.M,s.dim);if(r)return r;
    const T=new Uint8Array(s.M.length);for(let y=0;y<s.dim;y++)for(let x=0;x<s.dim;x++)T[x*s.dim+y]=s.M[y*s.dim+x];
    r=decodeMatrix(T,s.dim);if(r)return r}
  return null}
function decode(img){
  const w=img.width,h=img.height,d=img.data,gray=new Uint8Array(w*h);
  for(let i=0,j=0;i<gray.length;i++,j+=4)gray[i]=(d[j]*77+d[j+1]*150+d[j+2]*29)>>8;
  let B=binarize(gray,w,h),r=tryBinary(B,w,h);if(r)return r;
  for(let i=0;i<B.length;i++)B[i]^=1;return tryBinary(B,w,h)}
g.CSQR={decode,_rs:rsCorrect,_blk:BLK};
})(typeof self!=="undefined"?self:globalThis);
