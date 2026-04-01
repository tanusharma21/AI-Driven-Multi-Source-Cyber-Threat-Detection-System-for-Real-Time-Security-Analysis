import React, { useState, useEffect, useCallback, useRef } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { Line, Doughnut, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS, CategoryScale, LinearScale, BarElement,
  PointElement, LineElement, ArcElement, Filler, Tooltip, Legend,
} from 'chart.js';
ChartJS.register(CategoryScale, LinearScale, BarElement, PointElement, LineElement, ArcElement, Filler, Tooltip, Legend);

const API = 'http://localhost:8000';

/* ═══════════════════════════════════════════
   AUTH HELPERS
═══════════════════════════════════════════ */
const getToken = () => localStorage.getItem('cs_token');
const isAuth   = () => !!getToken();

/** Adds Authorization header to every API request automatically */
const apiFetch = (url, options = {}) => {
  const token = getToken();
  return fetch(`${API}${url}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  });
};

/** apiFetch variant for FormData (file uploads — no Content-Type override) */
const apiUpload = (url, formData) => {
  const token = getToken();
  return fetch(`${API}${url}`, {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: formData,
  });
};

/* ═══════════════════════════════════════════
   THEME
═══════════════════════════════════════════ */
const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Syne:wght@600;700;800&family=DM+Mono:wght@400;500&family=JetBrains+Mono:wght@700;800&display=swap');
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
  html,body,#root{height:100%;background:var(--bg,#080810);color:var(--fg,#c8c4d8);font-family:'DM Mono',monospace;}
  body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
    background-image:linear-gradient(rgba(150,120,220,.03) 1px,transparent 1px),
    linear-gradient(90deg,rgba(150,120,220,.03) 1px,transparent 1px);background-size:40px 40px;}
  ::-webkit-scrollbar{width:4px;} ::-webkit-scrollbar-track{background:#080810;}
  ::-webkit-scrollbar-thumb{background:#4a4760;border-radius:2px;}
  @keyframes fadeUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
  @keyframes fadeIn{from{opacity:0}to{opacity:1}}
  @keyframes pulse{0%,100%{box-shadow:0 0 6px #4ade9a}50%{box-shadow:0 0 16px #4ade9a,0 0 30px rgba(74,222,154,.3)}}
  @keyframes spin{to{transform:rotate(360deg)}}
  @keyframes slide{from{opacity:0;transform:translateX(16px)}to{opacity:1;transform:translateX(0)}}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
  #aegis-theme{}
`;

const DARK = {
  lav:'#b89dff', lavL:'#d0baff', lavD:'#8b6fd4',
  safe:'#4ade9a', danger:'#ff4d6a', warn:'#ffb547', info:'#60b4ff',
  card:'#11111f', card2:'#161628',
  border:'rgba(150,120,220,0.13)', borderB:'rgba(180,150,255,0.28)',
  gh:'#c8c4d8', gb:'#8a87a0', gm:'#4a4760',
};

const LIGHT = {
  lav:'#6c3fc5', lavL:'#4a2a9e', lavD:'#8b6fd4',
  safe:'#1a8a52', danger:'#cc1a3a', warn:'#b07800', info:'#1a6abf',
  card:'#ffffff', card2:'#f0eeff',
  border:'rgba(100,80,180,0.18)', borderB:'rgba(100,80,200,0.35)',
  gh:'#111122', gb:'#333355', gm:'#666688',
};

let C = {...DARK};

const lc = l => l==='Malicious'?C.danger:l==='Suspicious'?C.warn:C.safe;
const ri = l => l==='Malicious'?'!':l==='Suspicious'?'⚠':'✓';

/* ═══════════════════════════════════════════
   SHARED UI COMPONENTS
═══════════════════════════════════════════ */
const Spin = () => <span style={{display:'inline-block',width:11,height:11,border:'2px solid rgba(150,120,220,.3)',borderTopColor:C.lav,borderRadius:'50%',animation:'spin .7s linear infinite',verticalAlign:'middle'}}/>;

const Panel = ({children,style={},delay=0}) => (
  <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18,animation:`fadeUp .5s ease ${delay}s both`,...style}}>
    {children}
  </div>
);

const PH = ({title}) => (
  <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:14}}>
    <span style={{fontFamily:'Syne,sans-serif',fontSize:'.82rem',fontWeight:600,color:C.gh}}>{title}</span>
    <span style={{color:C.gm,letterSpacing:2}}>···</span>
  </div>
);

const Badge = ({label}) => {
  const col = lc(label);
  return <span style={{padding:'2px 8px',borderRadius:4,fontSize:'.62rem',fontWeight:700,background:`${col}18`,color:col,border:`1px solid ${col}44`}}>{label}</span>;
};

const InsightCard = ({insight,onClose}) => {
  if (!insight) return null;
  const col = insight.risk_level==='Critical'||insight.risk_level==='High' ? C.danger : insight.risk_level==='Medium' ? C.warn : C.safe;
  return (
    <div style={{marginTop:10,padding:'12px 14px',background:`${col}0d`,border:`1px solid ${col}44`,borderRadius:9,animation:'slide .3s ease',position:'relative'}}>
      <div style={{display:'flex',justifyContent:'space-between',marginBottom:6}}>
        <span style={{fontFamily:'Syne,sans-serif',fontSize:'.72rem',fontWeight:700,color:col}}>🤖 AI — Risk: {insight.risk_level}</span>
        {onClose && <span onClick={onClose} style={{cursor:'pointer',color:C.gm}}>✕</span>}
      </div>
      <p style={{fontSize:'.68rem',color:C.gb,lineHeight:1.6,marginBottom:6}}>{insight.message}</p>
      {insight.top_features?.length>0 && (
        <div style={{display:'flex',gap:5,flexWrap:'wrap',marginBottom:6}}>
          {insight.top_features.map(f=><span key={f} style={{padding:'1px 7px',borderRadius:4,background:`${col}18`,color:col,fontSize:'.6rem'}}>{f}</span>)}
        </div>
      )}
      <div style={{display:'flex',fontSize:'.62rem',color:C.gm,gap:10}}>
        <span style={{color:col}}>▶ {insight.action}</span>
        <span style={{marginLeft:'auto'}}>{insight.timestamp}</span>
      </div>
    </div>
  );
};

/* ═══════════════════════════════════════════
   LAYOUT SHELL  (Nav + Sidebar)
═══════════════════════════════════════════ */
const PAGES = [
  {path:'/dashboard',      label:'Dashboard'},
  {path:'/network',        label:'Network Monitor'},
  {path:'/scanner',        label:'File Scanner'},
  {path:'/url',            label:'URL Analyzer'},
  {path:'/ai-insights',    label:'AI Insights'},
  {path:'/reports',        label:'Reports'},
];

const ThemeContext = React.createContext({light:false,toggleTheme:()=>{}});

function Shell({children, back, app}) {
  const nav = useNavigate();
  const loc = useLocation();
  const {light, toggleTheme} = React.useContext(ThemeContext);

  const logout = async () => {
    try { await apiFetch('/api/logout', { method: 'POST' }); } catch (_) {}
    localStorage.removeItem('cs_token');
    nav('/');
  };

  const downloadReport = () => {
    const {stats, scanHistory=[], aiLog=[]} = app||{};
    const threats = scanHistory.filter(s=>s.label==='Malicious').length;
    const suspicious = scanHistory.filter(s=>s.label==='Suspicious').length;
    const safe = scanHistory.filter(s=>s.label==='Safe').length;
    const now = new Date().toLocaleString();
    const lines = [
      '================================================',
      '       ⟬⟭ AEGIS ⟭⟬ — SECURITY REPORT',
      '================================================',
      `Generated     : ${now}`,
      '------------------------------------------------',
      'SESSION SUMMARY',
      '------------------------------------------------',
      `Total Scans   : ${scanHistory.length||stats?.total_scans||0}`,
      `Threats Found : ${threats}`,
      `Suspicious    : ${suspicious}`,
      `Clean         : ${safe}`,
      `AI Insights   : ${aiLog.length}`,
      '------------------------------------------------',
      'MODEL ACCURACY',
      '------------------------------------------------',
      'Network RF    : 99.95%  (78 features)',
      'APK RF        : 74.70%  (216 features)',
      'URL RF        : 99.88%  (16 features)',
      'PDF RF        : 99.90%  (21 features)',
      '------------------------------------------------',
      'SCAN HISTORY',
      '------------------------------------------------',
      ...(scanHistory.length===0?['No scans recorded this session.']:scanHistory.slice(0,20).map((s,i)=>`${String(i+1).padStart(2,'0')}. [${s.label}] ${s.file||s.url||'Network'} — ${s.time}`)),
      '------------------------------------------------',
      'AI INSIGHTS',
      '------------------------------------------------',
      ...(aiLog.length===0?['No AI insights generated.']:aiLog.slice(0,10).map((l,i)=>`${String(i+1).padStart(2,'0')}. [${l.risk_level}] ${l.source}\n    ${l.message?.slice(0,100)}`)),
      '================================================',
      'System Status : SECURE',
      '⟬⟭ AEGIS ⟭⟬ — AI-Powered Cybersecurity Platform',
      '================================================',
    ];
    const blob = new Blob([lines.join('\n')],{type:'text/plain'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href=url; a.download=`AEGIS_Report_${Date.now()}.txt`; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div style={{display:'flex',flexDirection:'column',minHeight:'100vh',position:'relative',zIndex:1}}>
      {/* NAV */}
      <nav style={{position:'fixed',top:0,left:0,right:0,height:60,background:'rgba(8,8,16,.94)',backdropFilter:'blur(20px)',borderBottom:`1px solid ${C.border}`,display:'flex',alignItems:'center',padding:'0 24px',gap:10,zIndex:100}}>
        <div style={{display:'flex',alignItems:'center',gap:9,marginRight:'auto',cursor:'pointer'}} onClick={()=>nav('/dashboard')}>
          <svg width={32} height={32} viewBox="0 0 200 200" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="100" cy="100" r="90" fill="#1A1A2E"/>
            <path d="M50 110C50 60 70 40 100 40C130 40 150 60 150 110V140H50V110Z" fill="#322C54"/>
            <path d="M55 100C55 70 75 55 100 55C125 55 145 70 145 100" stroke="#7042F2" strokeWidth="2"/>
            <path d="M70 90C70 90 70 150 100 150C130 150 130 90 130 90" fill="#FFE0BD"/>
            <rect x="72" y="105" width="22" height="15" rx="4" stroke="#FF2E63" strokeWidth="3" fill="none"/>
            <rect x="106" y="105" width="22" height="15" rx="4" stroke="#FF2E63" strokeWidth="3" fill="none"/>
            <line x1="94" y1="112" x2="106" y2="112" stroke="#FF2E63" strokeWidth="3"/>
            <rect x="45" y="100" width="12" height="35" rx="4" fill="#00D1FF"/>
            <rect x="143" y="100" width="12" height="35" rx="4" fill="#00D1FF"/>
            <path d="M50 105C50 65 70 45 100 45C130 45 150 65 150 105" stroke="#00D1FF" strokeWidth="6" fill="none"/>
            <circle cx="100" cy="100" r="85" stroke="#FF2E63" strokeWidth="2" strokeDasharray="10 5"/>
          </svg>
          <span style={{fontFamily:'Syne,sans-serif',fontWeight:700,fontSize:'.84rem',color:C.lavL,letterSpacing:'.05em',textTransform:'uppercase'}}>⟬⟭ AEGIS ⟭⟬</span>
        </div>
        <div onClick={()=>nav('/analysis')} style={{padding:'5px 12px',borderRadius:6,fontSize:'.72rem',color:loc.pathname==='/analysis'?C.lavL:C.gb,cursor:'pointer',background:loc.pathname==='/analysis'?'rgba(150,120,220,.15)':'transparent'}}>Analysis</div>
        <div onClick={downloadReport} style={{padding:'5px 12px',borderRadius:6,fontSize:'.72rem',color:C.gb,cursor:'pointer'}}>Reports ↓</div>
        <div onClick={toggleTheme} title="Toggle theme" style={{padding:'5px 12px',borderRadius:6,fontSize:'.72rem',color:C.gb,cursor:'pointer'}}>{light?'🌙 Dark':'☀️ Light'}</div>
        <div style={{display:'flex',alignItems:'center',gap:6,padding:'4px 10px',border:`1px solid ${back===false?'rgba(255,77,106,.3)':'rgba(74,222,154,.2)'}`,borderRadius:20,fontSize:'.63rem',color:back===false?C.danger:C.safe}}>
          <span style={{width:6,height:6,borderRadius:'50%',background:back===false?C.danger:C.safe,display:'inline-block',animation:back!==false?'pulse 2s infinite':''}}/>
          {back===null?'Connecting…':back?'API Online':'Demo Mode'}
        </div>
        <div onClick={logout} style={{display:'flex',alignItems:'center',gap:7,padding:'4px 11px',border:`1px solid ${C.border}`,borderRadius:20,fontSize:'.7rem',color:C.gb,cursor:'pointer'}}>
          <span style={{width:7,height:7,borderRadius:'50%',background:C.safe,animation:'pulse 2s infinite',display:'inline-block'}}/> Admin ▾
        </div>
      </nav>

      <div style={{display:'flex',paddingTop:60,minHeight:'100vh'}}>
        {/* SIDEBAR */}
        <aside style={{width:220,flexShrink:0,background:'rgba(11,11,22,.88)',borderRight:`1px solid ${C.border}`,padding:'22px 0',position:'fixed',top:60,left:0,bottom:0,display:'flex',flexDirection:'column',overflowY:'auto'}}>
          <div style={{padding:'0 16px',margin:'6px 0 4px',fontSize:'.58rem',letterSpacing:'.14em',color:C.gm,textTransform:'uppercase'}}>Navigation</div>
          {PAGES.map(p=>{
            const active = loc.pathname===p.path;
            return <div key={p.path} onClick={()=>nav(p.path)} style={{padding:'9px 20px',cursor:'pointer',fontSize:'.73rem',color:active?C.lavL:C.gb,background:active?'rgba(150,120,220,.1)':'transparent',borderLeft:`2px solid ${active?C.lav:'transparent'}`}}>{p.label}</div>;
          })}
          <div style={{margin:'20px 14px 14px',padding:'11px 14px',background:'rgba(74,222,154,.06)',border:'1px solid rgba(74,222,154,.18)',borderRadius:10,display:'flex',alignItems:'center',gap:9}}>
            <span style={{width:8,height:8,borderRadius:'50%',background:C.safe,animation:'pulse 2s infinite',display:'inline-block',flexShrink:0}}/>
            <div><strong style={{color:C.safe,display:'block',fontSize:'.7rem'}}>System Secure</strong><span style={{color:C.gm,fontSize:'.6rem'}}>All modules nominal</span></div>
          </div>
        </aside>
        {/* CONTENT */}
        <main style={{marginLeft:220,flex:1,padding:22,display:'flex',flexDirection:'column',gap:14}}>
          {children}
        </main>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════
   PAGE: LOGIN
═══════════════════════════════════════════ */
function Login() {
  const nav=useNavigate();
  const [u,setU]=useState(''); const [p,setP]=useState('');
  const [err,setErr]=useState(''); const [ld,setLd]=useState(false);
  const inp={width:'100%',padding:'10px 13px',background:'#0e0e1a',border:`1px solid ${C.border}`,borderRadius:8,color:C.gh,fontFamily:'DM Mono,monospace',fontSize:'.8rem',outline:'none'};
  const lbl={display:'block',fontSize:'.62rem',color:C.gm,letterSpacing:'.1em',textTransform:'uppercase',margin:'14px 0 5px'};

  const sub = async (e) => {
    e.preventDefault();
    setLd(true);
    setErr('');
    try {
      const r = await fetch(`${API}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p }),
      });
      if (r.ok) {
        const data = await r.json();
        localStorage.setItem('cs_token', data.token);
        nav('/dashboard');
      } else {
        const data = await r.json();
        setErr(data.detail || 'Invalid credentials');
      }
    } catch {
      setErr('Cannot reach server — make sure the backend is running on port 8000');
    }
    setLd(false);
  };

  return(
    <div style={{minHeight:'100vh',display:'flex',alignItems:'center',justifyContent:'center',position:'relative',zIndex:1}}>
      <div style={{background:C.card,border:`1px solid ${C.borderB}`,borderRadius:18,padding:'44px 40px',width:390,animation:'fadeUp .45s ease both',boxShadow:'0 0 80px rgba(150,120,220,.08)'}}>
        <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:30}}>
          <svg viewBox="0 0 32 32" fill="none" width={32} height={32}><path d="M16 2L3 8v9c0 6 5.33 11.6 13 12.93C23.67 28.6 29 23 29 17V8L16 2z" fill="rgba(150,120,220,.15)" stroke="#b89dff" strokeWidth="1.5"/><path d="M10 16l4 4 8-8" stroke="#b89dff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
          <span style={{fontFamily:'Syne,sans-serif',fontWeight:700,fontSize:'.9rem',color:C.lavL,letterSpacing:'.06em',textTransform:'uppercase'}}>⟬⟭ AEGIS ⟭⟬</span>
        </div>
        <h1 style={{fontFamily:'Syne,sans-serif',fontSize:'1.6rem',fontWeight:800,color:C.gh,marginBottom:6}}>Welcome back</h1>
        <p style={{fontSize:'.72rem',color:C.gm,marginBottom:28}}>Sign in to access the security dashboard</p>
        <form onSubmit={sub}>
          <label style={lbl}>Username</label>
          <input style={inp} placeholder="ame" value={u} onChange={e=>setU(e.target.value)} autoFocus/>
          <label style={lbl}>Password</label>
          <input style={inp} type="password" placeholder="••••••••" value={p} onChange={e=>setP(e.target.value)}/>
          {err&&<div style={{marginTop:12,padding:'9px 12px',background:'rgba(255,77,106,.1)',border:'1px solid rgba(255,77,106,.25)',borderRadius:7,color:C.danger,fontSize:'.7rem'}}>{err}</div>}
          <button type="submit" disabled={ld} style={{width:'100%',marginTop:22,padding:13,background:'rgba(150,120,220,.2)',border:`1px solid ${C.lavD}`,borderRadius:9,color:C.lavL,fontSize:'.8rem',letterSpacing:'.06em',cursor:'pointer',fontFamily:'DM Mono,monospace'}}>
            {ld?<><Spin/> &nbsp;Authenticating…</>:'Sign In →'}
          </button>
        </form>
        <p style={{marginTop:16,fontSize:'.62rem',color:C.gm,textAlign:'center'}}></p>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════
   SHARED STATE HOOK
═══════════════════════════════════════════ */
function useApp() {
  const [stats,setStats]=useState(null);
  const [back,setBack]=useState(null);
  const [aiLog,setAiLog]=useState([]);
  const [scanHistory,setScanHistory]=useState([]);

  const loadStats=useCallback(async()=>{
    try{
      const r=await apiFetch('/api/stats');
      if(r.status===401){
        localStorage.removeItem('cs_token');
        window.location.href='/';
        return;
      }
      if(!r.ok) throw 0;
      setStats(await r.json());
      setBack(true);
    }catch{
      setBack(false);
      setStats({total_scans:1245,malicious_files:78,suspicious_urls:45,intrusion_alerts:12,third_party_risks:{safe:62,malicious:25,suspicious:10,third_party:3},malware_scan:{apk_safe:91,pdf_safe:86,image_safe:78}});
    }
  },[]);

  useEffect(()=>{loadStats();const id=setInterval(loadStats,15000);return()=>clearInterval(id);},[loadStats]);

  const addToLog=(insight,source)=>{
    if(!insight)return;
    setAiLog(p=>[{...insight,source,id:Date.now()},...p].slice(0,20));
  };
  const addScan=(scan)=>setScanHistory(p=>[{...scan,id:Date.now(),time:new Date().toLocaleTimeString()},...p].slice(0,50));

  return {stats,back,loadStats,aiLog,addToLog,scanHistory,addScan};
}

/* ═══════════════════════════════════════════
   PAGE: DASHBOARD
═══════════════════════════════════════════ */
function Dashboard({app}) {
  const [clock,setClock]=useState(''); const [date,setDate]=useState('');
  const [net]=useState(()=>{
    const L=Array.from({length:30},(_,i)=>i+1);
    return{labels:L,datasets:[
      {data:L.map(i=>28+Math.sin(i*.4)*8+Math.random()*5),borderColor:C.lav,backgroundColor:'rgba(184,157,255,.07)',fill:true,tension:.4,borderWidth:1.5,pointRadius:0},
      {data:L.map(i=>7+Math.random()*14+(i>20?Math.sin((i-20)*.7)*12:0)),borderColor:C.danger,backgroundColor:'rgba(255,77,106,.06)',fill:true,tension:.4,borderWidth:1.5,pointRadius:0},
    ]};
  });
  const [ticker,setTicker]=useState([]);

  useEffect(()=>{const t=()=>{const n=new Date();setClock(n.toLocaleTimeString());setDate(n.toLocaleDateString('en-GB',{weekday:'short',day:'2-digit',month:'short',year:'numeric'}));};t();const id=setInterval(t,1000);return()=>clearInterval(id);},[]);

  useEffect(()=>{
    const ev=[
      {type:'URL',label:'Malicious',msg:'Phishing URL blocked — fake-paypal.xyz'},
      {type:'Network',label:'Suspicious',msg:'Unusual traffic spike on port 443'},
      {type:'APK',label:'Safe',msg:'App scan completed — no threats found'},
      {type:'PDF',label:'Malicious',msg:'Malicious PDF quarantined — JS exploit'},
      {type:'Network',label:'Malicious',msg:'DDoS pattern detected — 847 IPs'},
      {type:'URL',label:'Safe',msg:'URL verified — trusted domain confirmed'},
    ];
    const id=setInterval(()=>{
      const e=ev[Math.floor(Math.random()*ev.length)];
      setTicker(p=>[{...e,id:Date.now(),time:new Date().toLocaleTimeString()},...p].slice(0,6));
    },4000);
    return()=>clearInterval(id);
  },[]);

  const {stats,back,aiLog,scanHistory}=app;
  const dd=stats?{labels:['Safe','Malicious','Suspicious','Third-Party'],datasets:[{data:[stats.third_party_risks.safe,stats.third_party_risks.malicious,stats.third_party_risks.suspicious,stats.third_party_risks.third_party],backgroundColor:[C.safe,C.danger,C.warn,C.lav],borderWidth:0,hoverOffset:6}]}:null;
  const cOpts={responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{enabled:false}},scales:{x:{display:false},y:{display:false}}};

  return(
    <Shell app={app} back={back}>
      <div style={{display:'flex',alignItems:'flex-end',justifyContent:'space-between'}}>
        <div>
          <h2 style={{fontFamily:'Syne,sans-serif',fontSize:'1.35rem',fontWeight:800,color:C.gh}}>Threat <span style={{color:C.lavL}}>Detection</span> Dashboard</h2>
          <p style={{fontSize:'.68rem',color:C.gm,marginTop:3}}>AI-powered real-time cybersecurity monitoring</p>
        </div>
        <div style={{textAlign:'right',fontSize:'.62rem',color:C.gm}}>
          <strong style={{display:'block',color:C.gb,fontSize:'.74rem'}}>{clock}</strong>{date}
        </div>
      </div>

      {/* ── STAT CARDS — numbers use JetBrains Mono ── */}
      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12}}>
        {[
          {label:'Total Scans',val:stats?.total_scans?.toLocaleString()??'—',color:C.lav,acc:C.lavD},
          {label:'Malicious Files',val:stats?.malicious_files??'—',color:C.danger,acc:C.danger},
          {label:'Suspicious URLs',val:stats?.suspicious_urls??'—',color:C.info,acc:C.info},
          {label:'Intrusion Alerts',val:stats?.intrusion_alerts??'—',color:C.warn,acc:C.warn,badge:'⚠ Critical'},
        ].map((c,i)=>(
          <div key={c.label} style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:'15px 18px',position:'relative',overflow:'hidden',animation:`fadeUp .45s ease ${i*.07}s both`}}>
            <div style={{position:'absolute',top:0,left:0,right:0,height:2,background:c.acc,opacity:.8}}/>
            <div style={{fontSize:'.6rem',color:C.gm,letterSpacing:'.1em',textTransform:'uppercase',marginBottom:8}}>{c.label}</div>
            <div style={{fontFamily:'"JetBrains Mono",monospace',fontSize:'1.9rem',fontWeight:800,color:c.color,lineHeight:1}}>
              {c.val}
              {c.badge&&<span style={{display:'inline-flex',padding:'2px 7px',borderRadius:4,fontSize:'.58rem',fontWeight:600,marginLeft:8,verticalAlign:'middle',background:'rgba(255,77,106,.15)',color:C.danger,border:'1px solid rgba(255,77,106,.3)',fontFamily:'DM Mono,monospace'}}>{c.badge}</span>}
            </div>
          </div>
        ))}
      </div>

      <div style={{display:'grid',gridTemplateColumns:'2fr 1.3fr 1fr',gap:14}}>
        <Panel delay={.1}>
          <PH title="Network Intrusion Detection"/>
          <div style={{height:120,marginBottom:10}}><Line data={net} options={cOpts}/></div>
          <div style={{display:'flex',gap:14,fontSize:'.6rem',color:C.gm,marginBottom:10}}>
            <span><span style={{display:'inline-block',width:8,height:8,borderRadius:'50%',background:C.lav,marginRight:5}}/>Normal</span>
            <span><span style={{display:'inline-block',width:8,height:8,borderRadius:'50%',background:C.danger,marginRight:5}}/>Anomalies</span>
          </div>
          <div style={{display:'flex',gap:7,flexWrap:'wrap'}}>
            <span style={{padding:'3px 9px',borderRadius:5,fontSize:'.6rem',background:'rgba(255,181,71,.1)',color:C.warn,border:'1px solid rgba(255,181,71,.2)'}}>▲ Traffic Anomalies</span>
            <span style={{padding:'3px 9px',borderRadius:5,fontSize:'.6rem',background:'rgba(255,77,106,.1)',color:C.danger,border:'1px solid rgba(255,77,106,.2)'}}>⛔ DDoS Detected</span>
          </div>
        </Panel>
        <Panel delay={.15}>
          <PH title="Malware Scan Results"/>
          {[{label:'APKs',pct:stats?.malware_scan?.apk_safe??91,color:C.safe},{label:'PDFs',pct:stats?.malware_scan?.pdf_safe??86,color:C.info},{label:'Images',pct:stats?.malware_scan?.image_safe??78,color:C.warn}].map(r=>(
            <div key={r.label} style={{display:'flex',alignItems:'center',padding:'8px 0',borderBottom:'1px solid rgba(150,120,220,.07)'}}>
              <span style={{fontSize:'.68rem',color:C.gb,width:52}}>{r.label}</span>
              <div style={{flex:1,margin:'0 10px',height:5,background:'rgba(150,120,220,.1)',borderRadius:3}}>
                <div style={{width:`${r.pct}%`,height:'100%',borderRadius:3,background:r.color,transition:'width .8s ease'}}/>
              </div>
              {/* percentage numbers → JetBrains Mono */}
              <span style={{fontFamily:'"JetBrains Mono",monospace',fontSize:'.74rem',fontWeight:700,color:r.color,width:34,textAlign:'right'}}>{r.pct}%</span>
            </div>
          ))}
          <div style={{marginTop:12,fontSize:'.65rem',color:C.gm,textAlign:'center',padding:'8px',border:`1px dashed ${C.border}`,borderRadius:8,cursor:'pointer'}} onClick={()=>window.location.href='/scanner'}>
            → Go to File Scanner to upload & scan
          </div>
        </Panel>
        <Panel delay={.2}>
          <PH title="Third-Party Risks"/>
          {dd&&<div style={{display:'flex',alignItems:'center',gap:14}}>
            <div style={{width:100,height:100,flexShrink:0}}><Doughnut data={dd} options={{responsive:true,cutout:'70%',plugins:{legend:{display:false}},animation:{duration:900}}}/></div>
            <div style={{display:'flex',flexDirection:'column',gap:7}}>
              {['Safe','Malicious','Suspicious','Third-Party'].map((l,i)=>(
                <div key={l} style={{display:'flex',alignItems:'center',gap:7,fontSize:'.65rem',color:C.gb}}>
                  <span style={{width:9,height:9,borderRadius:2,background:[C.safe,C.danger,C.warn,C.lav][i],flexShrink:0}}/>{l}
                  {/* percentage values → JetBrains Mono */}
                  <strong style={{fontFamily:'"JetBrains Mono",monospace',color:[C.safe,C.danger,C.warn,C.lav][i],marginLeft:4}}>{dd.datasets[0].data[i]}%</strong>
                </div>
              ))}
            </div>
          </div>}
        </Panel>
      </div>

      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14}}>
        <Panel delay={.25}>
          <PH title="Recent Scan Activity"/>
          {scanHistory.length===0?(
            <div style={{fontSize:'.68rem',color:C.gm,textAlign:'center',padding:'20px 0'}}>No scans yet — use File Scanner or URL Analyzer</div>
          ):(
            <div style={{maxHeight:200,overflowY:'auto',display:'flex',flexDirection:'column',gap:6}}>
              {scanHistory.slice(0,8).map(s=>{
                const col=lc(s.label);
                return(
                  <div key={s.id} style={{display:'flex',alignItems:'center',gap:9,padding:'7px 10px',background:`${col}0d`,border:`1px solid ${col}22`,borderRadius:7,animation:'slide .3s ease'}}>
                    <span style={{width:20,height:20,borderRadius:'50%',background:`${col}22`,color:col,display:'flex',alignItems:'center',justifyContent:'center',fontSize:'.65rem',fontWeight:700,flexShrink:0}}>{ri(s.label)}</span>
                    <span style={{flex:1,fontSize:'.68rem',color:C.gb,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{s.file||s.url||'Network'}</span>
                    <Badge label={s.label}/>
                    <span style={{fontSize:'.6rem',color:C.gm,flexShrink:0}}>{s.time}</span>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
        <Panel delay={.3}>
          <PH title="AI Insights Feed"/>
          {aiLog.length===0?(
            <div style={{fontSize:'.68rem',color:C.gm}}>
              {[{t:C.danger,i:'↑',txt:<span>Detected: <strong style={{color:C.danger}}>DDoS Attack</strong> — volumetric flood from 847 IPs on port 443.</span>},{t:C.warn,i:'◉',txt:<span>Risk: <strong style={{color:C.warn}}>High</strong> — threat score 87/100. Action required.</span>},{t:C.info,i:'ℹ',txt:<span>Recommendation: Block suspicious IPs, enable rate limiting.</span>}].map((ins,i)=>(
                <div key={i} style={{display:'flex',gap:9,padding:'8px 0',borderBottom:'1px solid rgba(150,120,220,.07)',fontSize:'.68rem'}}>
                  <span style={{width:20,height:20,borderRadius:'50%',background:`${ins.t}1a`,color:ins.t,display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0,fontSize:'.7rem'}}>{ins.i}</span>
                  <div style={{color:C.gb,lineHeight:1.55}}>{ins.txt}</div>
                </div>
              ))}
            </div>
          ):(
            <div style={{maxHeight:220,overflowY:'auto',display:'flex',flexDirection:'column',gap:6}}>
              {aiLog.slice(0,5).map(log=>{
                const col=log.risk_level==='Critical'||log.risk_level==='High'?C.danger:log.risk_level==='Medium'?C.warn:C.safe;
                return(
                  <div key={log.id} style={{padding:'8px 10px',background:`${col}0d`,border:`1px solid ${col}33`,borderRadius:7,animation:'slide .3s ease'}}>
                    <div style={{display:'flex',justifyContent:'space-between',marginBottom:3}}>
                      <span style={{color:col,fontWeight:700,fontSize:'.65rem'}}>{log.source}</span>
                      <span style={{color:C.gm,fontSize:'.6rem'}}>{log.risk_level}</span>
                    </div>
                    <div style={{fontSize:'.65rem',color:C.gm,lineHeight:1.4}}>{log.message.slice(0,90)}{log.message.length>90?'…':''}</div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
      </div>

      {ticker.length>0&&(
        <Panel delay={.35}>
          <PH title="Real-Time Threat Feed"/>
          <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:8}}>
            {ticker.slice(0,3).map(t=>{
              const col=lc(t.label);
              return(
                <div key={t.id} style={{padding:'9px 11px',background:`${col}0d`,border:`1px solid ${col}33`,borderRadius:8,animation:'slide .3s ease'}}>
                  <div style={{display:'flex',justifyContent:'space-between',marginBottom:4}}>
                    <span style={{fontSize:'.62rem',fontWeight:700,color:col}}>{t.type}</span>
                    <span style={{fontSize:'.58rem',color:C.gm}}>{t.time}</span>
                  </div>
                  <div style={{fontSize:'.65rem',color:C.gb,lineHeight:1.4}}>{t.msg}</div>
                  <div style={{marginTop:4,fontSize:'.6rem',color:col}}>{ri(t.label)} {t.label}</div>
                </div>
              );
            })}
          </div>
        </Panel>
      )}
    </Shell>
  );
}

/* ═══════════════════════════════════════════
   PAGE: FILE SCANNER
═══════════════════════════════════════════ */
function FileScanner({app}) {
  const {back,loadStats,addToLog,addScan}=app;
  const [state,setState]=useState({loading:false,result:null,insight:null,error:null});
  const [history,setHistory]=useState([]);
  const fRef=useRef();

  const handleFile=async(e)=>{
    const f=e.target.files[0]; if(!f)return; e.target.value='';
    const ext=f.name.split('.').pop().toLowerCase();
    if(!['apk','pdf','jpg','jpeg','png','gif','bmp','webp','zip'].includes(ext)){setState({loading:false,result:null,insight:null,error:'Only .apk, .pdf, image, or .zip files supported.'});return;}
    setState({loading:true,result:null,insight:null,error:null});
    try{
      const fd=new FormData(); fd.append('file',f);
      const r=await apiUpload('/api/scan/file', fd);
      if(r.status===401){localStorage.removeItem('cs_token');window.location.href='/';return;}
      if(!r.ok)throw new Error((await r.json()).detail||'Scan failed');
      const data=await r.json();
      setState({loading:false,result:data,insight:data.insight,error:null});
      setHistory(p=>[{...data,time:new Date().toLocaleTimeString(),id:Date.now()},...p].slice(0,20));
      addToLog(data.insight,`${data.type}: ${f.name}`);
      addScan({...data,file:f.name});
      loadStats();
    }catch(err){setState({loading:false,result:null,insight:null,error:err.message});}
  };

  const dropZone={
    border:`2px dashed ${state.loading?C.lav:C.borderB}`,borderRadius:14,padding:'40px 20px',
    textAlign:'center',cursor:'pointer',transition:'all .2s',background:state.loading?'rgba(150,120,220,.04)':'transparent'
  };

  return(
    <Shell app={app} back={back}>
      <div><h2 style={{fontFamily:'Syne,sans-serif',fontSize:'1.35rem',fontWeight:800,color:C.gh}}>File <span style={{color:C.lavL}}>Scanner</span></h2><p style={{fontSize:'.68rem',color:C.gm,marginTop:3}}>Upload APK or PDF files for AI-powered malware analysis</p></div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14}}>
        <Panel>
          <PH title="Upload File"/>
          <div style={dropZone} onClick={()=>fRef.current?.click()}>
            <input ref={fRef} type="file" accept=".apk,.pdf,.jpg,.jpeg,.png,.gif,.zip" onChange={handleFile} style={{display:'none'}}/>
            <div style={{fontSize:'2rem',marginBottom:12}}>📁</div>
            <div style={{fontFamily:'Syne,sans-serif',fontSize:'.9rem',color:C.gh,marginBottom:6}}>
              {state.loading?'Scanning…':'Drop file here or click to browse'}
            </div>
            <div style={{fontSize:'.68rem',color:C.gm}}>Supports: .apk, .pdf, .jpg, .png, .zip</div>
            {state.loading&&<div style={{marginTop:16}}><Spin/></div>}
          </div>
          {state.error&&<div style={{marginTop:12,padding:'10px 14px',background:'rgba(255,77,106,.08)',border:'1px solid rgba(255,77,106,.25)',borderRadius:8,color:C.danger,fontSize:'.72rem'}}>{state.error}</div>}
          {state.result&&(()=>{
            const col=lc(state.result.label);
            return(
              <div style={{marginTop:12}}>
                <div style={{padding:'14px',background:`${col}0d`,border:`1px solid ${col}44`,borderRadius:10}}>
                  <div style={{display:'flex',justifyContent:'space-between',marginBottom:8}}>
                    <span style={{fontFamily:'Syne,sans-serif',fontSize:'.78rem',fontWeight:700,color:C.gh}}>{state.result.file}</span>
                    <Badge label={state.result.label}/>
                  </div>
                  <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:8}}>
                    {[['Type',state.result.type],['Risk',state.result.risk],['Confidence',`${state.result.confidence}%`]].map(([k,v])=>(
                      <div key={k} style={{background:'rgba(150,120,220,.05)',padding:'8px',borderRadius:7,textAlign:'center'}}>
                        <div style={{fontSize:'.58rem',color:C.gm,textTransform:'uppercase',letterSpacing:'.1em',marginBottom:3}}>{k}</div>
                        {/* result values → JetBrains Mono */}
                        <div style={{fontFamily:'"JetBrains Mono",monospace',fontSize:'.82rem',fontWeight:700,color:col}}>{v}</div>
                      </div>
                    ))}
                  </div>
                </div>
                <InsightCard insight={state.insight} onClose={()=>setState(p=>({...p,insight:null}))}/>
              </div>
            );
          })()}
        </Panel>
        <Panel>
          <PH title="Scan History"/>
          {history.length===0?(
            <div style={{fontSize:'.68rem',color:C.gm,textAlign:'center',padding:'30px 0'}}>No scans yet</div>
          ):(
            <div style={{display:'flex',flexDirection:'column',gap:6,maxHeight:420,overflowY:'auto'}}>
              {history.map(h=>{
                const col=lc(h.label);
                return(
                  <div key={h.id} style={{display:'flex',alignItems:'center',gap:10,padding:'9px 12px',background:`${col}0d`,border:`1px solid ${col}22`,borderRadius:8}}>
                    <span style={{fontSize:'1.2rem'}}>{h.type==='APK'?'📱':h.type==='Image'?'🖼️':h.type==='ZIP'?'🗜️':'📄'}</span>
                    <div style={{flex:1}}>
                      <div style={{fontSize:'.72rem',color:C.gh,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{h.file}</div>
                      <div style={{fontSize:'.6rem',color:C.gm}}>{h.time}</div>
                    </div>
                    <Badge label={h.label}/>
                    {/* confidence % → JetBrains Mono */}
                    <span style={{fontFamily:'"JetBrains Mono",monospace',fontSize:'.68rem',color:col,flexShrink:0}}>{h.confidence}%</span>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
      </div>
      <Panel>
        <PH title="How File Scanning Works"/>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14,fontSize:'.72rem',color:C.gb,lineHeight:1.7}}>
          <div>
            <div style={{fontFamily:'Syne,sans-serif',color:C.lavL,marginBottom:6,fontSize:'.78rem'}}>📱 APK Analysis (216 features)</div>
            <p>Analyses Android permission vectors using a Random Forest classifier. Detects banking trojans, spyware, and RATs.</p>
          </div>
          <div>
            <div style={{fontFamily:'Syne,sans-serif',color:C.lavL,marginBottom:6,fontSize:'.78rem'}}>📄 PDF Analysis (21 features)</div>
            <p>Extracts PDF metadata features. Detects exploit documents and phishing PDFs with 99.9% accuracy.</p>
          </div>
          <div>
            <div style={{fontFamily:'Syne,sans-serif',color:C.lavL,marginBottom:6,fontSize:'.78rem'}}>🖼️ Image Analysis (rule-based)</div>
            <p>Checks image headers, detects hidden executables, double extensions, steganography and high entropy content.</p>
          </div>
          <div>
            <div style={{fontFamily:'Syne,sans-serif',color:C.lavL,marginBottom:6,fontSize:'.78rem'}}>🗜️ ZIP Analysis (deep scan)</div>
            <p>Extracts ZIP contents and scans each file inside using existing models. Detects zip bombs and suspicious files.</p>
          </div>
        </div>
      </Panel>
    </Shell>
  );
}

/* ═══════════════════════════════════════════
   PAGE: URL ANALYZER
═══════════════════════════════════════════ */
function URLAnalyzer({app}) {
  const {back,loadStats,addToLog,addScan}=app;
  const [input,setInput]=useState('');
  const [state,setState]=useState({loading:false,result:null,insight:null});
  const [history,setHistory]=useState([]);

  const scan=async()=>{
    const url=input.trim(); if(!url)return;
    setState({loading:true,result:null,insight:null});
    try{
      const r=await apiFetch('/api/scan/url',{method:'POST',body:JSON.stringify({url})});
      if(r.status===401){localStorage.removeItem('cs_token');window.location.href='/';return;}
      if(!r.ok)throw 0;
      const data=await r.json();
      setState({loading:false,result:data,insight:data.insight});
      setHistory(p=>[{...data,time:new Date().toLocaleTimeString(),id:Date.now()},...p].slice(0,20));
      addToLog(data.insight,`URL: ${url.slice(0,40)}`);
      addScan({...data,url});
      setInput(''); loadStats();
    }catch{setState({loading:false,result:null,insight:null});}
  };

  const FEATURES=['url_length','has_ip_address','dot_count','https_flag','url_entropy','token_count','subdomain_count','query_param_count','tld_length','path_length','has_hyphen_in_domain','number_of_digits','tld_popularity','suspicious_file_extension','domain_name_length','percentage_numeric_chars'];

  return(
    <Shell app={app} back={back}>
      <div><h2 style={{fontFamily:'Syne,sans-serif',fontSize:'1.35rem',fontWeight:800,color:C.gh}}>URL <span style={{color:C.lavL}}>Analyzer</span></h2><p style={{fontSize:'.68rem',color:C.gm,marginTop:3}}>Detect phishing and malicious URLs using 16 structural features</p></div>
      <Panel>
        <PH title="Scan URL"/>
        <div style={{display:'flex',gap:8}}>
          <input value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e=>e.key==='Enter'&&scan()} placeholder="https://example.com — paste any URL to scan"
            style={{flex:1,padding:'11px 14px',background:'#0e0e1a',border:`1px solid ${C.border}`,borderRadius:9,color:C.gh,fontFamily:'DM Mono,monospace',fontSize:'.8rem',outline:'none'}}/>
          <button onClick={scan} disabled={state.loading} style={{padding:'11px 22px',background:'rgba(150,120,220,.2)',border:`1px solid ${C.lavD}`,borderRadius:9,color:C.lavL,fontSize:'.78rem',cursor:'pointer',fontFamily:'DM Mono,monospace',display:'flex',alignItems:'center',gap:6}}>
            {state.loading?<><Spin/> Scanning…</>:'Scan →'}
          </button>
        </div>
        {state.result&&(()=>{
          const col=lc(state.result.label);
          return(
            <div style={{marginTop:14}}>
              <div style={{padding:'14px',background:`${col}0d`,border:`1px solid ${col}44`,borderRadius:10,marginBottom:6}}>
                <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:8}}>
                  <span style={{fontSize:'.72rem',color:C.gb,wordBreak:'break-all',flex:1,marginRight:10}}>{state.result.url}</span>
                  <Badge label={state.result.label}/>
                </div>
                <div style={{display:'flex',gap:12}}>
                  <span style={{fontSize:'.68rem',color:C.gm}}>Risk: <strong style={{fontFamily:'"JetBrains Mono",monospace',color:col}}>{state.result.risk}</strong></span>
                  <span style={{fontSize:'.68rem',color:C.gm}}>Confidence: <strong style={{fontFamily:'"JetBrains Mono",monospace',color:col}}>{state.result.confidence}%</strong></span>
                </div>
              </div>
              <InsightCard insight={state.insight} onClose={()=>setState(p=>({...p,insight:null}))}/>
            </div>
          );
        })()}
      </Panel>

      <div style={{display:'grid',gridTemplateColumns:'1.2fr 1fr',gap:14}}>
        <Panel>
          <PH title="Scan History"/>
          {history.length===0?(
            <div style={{fontSize:'.68rem',color:C.gm,textAlign:'center',padding:'20px 0'}}>No URLs scanned yet</div>
          ):(
            <div style={{display:'flex',flexDirection:'column',gap:6,maxHeight:320,overflowY:'auto'}}>
              {history.map(h=>{
                const col=lc(h.label);
                return(
                  <div key={h.id} style={{display:'flex',alignItems:'center',gap:9,padding:'9px 11px',background:`${col}0d`,border:`1px solid ${col}22`,borderRadius:8,animation:'slide .3s ease'}}>
                    <span style={{width:22,height:22,borderRadius:'50%',background:`${col}22`,color:col,display:'flex',alignItems:'center',justifyContent:'center',fontSize:'.65rem',fontWeight:700,flexShrink:0}}>{ri(h.label)}</span>
                    <span style={{flex:1,fontSize:'.68rem',color:C.gb,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}} title={h.url}>{h.url.length>45?h.url.slice(0,45)+'…':h.url}</span>
                    {/* confidence → JetBrains Mono */}
                    <span style={{fontFamily:'"JetBrains Mono",monospace',color:col,fontSize:'.65rem',flexShrink:0}}>{h.confidence}%</span>
                    <span style={{color:C.gm,fontSize:'.6rem',flexShrink:0}}>{h.time}</span>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
        <Panel>
          <PH title="16 Feature Set"/>
          <div style={{display:'flex',flexDirection:'column',gap:4}}>
            {FEATURES.map((f,i)=>(
              <div key={f} style={{display:'flex',alignItems:'center',gap:8,padding:'4px 8px',background:i%2===0?'rgba(150,120,220,.04)':'transparent',borderRadius:5}}>
                <span style={{fontSize:'.58rem',color:C.gm,width:16,textAlign:'right'}}>{i+1}</span>
                <span style={{fontSize:'.66rem',color:C.gb,fontFamily:'DM Mono,monospace'}}>{f}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </Shell>
  );
}

/* ═══════════════════════════════════════════
   PAGE: NETWORK MONITOR
═══════════════════════════════════════════ */
function NetworkMonitor({app}) {
  const {back,stats}=app;
  const [samples]=useState(()=>Array.from({length:20},()=>({
    features:Array.from({length:78},()=>Math.random()*100),
    label:Math.random()>0.7?'Malicious':Math.random()>0.5?'Suspicious':'Safe',
    confidence:Math.round(60+Math.random()*39),
    time:new Date().toLocaleTimeString(),
  })));

  const lineData={
    labels:Array.from({length:30},(_,i)=>i+1),
    datasets:[
      {label:'Benign',data:Array.from({length:30},()=>Math.round(200+Math.random()*100)),borderColor:C.safe,backgroundColor:'rgba(74,222,154,.08)',fill:true,tension:.4,borderWidth:2,pointRadius:0},
      {label:'Attacks',data:Array.from({length:30},(_,i)=>i>20?Math.round(50+Math.random()*150):Math.round(Math.random()*30)),borderColor:C.danger,backgroundColor:'rgba(255,77,106,.08)',fill:true,tension:.4,borderWidth:2,pointRadius:0},
    ]
  };
  const lineOpts={responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:C.gb,font:{size:11}}}},scales:{x:{display:false},y:{ticks:{color:C.gm,font:{size:10}},grid:{color:'rgba(150,120,220,.06)'}}}};

  return(
    <Shell app={app} back={back}>
      <div><h2 style={{fontFamily:'Syne,sans-serif',fontSize:'1.35rem',fontWeight:800,color:C.gh}}>Network <span style={{color:C.lavL}}>Monitor</span></h2><p style={{fontSize:'.68rem',color:C.gm,marginTop:3}}>Real-time network traffic analysis using CIC-IDS 2017 dataset — 78 flow features</p></div>

      {/* ── STAT CARDS — numbers use JetBrains Mono ── */}
      <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:12}}>
        {[{label:'Total Flows',val:'28,491',color:C.lav},{label:'Attacks Blocked',val:stats?.intrusion_alerts??'12',color:C.danger},{label:'Model Accuracy',val:'99.95%',color:C.safe}].map((c,i)=>(
          <div key={c.label} style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:'14px 18px',position:'relative',overflow:'hidden',animation:`fadeUp .4s ease ${i*.07}s both`}}>
            <div style={{position:'absolute',top:0,left:0,right:0,height:2,background:c.color,opacity:.8}}/>
            <div style={{fontSize:'.6rem',color:C.gm,letterSpacing:'.1em',textTransform:'uppercase',marginBottom:6}}>{c.label}</div>
            <div style={{fontFamily:'"JetBrains Mono",monospace',fontSize:'1.6rem',fontWeight:800,color:c.color}}>{c.val}</div>
          </div>
        ))}
      </div>

      <Panel>
        <PH title="Network Traffic — 30s Window"/>
        <div style={{height:180}}><Line data={lineData} options={lineOpts}/></div>
        <div style={{display:'flex',gap:12,marginTop:10,flexWrap:'wrap'}}>
          <span style={{padding:'3px 10px',borderRadius:5,fontSize:'.6rem',background:'rgba(255,77,106,.1)',color:C.danger,border:'1px solid rgba(255,77,106,.2)'}}>⛔ DDoS Attack Detected — 847 source IPs</span>
          <span style={{padding:'3px 10px',borderRadius:5,fontSize:'.6rem',background:'rgba(255,181,71,.1)',color:C.warn,border:'1px solid rgba(255,181,71,.2)'}}>▲ Volumetric Flood on Port 443</span>
          <span style={{padding:'3px 10px',borderRadius:5,fontSize:'.6rem',background:'rgba(74,222,154,.1)',color:C.safe,border:'1px solid rgba(74,222,154,.2)'}}>✓ Mitigation Active</span>
        </div>
      </Panel>
      <Panel>
        <PH title="Sample Flow Analysis (78 features each)"/>
        <div style={{display:'flex',flexDirection:'column',gap:4}}>
          <div style={{display:'grid',gridTemplateColumns:'1fr 2fr .8fr .8fr .8fr',gap:8,padding:'6px 10px',fontSize:'.6rem',color:C.gm,letterSpacing:'.08em',textTransform:'uppercase',borderBottom:`1px solid ${C.border}`}}>
            <span>#</span><span>Flow Duration / Bytes</span><span>Label</span><span>Confidence</span><span>Time</span>
          </div>
          {samples.slice(0,10).map((s,i)=>{
            const col=lc(s.label);
            return(
              <div key={i} style={{display:'grid',gridTemplateColumns:'1fr 2fr .8fr .8fr .8fr',gap:8,padding:'7px 10px',background:i%2===0?'rgba(150,120,220,.03)':'transparent',borderRadius:6,fontSize:'.68rem'}}>
                <span style={{color:C.gm}}>{i+1}</span>
                <span style={{color:C.gb,fontFamily:'DM Mono,monospace'}}>{s.features[0].toFixed(1)}μs / {Math.round(s.features[1]*1024)}B</span>
                <Badge label={s.label}/>
                {/* confidence → JetBrains Mono */}
                <span style={{fontFamily:'"JetBrains Mono",monospace',color:col}}>{s.confidence}%</span>
                <span style={{color:C.gm}}>{s.time}</span>
              </div>
            );
          })}
        </div>
      </Panel>
    </Shell>
  );
}

/* ═══════════════════════════════════════════
   PAGE: AI INSIGHTS
═══════════════════════════════════════════ */
function AIInsights({app}) {
  const {back,aiLog}=app;
  const barData={
    labels:['Network','APK','URL','PDF'],
    datasets:[{
      label:'Accuracy (%)',
      data:[99.95,74.7,99.88,99.9],
      backgroundColor:[C.lav,C.warn,C.safe,C.info],
      borderRadius:6, borderWidth:0,
    }]
  };
  const barOpts={responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>`${ctx.parsed.y}%`}}},scales:{x:{ticks:{color:C.gb},grid:{display:false}},y:{min:70,max:105,ticks:{color:C.gm,callback:v=>`${v}%`},grid:{color:'rgba(150,120,220,.06)'}}}};

  return(
    <Shell app={app} back={back}>
      <div><h2 style={{fontFamily:'Syne,sans-serif',fontSize:'1.35rem',fontWeight:800,color:C.gh}}>AI <span style={{color:C.lavL}}>Insights</span></h2><p style={{fontSize:'.68rem',color:C.gm,marginTop:3}}>Explainable AI analysis from all detection modules</p></div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14}}>
        <Panel>
          <PH title="Model Performance"/>
          <div style={{height:200}}><Bar data={barData} options={barOpts}/></div>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8,marginTop:12}}>
            {[['Network RF','99.95%','78 features',C.lav],['APK RF','74.70%','216 features',C.warn],['URL RF','99.88%','16 features',C.safe],['PDF RF','99.90%','21 features',C.info]].map(([name,acc,feat,col])=>(
              <div key={name} style={{padding:'10px',background:'rgba(150,120,220,.04)',border:`1px solid ${C.border}`,borderRadius:8}}>
                <div style={{fontFamily:'Syne,sans-serif',fontSize:'.72rem',color:C.gh,marginBottom:4}}>{name}</div>
                {/* accuracy numbers → JetBrains Mono */}
                <div style={{fontFamily:'"JetBrains Mono",monospace',fontSize:'1.1rem',fontWeight:800,color:col}}>{acc}</div>
                <div style={{fontSize:'.6rem',color:C.gm,marginTop:2}}>{feat}</div>
              </div>
            ))}
          </div>
        </Panel>
        <Panel>
          <PH title="AI Explanation Log"/>
          {aiLog.length===0?(
            <div style={{fontSize:'.68rem',color:C.gm,textAlign:'center',padding:'30px 0'}}>
              <div style={{fontSize:'1.5rem',marginBottom:8}}>🤖</div>
              Run a scan from File Scanner or URL Analyzer to see AI insights here.
            </div>
          ):(
            <div style={{display:'flex',flexDirection:'column',gap:8,maxHeight:360,overflowY:'auto'}}>
              {aiLog.map(log=>{
                const col=log.risk_level==='Critical'||log.risk_level==='High'?C.danger:log.risk_level==='Medium'?C.warn:C.safe;
                return(
                  <div key={log.id} style={{padding:'12px',background:`${col}0d`,border:`1px solid ${col}33`,borderRadius:9,animation:'slide .3s ease'}}>
                    <div style={{display:'flex',justifyContent:'space-between',marginBottom:5}}>
                      <span style={{fontFamily:'Syne,sans-serif',fontSize:'.72rem',fontWeight:700,color:col}}>{log.source}</span>
                      <span style={{fontSize:'.62rem',padding:'1px 7px',borderRadius:4,background:`${col}22`,color:col}}>{log.risk_level}</span>
                    </div>
                    <p style={{fontSize:'.68rem',color:C.gb,lineHeight:1.6,marginBottom:6}}>{log.message}</p>
                    {log.top_features?.length>0&&(
                      <div style={{display:'flex',gap:5,flexWrap:'wrap',marginBottom:6}}>
                        {log.top_features.map(f=><span key={f} style={{padding:'1px 7px',borderRadius:4,background:`${col}18`,color:col,fontSize:'.6rem'}}>{f}</span>)}
                      </div>
                    )}
                    <div style={{fontSize:'.62rem',color:C.gm}}>▶ {log.action} · {log.timestamp}</div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
      </div>
      <Panel>
        <PH title="GenAI Threat Analysis Engine"/>
        <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:14,fontSize:'.72rem',color:C.gb,lineHeight:1.7}}>
          <div>
            <div style={{fontFamily:'Syne,sans-serif',color:C.lavL,marginBottom:6}}>🧠 How It Works</div>
            <p>Each prediction from your trained Random Forest models is enriched with a contextual explanation. The AI engine maps prediction confidence and module type to a curated threat intelligence library, selecting the most relevant insight for the specific threat category.</p>
          </div>
          <div>
            <div style={{fontFamily:'Syne,sans-serif',color:C.lavL,marginBottom:6}}>📊 Feature Importance</div>
            <p>The engine highlights the top 3 features that contributed most to the classification decision, drawn directly from the Random Forest's <code style={{color:C.lav}}>feature_importances_</code> array. This makes predictions explainable and auditable.</p>
          </div>
          <div>
            <div style={{fontFamily:'Syne,sans-serif',color:C.lavL,marginBottom:6}}>⚡ Risk Assessment</div>
            <p>Risk levels (Critical, High, Medium, Low) are derived from both the predicted label and confidence score. Actionable recommendations are generated for each detection, from immediate blocking to monitoring to clearance.</p>
          </div>
        </div>
      </Panel>
    </Shell>
  );
}

/* ═══════════════════════════════════════════
   PAGE: REPORTS
═══════════════════════════════════════════ */
function Reports({app}) {
  const {back,stats,scanHistory,aiLog}=app;
  const threats=scanHistory.filter(s=>s.label==='Malicious').length;
  const suspicious=scanHistory.filter(s=>s.label==='Suspicious').length;
  const safe=scanHistory.filter(s=>s.label==='Safe').length;
  const now=new Date();

  return(
    <Shell app={app} back={back}>
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-end'}}>
        <div><h2 style={{fontFamily:'Syne,sans-serif',fontSize:'1.35rem',fontWeight:800,color:C.gh}}>Security <span style={{color:C.lavL}}>Reports</span></h2><p style={{fontSize:'.68rem',color:C.gm,marginTop:3}}>Session summary and threat intelligence report</p></div>
        <div style={{fontSize:'.65rem',color:C.gm}}>Generated: {now.toLocaleString()}</div>
      </div>

      {/* ── STAT CARDS — numbers use JetBrains Mono ── */}
      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12}}>
        {[
          {label:'Total Scans',val:scanHistory.length||stats?.total_scans||0,color:C.lav},
          {label:'Threats Found',val:threats,color:C.danger},
          {label:'Suspicious',val:suspicious,color:C.warn},
          {label:'Clean',val:safe,color:C.safe},
        ].map((c,i)=>(
          <div key={c.label} style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:'14px 18px',position:'relative',overflow:'hidden',animation:`fadeUp .4s ease ${i*.07}s both`}}>
            <div style={{position:'absolute',top:0,left:0,right:0,height:2,background:c.color,opacity:.8}}/>
            <div style={{fontSize:'.6rem',color:C.gm,letterSpacing:'.1em',textTransform:'uppercase',marginBottom:6}}>{c.label}</div>
            <div style={{fontFamily:'"JetBrains Mono",monospace',fontSize:'1.7rem',fontWeight:800,color:c.color}}>{c.val}</div>
          </div>
        ))}
      </div>

      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14}}>
        <Panel>
          <PH title="Scan History Log"/>
          {scanHistory.length===0?(
            <div style={{fontSize:'.68rem',color:C.gm,textAlign:'center',padding:'20px 0'}}>No scans recorded this session</div>
          ):(
            <div style={{display:'flex',flexDirection:'column',gap:5,maxHeight:300,overflowY:'auto'}}>
              {scanHistory.map((s,i)=>{
                const col=lc(s.label);
                return(
                  <div key={s.id} style={{display:'grid',gridTemplateColumns:'1fr 1fr .8fr .7fr',gap:8,padding:'7px 10px',background:i%2===0?'rgba(150,120,220,.03)':'transparent',borderRadius:6,alignItems:'center',fontSize:'.68rem'}}>
                    <span style={{color:C.gb,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{s.file||s.url||'Network'}</span>
                    <span style={{color:C.gm,fontSize:'.62rem'}}>{s.type||'Network'}</span>
                    <Badge label={s.label}/>
                    <span style={{color:C.gm,fontSize:'.6rem'}}>{s.time}</span>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
        <Panel>
          <PH title="AI Insights Summary"/>
          {aiLog.length===0?(
            <div style={{fontSize:'.68rem',color:C.gm,textAlign:'center',padding:'20px 0'}}>No AI insights generated yet</div>
          ):(
            <div style={{display:'flex',flexDirection:'column',gap:6,maxHeight:300,overflowY:'auto'}}>
              {aiLog.map(log=>{
                const col=log.risk_level==='Critical'||log.risk_level==='High'?C.danger:log.risk_level==='Medium'?C.warn:C.safe;
                return(
                  <div key={log.id} style={{padding:'9px 11px',background:`${col}0d`,border:`1px solid ${col}22`,borderRadius:7}}>
                    <div style={{display:'flex',justifyContent:'space-between',marginBottom:3}}>
                      <span style={{fontSize:'.65rem',color:col,fontWeight:700}}>{log.source}</span>
                      <span style={{fontSize:'.6rem',color:C.gm}}>{log.timestamp}</span>
                    </div>
                    <div style={{fontSize:'.64rem',color:C.gm,lineHeight:1.4}}>{log.message.slice(0,80)}{log.message.length>80?'…':''}</div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
      </div>
      <Panel>
        <PH title="Executive Summary"/>
        <div style={{fontFamily:'DM Mono,monospace',fontSize:'.72rem',color:C.gb,lineHeight:2,background:'rgba(150,120,220,.04)',padding:'16px',borderRadius:9,border:`1px solid ${C.border}`}}>
          <div style={{color:C.lavL,fontFamily:'Syne,sans-serif',fontWeight:700,marginBottom:8}}>⟬⟭ AEGIS ⟭⟬ — Session Report</div>
          <div>Generated : {now.toLocaleString()}</div>
          <div>Session Scans    : {scanHistory.length}</div>
          <div>Threats Detected : <span style={{color:C.danger}}>{threats}</span></div>
          <div>Suspicious Items : <span style={{color:C.warn}}>{suspicious}</span></div>
          <div>Clean Items      : <span style={{color:C.safe}}>{safe}</span></div>
          <div>AI Insights      : {aiLog.length}</div>
          <div>System Status    : <span style={{color:C.safe}}>SECURE</span></div>
          <div style={{marginTop:8,color:C.gm}}>Modules: Network RF (99.95%) | APK RF (74.70%) | URL RF (99.88%) | PDF RF (99.90%)</div>
        </div>
      </Panel>
    </Shell>
  );
}

/* ═══════════════════════════════════════════
   PAGE: ANALYSIS
═══════════════════════════════════════════ */
function Analysis({app}) {
  const {back, stats, scanHistory=[], aiLog=[]} = app;
  const models = [
    {name:'Network RF', acc:99.95, features:78, color:C.lav, desc:'Trained on CIC-IDS 2017 dataset. Detects DDoS, port scans, brute force, and volumetric flood attacks using 78 flow-level features.'},
    {name:'APK RF',     acc:74.70, features:216, color:C.warn, desc:'Analyses Android permission vectors. Detects banking trojans, spyware, and RATs by scoring 216 permission-based binary features.'},
    {name:'URL RF',     acc:99.88, features:16, color:C.safe, desc:'Structural URL analysis. Detects phishing and malware distribution using 16 lexical and domain-based features.'},
    {name:'PDF RF',     acc:99.90, features:21, color:C.info, desc:'PDF metadata analysis. Detects exploit documents and phishing PDFs using 21 structural metadata features.'},
  ];
  const totalScans = scanHistory.length || stats?.total_scans || 0;
  const threats = scanHistory.filter(s=>s.label==='Malicious').length;
  const suspicious = scanHistory.filter(s=>s.label==='Suspicious').length;

  return (
    <Shell app={app} back={back}>
      <div>
        <h2 style={{fontFamily:'Syne,sans-serif',fontSize:'1.35rem',fontWeight:800,color:C.gh}}>System <span style={{color:C.lavL}}>Analysis</span></h2>
        <p style={{fontSize:'.68rem',color:C.gm,marginTop:3}}>Model performance, detection accuracy and feature breakdown</p>
      </div>

      {/* ── STAT CARDS — numbers use JetBrains Mono ── */}
      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12}}>
        {[
          {label:'Models Active', val:'4', color:C.lav},
          {label:'Total Scans',   val:totalScans, color:C.safe},
          {label:'Threats',       val:threats,    color:C.danger},
          {label:'Suspicious',    val:suspicious, color:C.warn},
        ].map((c,i)=>(
          <div key={c.label} style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:'14px 18px',position:'relative',overflow:'hidden',animation:`fadeUp .4s ease ${i*.07}s both`}}>
            <div style={{position:'absolute',top:0,left:0,right:0,height:2,background:c.color,opacity:.8}}/>
            <div style={{fontSize:'.6rem',color:C.gm,letterSpacing:'.1em',textTransform:'uppercase',marginBottom:6}}>{c.label}</div>
            <div style={{fontFamily:'"JetBrains Mono",monospace',fontSize:'1.7rem',fontWeight:800,color:c.color}}>{c.val}</div>
          </div>
        ))}
      </div>

      {/* Model accuracy bars */}
      <Panel>
        <PH title="Model Accuracy Overview"/>
        <div style={{display:'flex',flexDirection:'column',gap:16}}>
          {models.map(m=>(
            <div key={m.name}>
              <div style={{display:'flex',justifyContent:'space-between',marginBottom:6}}>
                <span style={{fontSize:'.74rem',color:C.gh,fontFamily:'Syne,sans-serif',fontWeight:600}}>{m.name}</span>
                {/* accuracy % → JetBrains Mono */}
                <span style={{fontFamily:'"JetBrains Mono",monospace',fontSize:'.74rem',fontWeight:700,color:m.color}}>{m.acc}%</span>
              </div>
              <div style={{height:7,background:'rgba(150,120,220,.1)',borderRadius:4}}>
                <div style={{width:`${m.acc}%`,height:'100%',borderRadius:4,background:m.color,transition:'width 1s ease'}}/>
              </div>
              <div style={{fontSize:'.63rem',color:C.gm,marginTop:4}}>{m.features} features · {m.desc}</div>
            </div>
          ))}
        </div>
      </Panel>

      {/* Feature breakdown */}
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14}}>
        {models.map(m=>(
          <Panel key={m.name} delay={.1}>
            <PH title={`${m.name} — Feature Set`}/>
            <div style={{display:'flex',gap:10,alignItems:'center',marginBottom:12}}>
              <div style={{flex:1,height:60,background:'rgba(150,120,220,.05)',borderRadius:8,display:'flex',alignItems:'center',justifyContent:'center'}}>
                {/* feature count → JetBrains Mono */}
                <span style={{fontFamily:'"JetBrains Mono",monospace',fontSize:'1.6rem',fontWeight:800,color:m.color}}>{m.features}</span>
              </div>
              <div style={{flex:2}}>
                <div style={{fontSize:'.68rem',color:C.gb,lineHeight:1.7}}>{m.desc}</div>
              </div>
            </div>
            <div style={{display:'flex',justifyContent:'space-between',fontSize:'.65rem',color:C.gm,padding:'8px 10px',background:'rgba(150,120,220,.04)',borderRadius:7}}>
              <span>Accuracy</span>
              {/* accuracy → JetBrains Mono */}
              <span style={{fontFamily:'"JetBrains Mono",monospace',color:m.color,fontWeight:700}}>{m.acc}%</span>
            </div>
          </Panel>
        ))}
      </div>

      <Panel>
        <PH title="Latest AI Detection Log"/>
        {aiLog.length===0?(
          <div style={{fontSize:'.68rem',color:C.gm,textAlign:'center',padding:'20px 0'}}>No detections yet — run a scan to see analysis here</div>
        ):(
          <div style={{display:'flex',flexDirection:'column',gap:6,maxHeight:300,overflowY:'auto'}}>
            {aiLog.slice(0,8).map(log=>{
              const col=log.risk_level==='Critical'||log.risk_level==='High'?C.danger:log.risk_level==='Medium'?C.warn:C.safe;
              return(
                <div key={log.id} style={{display:'flex',gap:10,padding:'9px 12px',background:`${col}0d`,border:`1px solid ${col}22`,borderRadius:8}}>
                  <span style={{padding:'2px 8px',borderRadius:4,fontSize:'.6rem',fontWeight:700,background:`${col}22`,color:col,flexShrink:0,alignSelf:'flex-start'}}>{log.risk_level}</span>
                  <div style={{flex:1}}>
                    <div style={{fontSize:'.68rem',color:C.gb,fontWeight:600,marginBottom:2}}>{log.source}</div>
                    <div style={{fontSize:'.63rem',color:C.gm,lineHeight:1.5}}>{log.message?.slice(0,120)}</div>
                  </div>
                  <span style={{fontSize:'.6rem',color:C.gm,flexShrink:0}}>{log.timestamp}</span>
                </div>
              );
            })}
          </div>
        )}
      </Panel>
    </Shell>
  );
}

/* ═══════════════════════════════════════════
   ROOT APP
═══════════════════════════════════════════ */
function AppInner() {
  const app = useApp();
  const [light, setLight] = useState(false);

  const toggleTheme = () => {
    setLight(p=>{
      const next=!p;
      Object.assign(C, next ? LIGHT : DARK);
      const root = document.documentElement;
      if(next){
        root.style.setProperty('--bg','#f5f4ff');
        root.style.setProperty('--fg','#111122');
      } else {
        root.style.setProperty('--bg','#080810');
        root.style.setProperty('--fg','#c8c4d8');
      }
      const tag = document.getElementById('aegis-theme');
      if(tag) tag.textContent = next
        ? `body,#root{background:#f5f4ff!important;color:#111122!important;}
           nav{background:rgba(245,244,255,.97)!important;border-bottom:1px solid rgba(100,80,200,.2)!important;}
           aside{background:rgba(235,233,255,.95)!important;}
           div[style*="background:#11111f"]{background:#ffffff!important;}
           div[style*="background:#080810"]{background:#f5f4ff!important;}
           div[style*="background:rgb(8, 8, 16)"]{background:#f5f4ff!important;}
           div[style*="background:rgb(17, 17, 31)"]{background:#ffffff!important;}`
        : `body,#root{background:#080810!important;color:#c8c4d8!important;}
           nav{background:rgba(8,8,16,.94)!important;}
           aside{background:rgba(11,11,22,.88)!important;}`;
      return next;
    });
  };

  return (
    <ThemeContext.Provider value={{light, toggleTheme}}>
      <Routes>
        <Route path="/"            element={<Login/>}/>
        <Route path="/dashboard"   element={isAuth()?<Dashboard   app={app}/>:<Navigate to="/"/>}/>
        <Route path="/scanner"     element={isAuth()?<FileScanner app={app}/>:<Navigate to="/"/>}/>
        <Route path="/url"         element={isAuth()?<URLAnalyzer app={app}/>:<Navigate to="/"/>}/>
        <Route path="/network"     element={isAuth()?<NetworkMonitor app={app}/>:<Navigate to="/"/>}/>
        <Route path="/ai-insights" element={isAuth()?<AIInsights  app={app}/>:<Navigate to="/"/>}/>
        <Route path="/reports"     element={isAuth()?<Reports     app={app}/>:<Navigate to="/"/>}/>
        <Route path="/analysis"    element={isAuth()?<Analysis    app={app}/>:<Navigate to="/"/>}/>
        <Route path="*"            element={<Navigate to="/"/>}/>
      </Routes>
    </ThemeContext.Provider>
  );
}

export default function App() {
  return (
    <>
      <style>{CSS}</style>
      <style id="aegis-theme"></style>
      <BrowserRouter>
        <AppInner/>
      </BrowserRouter>
    </>
  );
}