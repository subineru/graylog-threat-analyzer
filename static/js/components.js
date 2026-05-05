/* components.js — Icon, primitive UI, modals */

/* ── ICONS ── */
const SVG = {
  dashboard:<svg viewBox="0 0 16 16" fill="none"><rect x="1" y="1" width="6" height="6" rx="1" fill="currentColor"/><rect x="9" y="1" width="6" height="6" rx="1" fill="currentColor" opacity=".5"/><rect x="1" y="9" width="6" height="6" rx="1" fill="currentColor" opacity=".5"/><rect x="9" y="9" width="6" height="6" rx="1" fill="currentColor" opacity=".7"/></svg>,
  events:<svg viewBox="0 0 16 16" fill="none"><path d="M2 3h12M2 8h12M2 13h8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>,
  edl:<svg viewBox="0 0 16 16" fill="none"><path d="M8 2l5 2v4c0 3-2 5-5 6-3-1-5-3-5-6V4l5-2z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/></svg>,
  whitelist:<svg viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.5"/><path d="M5.5 8l2 2 3-3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  audit:<svg viewBox="0 0 16 16" fill="none"><path d="M3 2h8l3 3v9H3V2z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/><path d="M11 2v3h3M5 7h6M5 10h4" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/></svg>,
  system:<svg viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="3" stroke="currentColor" strokeWidth="1.5"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.05 3.05l1.42 1.42M11.53 11.53l1.42 1.42M3.05 12.95l1.42-1.42M11.53 4.47l1.42-1.42" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/></svg>,
  alert:<svg viewBox="0 0 16 16" fill="none"><path d="M8 2L1.5 13h13L8 2z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/><path d="M8 7v3M8 11.5v.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>,
  check:<svg viewBox="0 0 16 16" fill="none"><path d="M3 8l4 4 6-6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  x:<svg viewBox="0 0 16 16" fill="none"><path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>,
  chevR:<svg viewBox="0 0 16 16" fill="none"><path d="M6 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  chevL:<svg viewBox="0 0 16 16" fill="none"><path d="M10 4L6 8l4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  download:<svg viewBox="0 0 16 16" fill="none"><path d="M8 2v8M5 7l3 3 3-3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><path d="M2 13h12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>,
  search:<svg viewBox="0 0 16 16" fill="none"><circle cx="7" cy="7" r="4" stroke="currentColor" strokeWidth="1.5"/><path d="M10 10l3 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>,
  plus:<svg viewBox="0 0 16 16" fill="none"><path d="M8 3v10M3 8h10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>,
  edit:<svg viewBox="0 0 16 16" fill="none"><path d="M11 2l3 3L5 14H2v-3L11 2z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round"/></svg>,
  trash:<svg viewBox="0 0 16 16" fill="none"><path d="M3 5h10M6 5V3h4v2M5 5l1 8h4l1-8" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  refresh:<svg viewBox="0 0 16 16" fill="none"><path d="M13 8A5 5 0 1 1 8 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/><path d="M8 1l3 2-3 2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  dot:<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="4" fill="currentColor"/></svg>,
  pptx:<svg viewBox="0 0 16 16" fill="none"><rect x="2" y="2" width="12" height="12" rx="2" stroke="currentColor" strokeWidth="1.4"/><path d="M5 5h3.5c1 0 1.5.7 1.5 1.5S9.5 8 8.5 8H5V5zM5 8v3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  arrowR:<svg viewBox="0 0 16 16" fill="none"><path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  file:<svg viewBox="0 0 16 16" fill="none"><path d="M3 2h7l3 3v9H3V2z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round"/><path d="M10 2v3h3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/></svg>,
  copy:<svg viewBox="0 0 16 16" fill="none"><rect x="5" y="5" width="9" height="9" rx="1" stroke="currentColor" strokeWidth="1.4"/><path d="M11 5V3H2v9h2" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/></svg>,
};

const Icon = ({n,size=14,color}) => {
  const s=SVG[n]; if(!s) return null;
  return <span style={{display:'inline-flex',width:size,height:size,color:color||'currentColor',flexShrink:0}}>{React.cloneElement(s,{width:size,height:size})}</span>;
};

/* ── PRIMITIVE UI ── */
const Badge = ({verdict,action,stage}) => {
  if(verdict){const m=VM[verdict]||{label:verdict,bg:'#f1f5f9',color:'#64748b'};return <span style={{padding:'2px 8px',borderRadius:3,fontSize:11,fontWeight:600,background:m.bg,color:m.color}}>{m.label}</span>;}
  if(action){const m=AM[action]||{label:action,color:'#64748b'};return <span style={{padding:'2px 8px',borderRadius:3,fontSize:11,fontWeight:500,border:`1px solid ${m.color}40`,color:m.color}}>{m.label}</span>;}
  if(stage){const m=SM[stage]||{label:stage,color:'#64748b'};return <span style={{padding:'1px 6px',borderRadius:3,fontSize:10,fontWeight:500,background:'#f1f5f9',color:m.color,fontFamily:'var(--mono)'}}>{m.label}</span>;}
  return null;
};

const Pill = ({children,color='#64748b',bg='#f1f5f9'}) => (
  <span style={{padding:'2px 8px',borderRadius:10,fontSize:11,fontWeight:500,background:bg,color}}>{children}</span>
);

const Btn = ({children,variant='sec',onClick,disabled,sm,icon,title}) => {
  const base={display:'inline-flex',alignItems:'center',gap:6,padding:sm?'4px 10px':'6px 14px',borderRadius:4,fontSize:sm?11:13,fontWeight:500,cursor:disabled?'not-allowed':'pointer',border:'none',transition:'all .15s',opacity:disabled?.5:1,fontFamily:'var(--font)',whiteSpace:'nowrap'};
  const S={
    pri:   {...base,background:'var(--blue)',color:'#fff'},
    sec:   {...base,background:'#fff',color:'var(--text-sub)',border:'1px solid var(--border)'},
    ghost: {...base,background:'transparent',color:'var(--text-sub)'},
    danger:{...base,background:'var(--red-light)',color:'var(--red)',border:'1px solid #fca5a5'},
    ok:    {...base,background:'var(--green-light)',color:'var(--green)',border:'1px solid #86efac'},
    icon:  {...base,padding:'5px',background:'transparent',color:'var(--text-muted)'},
    navy:  {...base,background:'var(--blue-dark)',color:'#fff'},
  };
  return <button style={S[variant]||S.sec} onClick={onClick} disabled={disabled} title={title}>{icon&&<Icon n={icon} size={13}/>}{children}</button>;
};

const SearchBox = ({value,onChange,placeholder,width=220}) => (
  <div style={{position:'relative',display:'flex',alignItems:'center'}}>
    <span style={{position:'absolute',left:8,pointerEvents:'none',display:'flex',color:'var(--text-muted)'}}><Icon n="search" size={13}/></span>
    <input value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder||'搜尋…'}
      style={{background:'#fff',border:'1px solid var(--border)',borderRadius:4,padding:'6px 10px 6px 28px',color:'var(--text)',fontSize:13,width,outline:'none'}}/>
  </div>
);

const Conf = ({v}) => {
  const pct=Math.round((v||0)*100), c=v>=.9?'var(--red)':v>=.75?'var(--yellow)':'var(--blue)';
  return <div style={{display:'flex',alignItems:'center',gap:5}}><div style={{width:44,height:3,background:'#e2e8f0',borderRadius:2,overflow:'hidden'}}><div style={{width:`${pct}%`,height:'100%',background:c}}/></div><span style={{fontSize:11,color:'var(--text-muted)',fontFamily:'var(--mono)'}}>{pct}%</span></div>;
};

const TH = ({children}) => <th style={{padding:'9px 14px',textAlign:'left',color:'var(--text-muted)',fontWeight:600,fontSize:11,textTransform:'uppercase',letterSpacing:'.05em',whiteSpace:'nowrap',borderBottom:'2px solid var(--border)',background:'#f8fafc'}}>{children}</th>;
const TD = ({children,style}) => <td style={{padding:'9px 14px',borderBottom:'1px solid var(--border)',fontSize:13,...style}}>{children}</td>;

const FF = ({label,children,required}) => (
  <div style={{display:'flex',flexDirection:'column',gap:5}}>
    <label style={{fontSize:11,fontWeight:600,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'.04em'}}>{label}{required&&<span style={{color:'var(--red)',marginLeft:2}}>*</span>}</label>
    {children}
  </div>
);
const FI = ({value,onChange,placeholder,mono,type='text'}) => (
  <input type={type} value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder}
    style={{background:'#fff',border:'1px solid #cbd5e1',borderRadius:4,padding:'7px 10px',color:'var(--text)',fontSize:13,fontFamily:mono?'var(--mono)':'var(--font)',outline:'none',width:'100%'}}/>
);
const FS = ({value,onChange,options}) => (
  <select value={value} onChange={e=>onChange(e.target.value)}
    style={{background:'#fff',border:'1px solid #cbd5e1',borderRadius:4,padding:'7px 10px',color:'var(--text)',fontSize:13,fontFamily:'var(--font)',outline:'none',width:'100%'}}>
    {options.map(([v,l])=><option key={v} value={v}>{l}</option>)}
  </select>
);

/* ── MODAL ── */
const Modal = ({title,onClose,children,width=520}) => (
  <div style={{position:'fixed',inset:0,zIndex:300,background:'rgba(15,23,42,.55)',backdropFilter:'blur(3px)',display:'flex',alignItems:'center',justifyContent:'center'}} onClick={onClose}>
    <div style={{background:'#fff',borderRadius:8,width,maxHeight:'88vh',overflow:'auto',boxShadow:'0 20px 60px rgba(0,0,0,.25)'}} onClick={e=>e.stopPropagation()}>
      <div style={{padding:'16px 22px',borderBottom:'1px solid var(--border)',display:'flex',justifyContent:'space-between',alignItems:'center',position:'sticky',top:0,background:'#fff',zIndex:1}}>
        <span style={{fontWeight:700,fontSize:15,color:'var(--text)'}}>{title}</span>
        <Btn variant="icon" onClick={onClose}><Icon n="x" size={16}/></Btn>
      </div>
      <div style={{padding:22}}>{children}</div>
    </div>
  </div>
);

/* ── PERIOD BAR ── */
const PeriodBar = ({onLoad,updatedAt,onExport,dateFrom,dateTo,setDateFrom,setDateTo}) => {
  const [period,setPeriod] = useState('Today');
  const presets = [['Today',0],['7 Days',6],['30 Days',29],['99 Days',98]];
  const handlePreset = (label,days) => {
    setPeriod(label);
    setDateFrom(daysAgo(days));
    setDateTo(today());
  };
  return (
    <div style={{display:'flex',alignItems:'center',gap:10,padding:'8px 20px',background:'#fff',borderBottom:'1px solid var(--border)',flexWrap:'wrap'}}>
      <span style={{fontSize:13,color:'var(--text-sub)',fontWeight:500}}>Period:</span>
      <div style={{display:'flex',gap:0,border:'1px solid var(--border)',borderRadius:4,overflow:'hidden'}}>
        {presets.map(([label,days])=>(
          <button key={label} onClick={()=>handlePreset(label,days)} style={{padding:'5px 12px',border:'none',cursor:'pointer',fontSize:12,fontWeight:500,background:period===label?'var(--blue)':'#fff',color:period===label?'#fff':'var(--text-sub)',transition:'all .15s',fontFamily:'var(--font)'}}>{label}</button>
        ))}
      </div>
      <input type="date" value={dateFrom} onChange={e=>{setPeriod('');setDateFrom(e.target.value);}}
        style={{border:'1px solid var(--border)',borderRadius:4,padding:'5px 8px',fontSize:12,color:'var(--text)',outline:'none',background:'#fff'}}/>
      <span style={{color:'var(--text-muted)',fontSize:13}}>~</span>
      <input type="date" value={dateTo} onChange={e=>{setPeriod('');setDateTo(e.target.value);}}
        style={{border:'1px solid var(--border)',borderRadius:4,padding:'5px 8px',fontSize:12,color:'var(--text)',outline:'none',background:'#fff'}}/>
      <Btn variant="pri" sm onClick={onLoad}>Load</Btn>
      {updatedAt && <span style={{fontSize:11,color:'var(--text-muted)'}}>Updated: {updatedAt}</span>}
      <div style={{marginLeft:'auto'}}>
        <Btn variant="navy" sm icon="pptx" onClick={onExport}>↑ Export PPT</Btn>
      </div>
    </div>
  );
};

/* ── WARNING BANNER ── */
const WarningBanner = ({count,onViewEDL,onViewWhitelist}) => (
  count>0 ? (
    <div style={{margin:'12px 20px 0',padding:'10px 16px',background:'#fffbeb',border:'1px solid #fcd34d',borderRadius:6,display:'flex',alignItems:'center',gap:8,fontSize:13}}>
      <Icon n="alert" size={15} color="#d97706"/>
      <span style={{color:'#92400e',fontWeight:500}}>{count} items require analyst review (monitor/investigate).</span>
      <button onClick={onViewEDL} style={{marginLeft:8,background:'none',border:'none',color:'var(--blue)',cursor:'pointer',fontSize:13,fontWeight:500,textDecoration:'underline',fontFamily:'var(--font)'}}>View EDL pending</button>
      <button onClick={onViewWhitelist} style={{background:'none',border:'none',color:'var(--blue)',cursor:'pointer',fontSize:13,fontWeight:500,textDecoration:'underline',fontFamily:'var(--font)'}}>View Whitelist pending</button>
    </div>
  ) : null
);

/* ── PIPELINE VIZ ── */
const PipelineViz = ({event}) => {
  const idx = PIPELINE.findIndex(g=>g.id===event?.stage);
  return (
    <div style={{display:'flex',alignItems:'center',gap:0,overflow:'auto',padding:'4px 0'}}>
      {PIPELINE.map((g,i)=>{
        const hit=g.id===event?.stage, passed=idx>i&&event;
        return (
          <React.Fragment key={g.id}>
            <div style={{display:'flex',flexDirection:'column',alignItems:'center',gap:3,padding:'8px 12px',borderRadius:4,border:'1px solid',flexShrink:0,borderColor:hit?g.color:'#e2e8f0',background:hit?g.color+'18':'#f8fafc',opacity:!event?.stage?.length?0.4:passed?0.35:1}}>
              <span style={{fontSize:11,fontWeight:hit?700:500,color:hit?g.color:'#64748b',whiteSpace:'nowrap'}}>{g.label}</span>
              <span style={{fontSize:10,color:'#94a3b8',whiteSpace:'nowrap'}}>{g.sub}</span>
              {hit&&<span style={{fontSize:9,fontWeight:700,color:g.color,textTransform:'uppercase'}}>命中</span>}
            </div>
            {i<PIPELINE.length-1&&<div style={{color:'#cbd5e1',flexShrink:0,opacity:passed?0.3:1}}><Icon n="arrowR" size={13}/></div>}
          </React.Fragment>
        );
      })}
    </div>
  );
};

/* ── EVENT DETAIL MODAL ── */
const EventDetail = ({event,onClose,onAddWhitelist,onAddEDL}) => {
  if(!event) return null;
  return (
    <Modal title={`事件詳情 — ${event.id}`} onClose={onClose} width={680}>
      <div style={{display:'flex',flexDirection:'column',gap:18}}>
        <div style={{display:'flex',gap:8,flexWrap:'wrap'}}><Badge verdict={event.verdict}/><Badge action={event.recommended_action}/><Badge stage={event.stage}/></div>
        <div>
          <div style={{fontSize:11,fontWeight:600,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'.05em',marginBottom:8}}>研判流程</div>
          <PipelineViz event={event}/>
        </div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
          {[['時間戳記',fmt(event.ts),true],['Signature ID',event.sig_id,true],['來源 IP',event.src_ip,true],['目的 IP',event.dst_ip,true],['來源主機',event.src_hostname||'—',false],['部門',event.src_dept||'—',false],['動作',event.action,true],['嚴重程度',event.severity||'—',true]].map(([k,v,m])=>(
            <div key={k} style={{background:'#f8fafc',borderRadius:4,padding:'9px 12px',border:'1px solid var(--border)'}}>
              <div style={{fontSize:10,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase',letterSpacing:'.04em',marginBottom:3}}>{k}</div>
              <div style={{fontSize:13,fontFamily:m?'var(--mono)':undefined,color:'var(--text)',fontWeight:500}}>{v}</div>
            </div>
          ))}
        </div>
        <div>
          <div style={{fontSize:11,fontWeight:600,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'.05em',marginBottom:8}}>PAN THREAT 欄位</div>
          <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:8}}>
            {[['來源 Zone',event.src_zone],['目的 Zone',event.dst_zone],['Rule Name',event.rule_name],['Transport',event.transport],['Direction',event.direction]].map(([k,v])=>(
              <div key={k} style={{background:'#f8fafc',borderRadius:4,padding:'8px 12px',border:'1px solid var(--border)'}}>
                <div style={{fontSize:10,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase',letterSpacing:'.04em',marginBottom:3}}>{k}</div>
                <div style={{fontSize:12,fontFamily:'var(--mono)',color:'var(--text)'}}>{v||'—'}</div>
              </div>
            ))}
          </div>
        </div>
        <div style={{background:'#f8fafc',borderRadius:4,padding:'10px 14px',border:'1px solid var(--border)'}}>
          <div style={{fontSize:11,color:'var(--text-muted)',fontWeight:600,textTransform:'uppercase',letterSpacing:'.04em',marginBottom:4}}>Signature 名稱</div>
          <div style={{fontSize:13}}>{event.sig_name}</div>
        </div>
        <div style={{background:'#fffbeb',border:'1px solid #fcd34d',borderRadius:4,padding:'12px 16px'}}>
          <div style={{fontSize:11,color:'#92400e',fontWeight:600,textTransform:'uppercase',letterSpacing:'.04em',marginBottom:6}}>研判理由</div>
          <div style={{fontSize:13,color:'#78350f',lineHeight:1.7}}>{event.reasoning}</div>
        </div>
        <div style={{display:'flex',alignItems:'center',gap:10}}>
          <span style={{fontSize:12,color:'var(--text-muted)',flexShrink:0}}>信心度</span>
          <div style={{flex:1,height:5,background:'#e2e8f0',borderRadius:3,overflow:'hidden'}}>
            <div style={{width:`${(event.confidence||0)*100}%`,height:'100%',background:event.confidence>=.9?'var(--red)':event.confidence>=.75?'var(--yellow)':'var(--blue)'}}/>
          </div>
          <span style={{fontSize:12,fontWeight:700,fontFamily:'var(--mono)',flexShrink:0}}>{Math.round((event.confidence||0)*100)}%</span>
        </div>
        {(event.verdict==='anomalous'||event.verdict==='false_positive'||event.verdict==='normal')&&(
          <div style={{display:'flex',gap:10,paddingTop:6,borderTop:'1px solid var(--border)'}}>
            {event.verdict==='anomalous'&&<Btn variant="danger" icon="edl" onClick={()=>onAddEDL(event)}>加入 EDL 封鎖</Btn>}
            <Btn variant="sec" icon="whitelist" onClick={()=>onAddWhitelist(event)}>加入白名單</Btn>
          </div>
        )}
      </div>
    </Modal>
  );
};

/* ── WHITELIST MODAL ── */
const WLModal = ({initial,onSave,onClose}) => {
  const blank = {sig_id:'',sig_name:'',action:'alert',src_ip:'',dst_ip:'',note:'',status:'monitoring',ttl_days:'90'};
  const [f,setF]=useState(initial||blank);
  const s=k=>v=>setF(prev=>({...prev,[k]:v}));
  useEffect(()=>{ setF(initial||blank); }, [initial?.id]);
  return (
    <Modal title={initial?.id?'編輯白名單規則':'新增白名單規則'} onClose={onClose} width={560}>
      <div style={{display:'flex',flexDirection:'column',gap:14}}>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
          <FF label="Signature ID" required><FI value={f.sig_id} onChange={s('sig_id')} placeholder="92322" mono/></FF>
          <FF label="動作"><FS value={f.action} onChange={s('action')} options={[['alert','alert'],['drop','drop'],['block-ip','block-ip'],['reset-both','reset-both'],['','any']]}/></FF>
        </div>
        <FF label="Signature 名稱" required><FI value={f.sig_name} onChange={s('sig_name')} placeholder="Signature 全名"/></FF>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
          <FF label="來源 IP / CIDR"><FI value={f.src_ip} onChange={s('src_ip')} placeholder="空白=任意" mono/></FF>
          <FF label="目的 IP / CIDR"><FI value={f.dst_ip} onChange={s('dst_ip')} placeholder="空白=任意" mono/></FF>
        </div>
        <FF label="備註"><FI value={f.note} onChange={s('note')} placeholder="說明此規則用途"/></FF>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
          <FF label="狀態"><FS value={f.status} onChange={v=>setF(p=>({...p,status:v,...(v==='confirmed'?{ttl_days:'-1'}:{})}))} options={[['monitoring','monitoring'],['confirmed','confirmed']]}/></FF>
          <FF label="TTL（天，-1=永不過期）"><FI value={String(f.ttl_days)} onChange={s('ttl_days')} placeholder="90" mono type="number" disabled={f.status==='confirmed'}/></FF>
        </div>
        <div style={{display:'flex',justifyContent:'flex-end',gap:10,paddingTop:8,borderTop:'1px solid var(--border)'}}>
          <Btn variant="sec" onClick={onClose}>取消</Btn>
          <Btn variant="pri" disabled={!f.sig_id||!f.sig_name} onClick={()=>onSave({...f,ttl_days:f.status==='confirmed'?-1:(parseInt(f.ttl_days)||90)})}>儲存</Btn>
        </div>
      </div>
    </Modal>
  );
};

/* ── EDL TTL MODAL ── */
const TTLModal = ({entry,onSave,onClose}) => {
  const [v,setV]=useState(String(entry.ttl_days));
  return (
    <Modal title={`修改 TTL — ${entry.value}`} onClose={onClose} width={380}>
      <div style={{display:'flex',flexDirection:'column',gap:14}}>
        <div style={{background:'#f8fafc',border:'1px solid var(--border)',borderRadius:4,padding:'10px 14px',fontSize:13}}>
          <div style={{fontSize:11,color:'var(--text-muted)',marginBottom:3}}>當前 TTL</div>
          <span style={{fontFamily:'var(--mono)',fontWeight:600}}>{entry.ttl_days===-1?'∞ 永不過期':entry.ttl_days+'d'}</span>
        </div>
        <FF label="新 TTL（天，-1=永不過期）"><FI value={v} onChange={setV} placeholder="-1 或天數" mono type="number"/></FF>
        <div style={{display:'flex',gap:8,justifyContent:'flex-end',paddingTop:8,borderTop:'1px solid var(--border)'}}>
          <Btn variant="sec" onClick={onClose}>取消</Btn>
          <Btn variant="pri" onClick={()=>onSave(parseInt(v))}>確認</Btn>
        </div>
      </div>
    </Modal>
  );
};

/* ── EDL FILE MODAL ── */
const EDLFileModal = ({active,onClose}) => {
  const [tab,setTab]=useState('ip');
  const files={
    ip:     {name:'block_ip.txt',    items:active.filter(a=>a.type==='ip').map(a=>a.value)},
    domain: {name:'block_domain.txt',items:active.filter(a=>a.type==='domain').map(a=>a.value)},
    url:    {name:'block_url.txt',   items:active.filter(a=>a.type==='url').map(a=>a.value)},
  };
  const cur=files[tab];
  const content=`# Generated by Graylog Threat Analyzer\n# Updated: ${new Date().toISOString()}\n# Count: ${cur.items.length}\n${cur.items.join('\n')}`;
  return (
    <Modal title="EDL 檔案預覽 (GlobalProtect 格式)" onClose={onClose} width={580}>
      <div style={{display:'flex',flexDirection:'column',gap:14}}>
        <div style={{display:'flex',gap:4}}>
          {Object.entries(files).map(([k,f])=>(
            <button key={k} onClick={()=>setTab(k)} style={{padding:'5px 14px',borderRadius:4,border:'1px solid var(--border)',cursor:'pointer',fontSize:12,fontWeight:500,background:tab===k?'var(--blue-light)':'#fff',color:tab===k?'var(--blue)':'var(--text-sub)',fontFamily:'var(--font)'}}>
              {f.name} ({f.items.length})
            </button>
          ))}
        </div>
        <pre style={{background:'#0f172a',borderRadius:6,padding:16,fontFamily:'var(--mono)',fontSize:12,color:'#94a3b8',lineHeight:1.7,maxHeight:280,overflow:'auto',whiteSpace:'pre-wrap'}}>{content}</pre>
        <div style={{display:'flex',gap:8,justifyContent:'flex-end'}}>
          <Btn variant="sec" icon="copy" onClick={()=>navigator.clipboard?.writeText(content)}>複製</Btn>
          <Btn variant="sec" onClick={onClose}>關閉</Btn>
        </div>
      </div>
    </Modal>
  );
};

Object.assign(window, {
  Icon, Badge, Pill, Btn, SearchBox, Conf, TH, TD, FF, FI, FS,
  Modal, PeriodBar, WarningBanner, PipelineViz,
  EventDetail, WLModal, TTLModal, EDLFileModal,
});
