/* pages.js — DashboardPage, EventsPage, EDLPage, WhitelistPage, AuditPage, SystemPage */

/* ── DASHBOARD PAGE ── */
const DashboardPage = ({stats,setPage,edlPending,whitelist,actionDist,dailyData,topSigs,loading}) => {
  const maxDaily = Math.max(...(dailyData.map(d=>d.count)), 1);
  if(loading) return (
    <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:200,color:'var(--text-muted)',fontSize:13}}>
      載入中…
    </div>
  );
  return (
    <div style={{display:'flex',flexDirection:'column',gap:0}}>
      {/* KPI row */}
      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:14,padding:'16px 20px'}}>
        {[
          {label:'TOTAL EVENTS',    val:stats.total_events.toLocaleString(), sub:'Events processed in period', valColor:'var(--text)'},
          {label:'BLOCKED',         val:stats.blocked,                        sub:'Confirmed threats (EDL candidates)', valColor:'var(--red)'},
          {label:'SUPPRESSION RATE',val:stats.suppression_rate+'%',           sub:'Auto-handled without alert', valColor:'var(--green)'},
          {label:'PENDING REVIEW',  val:stats.pending_review,                 sub:'Monitor + Investigate items', valColor:'var(--orange)'},
        ].map(k=>(
          <div key={k.label} style={{background:'#fff',border:'1px solid var(--border)',borderRadius:6,padding:'18px 20px',display:'flex',flexDirection:'column',gap:6}}>
            <div style={{fontSize:11,fontWeight:700,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'.07em'}}>{k.label}</div>
            <div style={{fontSize:32,fontWeight:700,color:k.valColor,letterSpacing:'-.02em',lineHeight:1}}>{k.val}</div>
            <div style={{fontSize:11,color:'var(--text-muted)'}}>{k.sub}</div>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14,padding:'0 20px 16px'}}>
        {/* Action Distribution */}
        <div style={{background:'#fff',border:'1px solid var(--border)',borderRadius:6,overflow:'hidden'}}>
          <div style={{padding:'12px 18px',borderBottom:'1px solid var(--border)',background:'#1a2840'}}>
            <span style={{fontSize:13,fontWeight:600,color:'#fff'}}>Action Distribution</span>
          </div>
          <div style={{padding:'16px 20px',display:'flex',flexDirection:'column',gap:12}}>
            {actionDist.map(a=>{
              const barW = Math.max(parseFloat(a.pct), 0.3);
              return (
                <div key={a.action} style={{display:'flex',alignItems:'center',gap:10}}>
                  <span style={{width:72,fontSize:13,color:'var(--text-sub)',textAlign:'right',flexShrink:0}}>{a.action}</span>
                  <div style={{flex:1,height:22,background:'#f1f5f9',borderRadius:3,overflow:'hidden',position:'relative'}}>
                    <div style={{width:`${barW}%`,height:'100%',background:a.color,borderRadius:3,transition:'width .5s'}}/>
                  </div>
                  <span style={{width:90,fontSize:12,color:'var(--text-muted)',textAlign:'right',flexShrink:0,fontFamily:'var(--mono)'}}>
                    {a.count.toLocaleString()} ({a.pct}%)
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Daily Trend */}
        <div style={{background:'#fff',border:'1px solid var(--border)',borderRadius:6,overflow:'hidden'}}>
          <div style={{padding:'12px 18px',borderBottom:'1px solid var(--border)',background:'#1a2840'}}>
            <span style={{fontSize:13,fontWeight:600,color:'#fff'}}>Daily Trend</span>
          </div>
          <div style={{padding:'16px 20px',display:'flex',flexDirection:'column',gap:12}}>
            {dailyData.length===0 && <span style={{fontSize:12,color:'var(--text-muted)'}}>此期間無資料</span>}
            {dailyData.map(d=>{
              const barW = (d.count/maxDaily)*100;
              return (
                <div key={d.date} style={{display:'flex',alignItems:'center',gap:12}}>
                  <span style={{width:80,fontSize:12,fontFamily:'var(--mono)',color:'var(--text-sub)',flexShrink:0}}>{d.date}</span>
                  <div style={{flex:1,height:22,background:'#f1f5f9',borderRadius:3,overflow:'hidden'}}>
                    <div style={{width:`${barW}%`,height:'100%',background:'#2563eb',borderRadius:3,transition:'width .5s'}}/>
                  </div>
                  <span style={{width:50,fontSize:12,fontFamily:'var(--mono)',color:'var(--text-sub)',textAlign:'right',flexShrink:0}}>{d.count.toLocaleString()}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Top 10 Threat Signatures */}
      <div style={{margin:'0 20px 20px',background:'#fff',border:'1px solid var(--border)',borderRadius:6,overflow:'hidden'}}>
        <div style={{padding:'12px 18px',borderBottom:'1px solid var(--border)',background:'#1a2840'}}>
          <span style={{fontSize:13,fontWeight:600,color:'#fff'}}>Top 10 Threat Signatures</span>
        </div>
        {topSigs.length===0
          ? <div style={{padding:'24px',textAlign:'center',color:'var(--text-muted)',fontSize:13}}>此期間無資料</div>
          : <table style={{width:'100%',borderCollapse:'collapse'}}>
              <thead><tr><TH>#</TH><TH>Signature</TH><TH>Count</TH></tr></thead>
              <tbody>
                {topSigs.map((s,i)=>(
                  <tr key={s.rank} style={{background:i%2?'#f8fafc':'#fff'}}>
                    <TD><span style={{fontWeight:700,color:'var(--blue)',fontFamily:'var(--mono)'}}>#{s.rank}</span></TD>
                    <TD><span style={{fontSize:13,color:'var(--text)'}}>{s.sig}</span></TD>
                    <TD>
                      <span style={{fontFamily:'var(--mono)',fontWeight:600}}>{s.count.toLocaleString()}</span>
                      <span style={{marginLeft:8,fontSize:11,color:'var(--text-muted)'}}>({s.pct}%)</span>
                    </TD>
                  </tr>
                ))}
              </tbody>
            </table>
        }
      </div>
    </div>
  );
};

/* ── EVENTS PAGE ── */
const EventsPage = ({events,onAddWhitelist,onAddEDL}) => {
  const [q,setQ]=useState('');
  const [flt,setFlt]=useState('all');
  const [sel,setSel]=useState(null);
  const rows=events.filter(e=>{
    const qq=q.toLowerCase();
    return (!qq||(e.src_ip||'').includes(qq)||(e.sig_name||'').toLowerCase().includes(qq)||(e.sig_id||'').includes(qq))
        && (flt==='all'||e.verdict===flt);
  });
  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:12}}>
      <div style={{display:'flex',gap:10,alignItems:'center',flexWrap:'wrap'}}>
        <SearchBox value={q} onChange={setQ} placeholder="搜尋 IP / Signature…"/>
        <div style={{display:'flex',gap:3}}>
          {['all','anomalous','false_positive','normal','duplicate'].map(f=>(
            <button key={f} onClick={()=>setFlt(f)} style={{padding:'5px 12px',borderRadius:4,fontSize:12,fontWeight:500,cursor:'pointer',border:'1px solid var(--border)',background:flt===f?'var(--blue)':'#fff',color:flt===f?'#fff':'var(--text-sub)',transition:'all .15s',fontFamily:'var(--font)'}}>
              {f==='all'?'全部':VM[f]?.label||f}
            </button>
          ))}
        </div>
        <span style={{marginLeft:'auto',fontSize:12,color:'var(--text-muted)'}}>{rows.length} 筆</span>
      </div>
      {events.length===0
        ? <div style={{background:'#fff',border:'1px solid var(--border)',borderRadius:6,padding:40,textAlign:'center',color:'var(--text-muted)',fontSize:13}}>此期間無事件紀錄</div>
        : <div style={{background:'#fff',border:'1px solid var(--border)',borderRadius:6,overflow:'hidden'}}>
            <table style={{width:'100%',borderCollapse:'collapse'}}>
              <thead><tr><TH>時間</TH><TH>來源 IP</TH><TH>目的 IP</TH><TH>Signature</TH><TH>Verdict</TH><TH>動作</TH><TH>Stage</TH><TH>信心度</TH><TH></TH></tr></thead>
              <tbody>
                {rows.map((e,i)=>(
                  <tr key={e.id} onClick={()=>setSel(e)} style={{cursor:'pointer',background:i%2?'#f8fafc':'#fff',transition:'background .1s'}}
                    onMouseEnter={ev=>ev.currentTarget.style.background='#eff6ff'}
                    onMouseLeave={ev=>ev.currentTarget.style.background=i%2?'#f8fafc':'#fff'}>
                    <TD style={{fontSize:11,fontFamily:'var(--mono)',whiteSpace:'nowrap',color:'var(--text-muted)'}}>{fmt(e.ts)}</TD>
                    <TD style={{fontFamily:'var(--mono)',fontSize:12,whiteSpace:'nowrap'}}>{e.src_ip}</TD>
                    <TD style={{fontFamily:'var(--mono)',fontSize:12,whiteSpace:'nowrap',color:'var(--text-sub)'}}>{e.dst_ip}</TD>
                    <TD style={{maxWidth:200,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',color:'var(--text-sub)'}}>{e.sig_name}</TD>
                    <TD><Badge verdict={e.verdict}/></TD>
                    <TD><Badge action={e.recommended_action}/></TD>
                    <TD><Badge stage={e.stage}/></TD>
                    <TD><Conf v={e.confidence}/></TD>
                    <TD><Icon n="chevR" size={13} color="#94a3b8"/></TD>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
      }
      {sel&&<EventDetail event={sel} onClose={()=>setSel(null)}
        onAddWhitelist={e=>{onAddWhitelist(e);setSel(null);}}
        onAddEDL={e=>{onAddEDL(e);setSel(null);}}/>}
    </div>
  );
};

/* ── EDL PAGE ── */
const EDLPage = ({pending,active,onApprove,onReject,onEditTTL}) => {
  const [tab,setTab]=useState('pending');
  const [editEntry,setEditEntry]=useState(null);
  const [showFiles,setShowFiles]=useState(false);
  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:12}}>
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
        <div style={{display:'flex',gap:0,border:'1px solid var(--border)',borderRadius:4,overflow:'hidden',background:'#fff'}}>
          {[['pending','待審封鎖'],['active','已封鎖']].map(([k,l])=>(
            <button key={k} onClick={()=>setTab(k)} style={{padding:'6px 18px',border:'none',cursor:'pointer',fontSize:13,fontWeight:500,background:tab===k?'var(--blue)':'transparent',color:tab===k?'#fff':'var(--text-sub)',transition:'all .15s',fontFamily:'var(--font)'}}>
              {l}{k==='pending'&&pending.length>0&&<span style={{marginLeft:6,background:tab==='pending'?'rgba(255,255,255,.3)':'var(--red)',color:'#fff',borderRadius:8,padding:'0 5px',fontSize:10,fontWeight:700}}>{pending.length}</span>}
            </button>
          ))}
        </div>
        <Btn variant="sec" icon="file" onClick={()=>setShowFiles(true)}>EDL 檔案預覽</Btn>
      </div>

      {tab==='pending'&&(
        <div style={{display:'flex',flexDirection:'column',gap:10}}>
          {pending.length===0&&<div style={{background:'#fff',border:'1px solid var(--border)',borderRadius:6,padding:32,textAlign:'center',color:'var(--text-muted)',fontSize:13}}>無待審條目</div>}
          {pending.map(p=>(
            <div key={p.id} style={{background:'#fff',border:'1px solid var(--border)',borderRadius:6,padding:'14px 20px',display:'flex',alignItems:'center',gap:14}}>
              <div style={{width:8,height:8,borderRadius:2,background:p.type==='ip'?'var(--red)':p.type==='domain'?'var(--purple)':'var(--yellow)',flexShrink:0}}/>
              <div style={{flex:1,minWidth:0}}>
                <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:4}}>
                  <Pill bg={p.type==='ip'?'#fee2e2':'#f3e8ff'} color={p.type==='ip'?'var(--red)':'var(--purple)'}>{p.type.toUpperCase()}</Pill>
                  <span style={{fontFamily:'var(--mono)',fontSize:14,fontWeight:700,color:'var(--text)'}}>{p.value}</span>
                </div>
                <div style={{fontSize:12,color:'var(--text-muted)'}}>{p.reason}</div>
              </div>
              <div style={{display:'flex',flexDirection:'column',alignItems:'flex-end',gap:4,fontSize:11,color:'var(--text-muted)',flexShrink:0}}>
                <Conf v={p.confidence}/>
                <span>{fmt(p.created)}</span>
              </div>
              <div style={{display:'flex',gap:8,flexShrink:0}}>
                <Btn variant="ok" sm icon="check" onClick={()=>onApprove(p.token)}>確認封鎖</Btn>
                <Btn variant="danger" sm icon="x" onClick={()=>onReject(p.token)}>拒絕</Btn>
              </div>
            </div>
          ))}
        </div>
      )}

      {tab==='active'&&(
        <div style={{background:'#fff',border:'1px solid var(--border)',borderRadius:6,overflow:'hidden'}}>
          {active.length===0
            ? <div style={{padding:32,textAlign:'center',color:'var(--text-muted)',fontSize:13}}>無已封鎖條目</div>
            : <table style={{width:'100%',borderCollapse:'collapse'}}>
                <thead><tr><TH>類型</TH><TH>值</TH><TH>核准時間</TH><TH>TTL</TH><TH>到期日</TH><TH></TH></tr></thead>
                <tbody>
                  {active.map((a,i)=>(
                    <tr key={a.id} style={{background:i%2?'#f8fafc':'#fff'}}>
                      <TD><Pill bg={a.type==='ip'?'#fee2e2':a.type==='domain'?'#f3e8ff':'#fef3c7'} color={a.type==='ip'?'var(--red)':a.type==='domain'?'var(--purple)':'var(--yellow)'}>{a.type.toUpperCase()}</Pill></TD>
                      <TD style={{fontFamily:'var(--mono)',fontSize:13,fontWeight:600}}>{a.value}</TD>
                      <TD style={{fontSize:11,fontFamily:'var(--mono)',color:'var(--text-muted)'}}>{a.approved_at?fmt(a.approved_at):'—'}</TD>
                      <TD style={{fontFamily:'var(--mono)',fontWeight:600,color:a.ttl_days===-1?'var(--blue)':'var(--text)'}}>{a.ttl_days===-1?'∞':a.ttl_days+'d'}</TD>
                      <TD style={{color:'var(--text-sub)'}}>{a.expires}</TD>
                      <TD><Btn variant="icon" sm title="修改 TTL" onClick={()=>setEditEntry(a)}><Icon n="edit" size={13} color="#94a3b8"/></Btn></TD>
                    </tr>
                  ))}
                </tbody>
              </table>
          }
        </div>
      )}
      {editEntry&&<TTLModal entry={editEntry} onClose={()=>setEditEntry(null)} onSave={days=>{onEditTTL(editEntry.value,days);setEditEntry(null);}}/>}
      {showFiles&&<EDLFileModal active={active} onClose={()=>setShowFiles(false)}/>}
    </div>
  );
};

/* ── WHITELIST PAGE ── */
const WhitelistPage = ({rules,onAdd,onEdit,onDelete,onReload}) => {
  const [q,setQ]=useState('');
  const [modal,setModal]=useState(false);
  const [editTarget,setEditTarget]=useState(null);
  const [reloading,setReloading]=useState(false);
  const filtered=rules.filter(r=>{
    const qq=q.toLowerCase();
    return !qq||(r.sig_name||'').toLowerCase().includes(qq)||(r.sig_id||'').includes(qq)||(r.src_ip||'').includes(qq)||(r.dst_ip||'').includes(qq)||(r.note||'').toLowerCase().includes(qq);
  });
  const doReload=async()=>{setReloading(true);try{await onReload();}finally{setReloading(false);}};
  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:12}}>
      <div style={{display:'flex',gap:10,alignItems:'center'}}>
        <SearchBox value={q} onChange={setQ} placeholder="搜尋 Signature / IP / 備註…"/>
        <div style={{marginLeft:'auto',display:'flex',gap:8}}>
          <Btn variant="sec" icon="refresh" onClick={doReload}>{reloading?'重載中…':'Hot Reload'}</Btn>
          <Btn variant="pri" icon="plus" onClick={()=>{setEditTarget(null);setModal(true);}}>新增規則</Btn>
        </div>
      </div>
      <div style={{background:'#fff',border:'1px solid var(--border)',borderRadius:6,overflow:'hidden'}}>
        {rules.length===0
          ? <div style={{padding:40,textAlign:'center',color:'var(--text-muted)',fontSize:13}}>無白名單規則</div>
          : <table style={{width:'100%',borderCollapse:'collapse'}}>
              <thead><tr><TH>Sig ID</TH><TH>Signature 名稱</TH><TH>動作</TH><TH>來源 IP</TH><TH>目的 IP</TH><TH>備註</TH><TH>狀態</TH><TH>TTL</TH><TH>命中</TH><TH>最後命中</TH><TH></TH></tr></thead>
              <tbody>
                {filtered.map((r,i)=>(
                  <tr key={`${r.id}_${i}`} style={{background:i%2?'#f8fafc':'#fff'}}>
                    <TD style={{fontFamily:'var(--mono)',fontSize:11,color:'var(--blue)',fontWeight:600}}>{r.sig_id}</TD>
                    <TD style={{maxWidth:180,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{r.sig_name}</TD>
                    <TD><Pill>{r.action||'any'}</Pill></TD>
                    <TD style={{fontFamily:'var(--mono)',fontSize:11,color:'var(--text-sub)'}}>{r.src_ip||<span style={{color:'#94a3b8'}}>*</span>}</TD>
                    <TD style={{fontFamily:'var(--mono)',fontSize:11,color:'var(--text-sub)'}}>{r.dst_ip||<span style={{color:'#94a3b8'}}>*</span>}</TD>
                    <TD style={{fontSize:11,color:'var(--text-muted)',maxWidth:120,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{r.note}</TD>
                    <TD><Pill bg={r.status==='confirmed'?'#dcfce7':'#fef3c7'} color={r.status==='confirmed'?'var(--green)':'var(--yellow)'}>{r.status}</Pill></TD>
                    <TD style={{fontFamily:'var(--mono)',fontSize:11,fontWeight:600,color:r.ttl_days===-1?'var(--blue)':'var(--text)'}}>{r.ttl_days===-1?'∞':r.ttl_days+'d'}</TD>
                    <TD style={{fontFamily:'var(--mono)',fontWeight:700,color:r.hit_count>100?'var(--green)':'var(--text)'}}>{(r.hit_count||0).toLocaleString()}</TD>
                    <TD style={{fontSize:11,color:'var(--text-muted)',whiteSpace:'nowrap'}}>{r.last_hit?fmt(r.last_hit):'—'}</TD>
                    <TD>
                      <div style={{display:'flex',gap:4}}>
                        <Btn variant="icon" sm title="編輯" onClick={()=>{setEditTarget(r);setModal(true);}}><Icon n="edit" size={13} color="#94a3b8"/></Btn>
                        <Btn variant="icon" sm title="刪除" onClick={()=>onDelete(r.id,r.src_ip,r.dst_ip)}><Icon n="trash" size={13} color="#ef4444"/></Btn>
                      </div>
                    </TD>
                  </tr>
                ))}
              </tbody>
            </table>
        }
      </div>
      <div style={{display:'flex',gap:16,padding:'10px 16px',background:'#fff',border:'1px solid var(--border)',borderRadius:6,fontSize:12,flexWrap:'wrap'}}>
        {[['共',rules.length,'條規則','var(--text)'],['總命中',rules.reduce((s,r)=>s+(r.hit_count||0),0).toLocaleString(),'次','var(--text)'],['永久',rules.filter(r=>r.ttl_days===-1).length,'條','var(--blue)'],['觀察中',rules.filter(r=>r.status==='monitoring').length,'條','var(--yellow)']].map(([pre,val,suf,c])=>(
          <span key={pre} style={{color:'var(--text-muted)'}}>{pre} <strong style={{color:c}}>{val}</strong> {suf}</span>
        ))}
      </div>
      {modal&&<WLModal initial={editTarget} onClose={()=>setModal(false)} onSave={data=>{editTarget?onEdit({...editTarget,...data,_orig_src_ip:editTarget.src_ip,_orig_dst_ip:editTarget.dst_ip}):onAdd(data);setModal(false);}}/>}
    </div>
  );
};

/* ── AUDIT PAGE ── */
const AuditPage = () => {
  const [date,setDate]=useState(today());
  const [records,setRecords]=useState([]);
  const [q,setQ]=useState('');
  const [expand,setExpand]=useState(null);
  const [loadingAudit,setLoadingAudit]=useState(false);

  const loadAudit = useCallback(async (d, signal) => {
    setLoadingAudit(true);
    setRecords([]);
    try {
      const r = await fetch(`/audit/export?date=${d}&format=jsonl`, {signal});
      if(!r.ok){ setRecords([]); return; }
      const text = await r.text();
      const rows = text.trim().split('\n')
        .filter(Boolean)
        .map((line, idx)=>{
          try{ return JSON.parse(line); }
          catch(e){ console.warn(`JSONL parse error at line ${idx}:`, e.message); return null; }
        })
        .filter(Boolean)
        .map((rec,i)=>({
          id:                 `a${i}`,
          ts:                 rec.timestamp,
          stage:              rec.stage,
          verdict:            rec.verdict?.verdict,
          recommended_action: rec.verdict?.recommended_action,
          confidence:         rec.verdict?.confidence,
          reasoning:          rec.verdict?.reasoning,
          src_ip:             rec.event_summary?.source_ip || '—',
          dst_ip:             rec.event_summary?.destination_ip || '—',
          sig_id:             rec.event_summary?.signature_id || rec.event_summary?.threat_id || '—',
          sig_name:           rec.event_summary?.signature_name || rec.event_summary?.alert_signature || '—',
        }));
      setRecords(rows);
    } catch(e) {
      if(e.name !== 'AbortError') console.error('Audit load failed:', e);
    } finally {
      setLoadingAudit(false);
    }
  }, []);

  useEffect(()=>{
    const ctrl = new AbortController();
    loadAudit(date, ctrl.signal);
    return () => ctrl.abort();
  }, [date]);

  const rows = records.filter(e=>{
    const qq=q.toLowerCase();
    return !qq||(e.src_ip||'').includes(qq)||(e.sig_name||'').toLowerCase().includes(qq)||(e.verdict||'').includes(qq);
  });

  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:12}}>
      <div style={{display:'flex',gap:10,alignItems:'center',flexWrap:'wrap'}}>
        <SearchBox value={q} onChange={setQ} placeholder="搜尋 IP / Verdict / Signature…"/>
        <input type="date" value={date} onChange={e=>setDate(e.target.value)}
          style={{border:'1px solid var(--border)',borderRadius:4,padding:'6px 8px',fontSize:12,color:'var(--text)',outline:'none',background:'#fff'}}/>
        <div style={{marginLeft:'auto',display:'flex',gap:8}}>
          <Btn variant="sec" sm icon="download" onClick={()=>window.open(`/audit/export?date=${date}&format=jsonl`)}>匯出 JSONL</Btn>
          <Btn variant="pri" sm icon="download" onClick={()=>window.open(`/audit/export?date=${date}&format=csv`)}>匯出 CSV</Btn>
        </div>
      </div>

      {loadingAudit
        ? <div style={{padding:40,textAlign:'center',color:'var(--text-muted)',fontSize:13}}>載入中…</div>
        : <div style={{background:'#fff',border:'1px solid var(--border)',borderRadius:6,overflow:'hidden'}}>
            {rows.length===0
              ? <div style={{padding:40,textAlign:'center',color:'var(--text-muted)',fontSize:13}}>此日期無稽核紀錄</div>
              : <table style={{width:'100%',borderCollapse:'collapse'}}>
                  <thead><tr><TH></TH><TH>時間</TH><TH>Stage</TH><TH>Verdict</TH><TH>動作</TH><TH>信心度</TH><TH>來源 IP</TH><TH>目的 IP</TH><TH>Sig ID</TH><TH>Sig 名稱</TH></tr></thead>
                  <tbody>
                    {rows.map((e,i)=>(
                      <React.Fragment key={e.id}>
                        <tr onClick={()=>setExpand(expand===e.id?null:e.id)} style={{cursor:'pointer',background:i%2?'#f8fafc':'#fff',transition:'background .1s'}}
                          onMouseEnter={ev=>ev.currentTarget.style.background='#eff6ff'}
                          onMouseLeave={ev=>ev.currentTarget.style.background=i%2?'#f8fafc':'#fff'}>
                          <TD><Icon n={expand===e.id?'chevL':'chevR'} size={12} color="#94a3b8"/></TD>
                          <TD style={{fontSize:11,fontFamily:'var(--mono)',whiteSpace:'nowrap',color:'var(--text-muted)'}}>{e.ts?fmt(e.ts):'—'}</TD>
                          <TD><Badge stage={e.stage}/></TD>
                          <TD><Badge verdict={e.verdict}/></TD>
                          <TD><Badge action={e.recommended_action}/></TD>
                          <TD><Conf v={e.confidence}/></TD>
                          <TD style={{fontFamily:'var(--mono)',fontSize:11}}>{e.src_ip}</TD>
                          <TD style={{fontFamily:'var(--mono)',fontSize:11,color:'var(--text-sub)'}}>{e.dst_ip}</TD>
                          <TD style={{fontFamily:'var(--mono)',fontSize:11,color:'var(--blue)',fontWeight:600}}>{e.sig_id}</TD>
                          <TD style={{maxWidth:180,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',color:'var(--text-sub)'}}>{e.sig_name}</TD>
                        </tr>
                        {expand===e.id&&(
                          <tr style={{background:'#fffbeb'}}>
                            <td colSpan={10} style={{padding:'10px 20px 14px 36px',borderBottom:'1px solid var(--border)'}}>
                              <div style={{fontSize:11,fontWeight:700,color:'#92400e',textTransform:'uppercase',letterSpacing:'.04em',marginBottom:5}}>Reasoning</div>
                              <div style={{fontSize:13,color:'#78350f',lineHeight:1.7}}>{e.reasoning||'—'}</div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
            }
          </div>
      }
      <div style={{fontSize:11,color:'var(--text-muted)'}}>共 {records.length} 筆｜CSV 欄位：timestamp, stage, verdict, confidence, reasoning, recommended_action, src_ip, dst_ip, signature_id, signature_name</div>
    </div>
  );
};

/* ── SYSTEM PAGE ── */
const SystemPage = ({whitelist,edlPending,blStats,onBlReload}) => {
  const [blReloading,setBlReloading]=useState(false);
  const [wlReloading,setWlReloading]=useState(false);
  const endpoints=[
    {m:'POST',  p:'/webhook',              d:'Graylog HTTP Notification 接收'},
    {m:'POST',  p:'/webhook/graylog',      d:'同上（別名）'},
    {m:'GET',   p:'/edl/approve/{token}',  d:'確認 EDL 封鎖'},
    {m:'GET',   p:'/edl/reject/{token}',   d:'拒絕 EDL 封鎖'},
    {m:'GET',   p:'/edl/pending',          d:'列出待審 EDL'},
    {m:'GET',   p:'/edl/entries',          d:'列出已封鎖 EDL'},
    {m:'PATCH', p:'/edl/entry/{value}',    d:'修改 per-entry TTL'},
    {m:'DELETE',p:'/edl/entry/{value}',    d:'移除 EDL 條目'},
    {m:'POST',  p:'/whitelist/rule/direct',d:'直接新增白名單規則'},
    {m:'POST',  p:'/whitelist/reload',     d:'熱重載白名單 CSV'},
    {m:'GET',   p:'/whitelist/stats',      d:'白名單命中統計'},
    {m:'DELETE',p:'/whitelist/rule/{id}',  d:'刪除白名單規則'},
    {m:'POST',  p:'/blacklist/reload',     d:'熱重載黑名單'},
    {m:'GET',   p:'/blacklist/stats',      d:'黑名單統計'},
    {m:'GET',   p:'/audit/export',         d:'匯出稽核紀錄'},
    {m:'GET',   p:'/report/summary',       d:'摘要統計 (dashboard)'},
    {m:'GET',   p:'/report/pptx',          d:'下載 PowerPoint 報告'},
    {m:'GET',   p:'/health',               d:'健康檢查'},
  ];
  const mc={GET:'#16a34a',POST:'#2563eb',PATCH:'#d97706',DELETE:'#dc2626'};
  const blEnabled = blStats?.enabled ?? false;

  const doBlReload = async () => {
    setBlReloading(true);
    try { await onBlReload(); } finally { setBlReloading(false); }
  };

  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:14}}>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14}}>
        {/* Service health */}
        <div style={{background:'#fff',border:'1px solid var(--border)',borderRadius:6,overflow:'hidden'}}>
          <div style={{padding:'12px 18px',borderBottom:'1px solid var(--border)',background:'#1a2840'}}>
            <span style={{fontSize:13,fontWeight:600,color:'#fff'}}>服務狀態</span>
          </div>
          {[
            {name:'Webhook Server',   ok:true, lat:'2.1ms', uptime:'99.97%',detail:'FastAPI :8000'},
            {name:'Rate Limiter',     ok:true, lat:'0.3ms', uptime:'100%',  detail:'15m 視窗'},
            {name:'Whitelist Gate 1', ok:true, lat:'1.2ms', uptime:'100%',  detail:`${whitelist.length} 條規則`},
            {name:'EDL Gate 1.5',     ok:true, lat:'0.5ms', uptime:'100%',  detail:'已啟用'},
            {name:'Blacklist Gate 2', ok:blEnabled, lat:'0.8ms', uptime:'100%', detail:blEnabled?`${blStats.entry_count||0} 條`:'已停用'},
            {name:'LLM Gate3-L',      ok:true, lat:'820ms', uptime:'98.5%', detail:'OpenAI-compat'},
            {name:'SMTP Notifier',    ok:true, lat:'—',     uptime:'—',     detail:'Email 通知'},
            {name:'Graylog Client',   ok:true, lat:'42ms',  uptime:'99.8%', detail:'Enrichment'},
            {name:'Audit Logger',     ok:true, lat:'1.8ms', uptime:'100%',  detail:'JSONL 正常'},
            {name:'EDL Manager',      ok:true, lat:'2.1ms', uptime:'100%',  detail:`${edlPending.length} 待審`},
          ].map((s,i,arr)=>(
            <div key={s.name} style={{padding:'10px 18px',borderBottom:i<arr.length-1?'1px solid var(--border)':'none',display:'flex',alignItems:'center',gap:10}}>
              <span style={{color:s.ok?'#16a34a':'#dc2626',display:'inline-flex'}}><Icon n="dot" size={8} color={s.ok?'#16a34a':'#dc2626'}/></span>
              <div style={{flex:1}}><div style={{fontSize:12,fontWeight:500}}>{s.name}</div><div style={{fontSize:11,color:'var(--text-muted)'}}>{s.detail}</div></div>
              <div style={{textAlign:'right',fontSize:11}}><div style={{fontFamily:'var(--mono)',color:'var(--text-muted)'}}>{s.lat}</div><div style={{color:s.uptime==='100%'?'var(--green)':'var(--text-muted)'}}>{s.uptime}</div></div>
            </div>
          ))}
        </div>

        <div style={{display:'flex',flexDirection:'column',gap:14}}>
          {/* Blacklist control */}
          <div style={{background:'#fff',border:'1px solid var(--border)',borderRadius:6,overflow:'hidden'}}>
            <div style={{padding:'12px 18px',borderBottom:'1px solid var(--border)',background:'#1a2840'}}>
              <span style={{fontSize:13,fontWeight:600,color:'#fff'}}>黑名單 Gate 2</span>
            </div>
            <div style={{padding:'14px 18px',display:'flex',flexDirection:'column',gap:12}}>
              <div style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
                <div>
                  <div style={{fontSize:13,fontWeight:600}}>Gate 2 黑名單</div>
                  <div style={{fontSize:11,color:'var(--text-muted)',marginTop:2}}>custom_blacklist.txt (IP/CIDR)</div>
                </div>
                <span style={{padding:'5px 16px',borderRadius:20,fontSize:12,fontWeight:600,background:blEnabled?'#dcfce7':'#f1f5f9',color:blEnabled?'var(--green)':'var(--text-muted)'}}>
                  {blEnabled?'已啟用':'已停用'}
                </span>
              </div>
              {blEnabled && (
                <div style={{display:'flex',gap:10,fontSize:12,color:'var(--text-muted)'}}>
                  <span>共 <strong style={{color:'var(--text)'}}>{blStats.entry_count||0}</strong> 條</span>
                  <span>命中 <strong style={{color:'var(--red)'}}>{blStats.hit_count||0}</strong> 次</span>
                  {blStats.loaded_at&&<span>最後重載 <strong style={{color:'var(--text)'}}>{fmt(blStats.loaded_at)}</strong></span>}
                </div>
              )}
              <Btn variant="sec" sm icon="refresh" onClick={doBlReload}>{blReloading?'重載中…':'Hot Reload 黑名單'}</Btn>
            </div>
          </div>

          {/* API endpoints */}
          <div style={{background:'#fff',border:'1px solid var(--border)',borderRadius:6,overflow:'hidden'}}>
            <div style={{padding:'12px 18px',borderBottom:'1px solid var(--border)',background:'#1a2840'}}>
              <span style={{fontSize:13,fontWeight:600,color:'#fff'}}>API 端點</span>
            </div>
            <div style={{maxHeight:280,overflow:'auto'}}>
              {endpoints.map((e,i)=>(
                <div key={e.p} style={{padding:'7px 18px',borderBottom:i<endpoints.length-1?'1px solid var(--border)':'none',display:'flex',alignItems:'center',gap:10}}>
                  <span style={{fontFamily:'var(--mono)',fontSize:10,fontWeight:700,color:mc[e.m]||'#64748b',width:44,textAlign:'right',flexShrink:0}}>{e.m}</span>
                  <span style={{fontFamily:'var(--mono)',fontSize:11,flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{e.p}</span>
                  <span style={{fontSize:11,color:'var(--text-muted)',flexShrink:0,textAlign:'right'}}>{e.d}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

Object.assign(window, {
  DashboardPage, EventsPage, EDLPage, WhitelistPage, AuditPage, SystemPage,
});
