/* app.js — App component with real API wiring */

const App = () => {
  const [tweaks,setTweak] = useTweaks({darkSidebar:true,compactMode:false});
  const [page,setPage]     = useState('dashboard');

  /* ── API state ── */
  const [summary,setSummary]     = useState(null);
  const [edlPending,setEdlPending] = useState([]);
  const [edlActive,setEdlActive]   = useState([]);
  const [whitelist,setWhitelist]   = useState([]);
  const [blStats,setBlStats]       = useState({enabled:false});
  const [loading,setLoading]       = useState(true);
  const [updatedAt,setUpdatedAt]   = useState(null);

  /* ── Date range ── */
  const [dateFrom,setDateFrom] = useState(today());
  const [dateTo,setDateTo]     = useState(today());

  /* ── Fetch helper ── */
  const apiFetch = async (url, opts={}) => {
    const r = await fetch(url, opts);
    if (!r.ok) throw new Error(`${opts.method||'GET'} ${url} → ${r.status}`);
    return r;
  };

  /* ── Loaders ── */
  const loadSummary = useCallback(async (from,to) => {
    try {
      const r = await apiFetch(`/report/summary?start=${from}&end=${to}`);
      setSummary(await r.json());
      setUpdatedAt(new Date().toLocaleTimeString('zh-TW'));
    } catch(e) { console.error('loadSummary:', e); }
  }, []);

  const loadEDL = useCallback(async () => {
    try {
      const [pendRes,entRes] = await Promise.all([
        apiFetch('/edl/pending').then(r=>r.json()),
        apiFetch('/edl/entries').then(r=>r.json()),
      ]);
      setEdlPending(mapPending(pendRes.pending || []));
      setEdlActive(mapEntries(entRes.entries || []));
    } catch(e) { console.error('loadEDL:', e); }
  }, []);

  const loadWhitelist = useCallback(async () => {
    try {
      const d = await apiFetch('/whitelist/stats').then(r=>r.json());
      setWhitelist(mapWhitelist(d.rules || []));
    } catch(e) { console.error('loadWhitelist:', e); }
  }, []);

  const loadBlacklist = useCallback(async () => {
    try {
      const d = await apiFetch('/blacklist/stats').then(r=>r.json());
      setBlStats(d);
    } catch(e) { console.error('loadBlacklist:', e); }
  }, []);

  /* ── Initial load ── */
  useEffect(() => {
    Promise.all([
      loadSummary(dateFrom, dateTo),
      loadEDL(),
      loadWhitelist(),
      loadBlacklist(),
    ]).finally(() => setLoading(false));
  }, []);

  /* ── Period bar actions ── */
  const handleLoad = () => {
    setLoading(true);
    loadSummary(dateFrom, dateTo).finally(() => setLoading(false));
  };

  const handleExport = () => {
    window.open(`/report/pptx?start=${dateFrom}&end=${dateTo}`, '_blank');
  };

  /* ── EDL operations ── */
  const edlApprove = async (token) => {
    try { await apiFetch(`/edl/approve/${token}`); } catch(e) { console.error('edlApprove:', e); }
    await loadEDL();
  };
  const edlReject = async (token) => {
    try { await apiFetch(`/edl/reject/${token}`); } catch(e) { console.error('edlReject:', e); }
    await loadEDL();
  };
  const edlEditTTL = async (value, days) => {
    try {
      await apiFetch('/edl/entry', {
        method: 'PATCH',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({value, ttl_days: days}),
      });
    } catch(e) { console.error('edlEditTTL:', e); }
    await loadEDL();
  };

  /* ── Whitelist operations ── */
  const wlAdd = async (data) => {
    try {
      await apiFetch('/whitelist/rule/direct', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(data),
      });
    } catch(e) { console.error('wlAdd:', e); }
    await loadWhitelist();
  };
  const wlEdit = async (data) => {
    try {
      if (data.id) {
        const p = new URLSearchParams({src_ip: data._orig_src_ip ?? '', dst_ip: data._orig_dst_ip ?? ''});
        await fetch(`/whitelist/rule/${data.id}?${p}`, {method:'DELETE'});
      }
      await apiFetch('/whitelist/rule/direct', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(data),
      });
    } catch(e) { console.error('wlEdit:', e); }
    await loadWhitelist();
  };
  const wlDel = async (id, src_ip='', dst_ip='') => {
    try {
      const p = new URLSearchParams({src_ip, dst_ip});
      await apiFetch(`/whitelist/rule/${id}?${p}`, {method:'DELETE'});
    } catch(e) { console.error('wlDel:', e); }
    await loadWhitelist();
  };
  const wlReload = async () => {
    try { await apiFetch('/whitelist/reload', {method:'POST'}); } catch(e) { console.error('wlReload:', e); }
    await loadWhitelist();
  };

  /* ── Cross-page event actions ── */
  const addEDLFromEvent = async (e) => {
    try {
      await apiFetch('/edl/entry', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({value: e.src_ip, note: `${e.sig_name} (${e.sig_id})`}),
      });
    } catch(e2) { console.error('addEDLFromEvent:', e2); }
    await loadEDL();
    setPage('edl');
  };
  const addWLFromEvent = async (e) => {
    const src = (e.src_ip && e.src_ip !== '—') ? e.src_ip : '';
    await wlAdd({sig_id:e.sig_id,sig_name:e.sig_name,action:'',src_ip:src,dst_ip:'',note:`從事件 ${e.id} 標記`,status:'monitoring',ttl_days:90});
    setPage('whitelist');
  };

  /* ── Computed values ── */
  const stats      = computeStats(summary, edlPending, edlActive);
  const actionDist = computeActionDist(summary);
  const dailyData  = computeDailyData(summary);
  const topSigs    = computeTopSigs(summary);
  const events     = summary ? mapEvents(summary) : [];

  /* ── Sidebar theme ── */
  const sbBg          = tweaks.darkSidebar ? '#1e2d4a' : '#fff';
  const sbText        = tweaks.darkSidebar ? '#a8bcd6' : '#4a5568';
  const sbActiveText  = tweaks.darkSidebar ? '#fff'    : '#1a2840';
  const sbActiveBg    = tweaks.darkSidebar ? '#2d4270' : '#eff6ff';
  const sbHoverBg     = tweaks.darkSidebar ? '#253558' : '#f8fafc';
  const sbGroupColor  = tweaks.darkSidebar ? '#5a7496' : '#94a3b8';
  const sbBorder      = tweaks.darkSidebar ? '#2a3f60' : '#e2e8f0';

  return (
    <div style={{display:'flex',height:'100vh',width:'100vw',overflow:'hidden',background:'var(--bg)'}}>

      {/* ── Sidebar ── */}
      <aside style={{width:200,flexShrink:0,background:sbBg,borderRight:`1px solid ${sbBorder}`,display:'flex',flexDirection:'column'}}>
        <div style={{height:'var(--header-h)',display:'flex',alignItems:'center',gap:10,padding:'0 16px',borderBottom:`1px solid ${sbBorder}`,flexShrink:0,background:tweaks.darkSidebar?'#1a2840':'#fff'}}>
          <div style={{width:24,height:24,borderRadius:5,background:'#2563eb',display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0}}>
            <Icon n="edl" size={13} color="#fff"/>
          </div>
          <div>
            <div style={{fontSize:13,fontWeight:700,color:sbActiveText,letterSpacing:'-.01em',whiteSpace:'nowrap'}}>Graylog Threat</div>
            <div style={{fontSize:10,color:sbGroupColor,whiteSpace:'nowrap'}}>Analyzer</div>
          </div>
        </div>
        <div style={{fontSize:10,fontWeight:700,color:'#fff',background:'#2563eb',padding:'3px 16px',letterSpacing:'.04em'}}>Security Operations Center</div>
        <nav style={{flex:1,padding:'8px 0',overflowY:'auto'}}>
          {NAV_GROUPS.map(group=>(
            <div key={group.group}>
              <div style={{padding:'10px 16px 4px',fontSize:10,fontWeight:700,color:sbGroupColor,letterSpacing:'.08em'}}>{group.group}</div>
              {group.items.map(item=>{
                const active=page===item.id;
                const badge=item.id==='edl'&&edlPending.length>0?edlPending.length:null;
                return (
                  <button key={item.id} onClick={()=>setPage(item.id)}
                    style={{display:'flex',alignItems:'center',gap:9,width:'100%',padding:'8px 16px',border:'none',cursor:'pointer',textAlign:'left',transition:'all .12s',background:active?sbActiveBg:'transparent',color:active?sbActiveText:sbText,fontSize:13,fontWeight:active?600:400,fontFamily:'var(--font)',borderLeft:`3px solid ${active?'#2563eb':'transparent'}`}}
                    onMouseEnter={ev=>{if(!active)ev.currentTarget.style.background=sbHoverBg;}}
                    onMouseLeave={ev=>{if(!active)ev.currentTarget.style.background='transparent';}}>
                    <Icon n={item.icon} size={14} color={active?'#2563eb':sbText}/>
                    <span style={{flex:1}}>{item.label}</span>
                    {badge&&<span style={{background:'#dc2626',color:'#fff',borderRadius:8,padding:'0 5px',fontSize:10,fontWeight:700}}>{badge}</span>}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
      </aside>

      {/* ── Main ── */}
      <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden'}}>
        {/* Header */}
        <header style={{height:'var(--header-h)',flexShrink:0,background:'var(--header-bg)',display:'flex',alignItems:'center',padding:'0 20px',gap:12}}>
          <span style={{fontSize:15,fontWeight:700,color:'#fff'}}>{NAV_GROUPS.flatMap(g=>g.items).find(i=>i.id===page)?.label}</span>
          <div style={{marginLeft:'auto',display:'flex',alignItems:'center',gap:10}}>
            <div style={{display:'flex',alignItems:'center',gap:5,fontSize:11,color:'#a8bcd6'}}>
              <div style={{width:6,height:6,borderRadius:'50%',background:'#22c55e',boxShadow:'0 0 6px #22c55e'}}/>
              服務運行中
            </div>
            {edlPending.length>0&&(
              <button onClick={()=>setPage('edl')} style={{display:'flex',alignItems:'center',gap:5,padding:'3px 10px',background:'rgba(245,158,11,.2)',border:'1px solid rgba(245,158,11,.4)',borderRadius:12,fontSize:11,cursor:'pointer',color:'#fcd34d',fontFamily:'var(--font)'}}>
                <Icon n="alert" size={11} color="#fcd34d"/>
                {edlPending.length} 件待審 EDL
              </button>
            )}
          </div>
        </header>

        {/* Period bar (dashboard only) */}
        {page==='dashboard'&&(
          <PeriodBar
            onLoad={handleLoad}
            updatedAt={updatedAt}
            onExport={handleExport}
            dateFrom={dateFrom}
            dateTo={dateTo}
            setDateFrom={setDateFrom}
            setDateTo={setDateTo}
          />
        )}

        {/* Warning banner (dashboard only) */}
        {page==='dashboard'&&(
          <WarningBanner count={stats.pending_review} onViewEDL={()=>setPage('edl')} onViewWhitelist={()=>setPage('whitelist')}/>
        )}

        {/* Content */}
        <main style={{flex:1,overflow:'auto'}}>
          {page==='dashboard'  && <DashboardPage stats={stats} setPage={setPage} edlPending={edlPending} whitelist={whitelist} actionDist={actionDist} dailyData={dailyData} topSigs={topSigs} loading={loading}/>}
          {page==='events'     && <EventsPage events={events} onAddWhitelist={addWLFromEvent} onAddEDL={addEDLFromEvent}/>}
          {page==='edl'        && <EDLPage pending={edlPending} active={edlActive} onApprove={edlApprove} onReject={edlReject} onEditTTL={edlEditTTL}/>}
          {page==='whitelist'  && <WhitelistPage rules={whitelist} onAdd={wlAdd} onEdit={wlEdit} onDelete={wlDel} onReload={wlReload}/>}
          {page==='audit'      && <AuditPage/>}
          {page==='system'     && <SystemPage whitelist={whitelist} edlPending={edlPending} blStats={blStats} onBlReload={loadBlacklist}/>}
        </main>
      </div>

      {/* Tweaks panel */}
      <TweaksPanel>
        <TweakSection label="側邊欄">
          <TweakToggle label="深色側邊欄" value={tweaks.darkSidebar} onChange={v=>setTweak('darkSidebar',v)}/>
        </TweakSection>
        <TweakSection label="顯示">
          <TweakToggle label="緊湊模式" value={tweaks.compactMode} onChange={v=>setTweak('compactMode',v)}/>
        </TweakSection>
      </TweaksPanel>
    </div>
  );
};

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
