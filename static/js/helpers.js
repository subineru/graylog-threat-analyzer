/* helpers.js — constants, formatters, data adapters */

const {useState,useEffect,useRef,useMemo,useCallback} = React;

/* ── TIME & ID ── */
const today = () => new Date().toISOString().slice(0,10);
const daysAgo = n => { const d=new Date(); d.setDate(d.getDate()-n); return d.toISOString().slice(0,10); };
const fmt = ts => new Date(ts).toLocaleString('zh-TW',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
let _id=0; const uid = () => 'u'+(++_id);

/* ── LOOKUP MAPS ── */
const VM = {
  anomalous:     {label:'異常',   bg:'#fee2e2',color:'#dc2626'},
  false_positive:{label:'誤判',   bg:'#dcfce7',color:'#16a34a'},
  normal:        {label:'正常',   bg:'#dbeafe',color:'#2563eb'},
  duplicate:     {label:'重複',   bg:'#f1f5f9',color:'#64748b'},
};
const AM = {
  block:      {label:'封鎖',color:'#dc2626'},
  monitor:    {label:'監控',color:'#d97706'},
  investigate:{label:'調查',color:'#7c3aed'},
  suppress:   {label:'靜默',color:'#64748b'},
};
const SM = {
  rate_limit: {label:'Rate Limit',color:'#64748b'},
  whitelist:  {label:'Whitelist', color:'#2563eb'},
  edl_active: {label:'EDL Active',color:'#2563eb'},
  blacklist:  {label:'Blacklist', color:'#dc2626'},
  gate3_rule: {label:'Gate3 Rule',color:'#d97706'},
  gate3_llm:  {label:'Gate3 LLM', color:'#7c3aed'},
};
const PIPELINE = [
  {id:'rate_limit',label:'Rate Limit',sub:'15m 去重',  color:'#64748b'},
  {id:'whitelist', label:'Gate 1',    sub:'白名單',     color:'#2563eb'},
  {id:'edl_active',label:'Gate 1.5', sub:'EDL IP',     color:'#0891b2'},
  {id:'blacklist', label:'Gate 2',   sub:'黑名單',      color:'#dc2626'},
  {id:'gate3_rule',label:'Gate 3R',  sub:'固定規則',    color:'#d97706'},
  {id:'gate3_llm', label:'Gate 3L',  sub:'LLM',        color:'#7c3aed'},
];
const NAV_GROUPS = [
  {group:'ANALYZE', items:[{id:'dashboard',label:'Dashboard',icon:'dashboard'},{id:'events',label:'Events',icon:'events'}]},
  {group:'MANAGE',  items:[{id:'edl',label:'EDL',icon:'edl'},{id:'whitelist',label:'Whitelist',icon:'whitelist'}]},
  {group:'SYSTEM',  items:[{id:'audit',label:'Audit Log',icon:'audit'},{id:'system',label:'System',icon:'system'}]},
];

/* ── TYPE DETECTION ── */
const detectType = v => {
  if (!v) return 'ip';
  if (/^[\d.]+\/\d+$/.test(v)) return 'ip';               // IPv4 CIDR
  if (/^[\d.]+$/.test(v)) return 'ip';                    // IPv4
  if (/^[\da-f:]+\/\d+$/i.test(v)) return 'ip';           // IPv6 CIDR
  if (/^([\da-f]{0,4}:){2,7}[\da-f]{0,4}$/i.test(v)) return 'ip'; // IPv6
  if (/^https?:\/\//.test(v)) return 'url';
  return 'domain';
};

/* ── DATA ADAPTERS ── */
const mapPending = (list=[]) => list.map(e => ({
  id:         e.token,
  token:      e.token,
  type:       detectType(e.value),
  value:      e.value,
  reason:     e.source_signature || '—',
  confidence: 0.9,
  created:    e.suggested_at,
}));

const mapEntries = (list=[]) => list.map(e => ({
  id:          e.value,
  type:        e.entry_type || detectType(e.value),
  value:       e.value,
  approved_at: e.added_at,
  ttl_days:    e.ttl_days,
  expires:     e.ttl_days===-1 ? '永不過期' : (e.expires_at?.slice(0,10) || '—'),
}));

const mapWhitelist = (list=[]) => list.map(r => ({
  id:        r.signature_id,
  sig_id:    r.signature_id,
  sig_name:  r.signature_name,
  action:     r.action         || '',
  src_ip:     r.source_ip      || '',
  dst_ip:     r.destination_ip || '',
  note:       r.note           || '',
  status:     r.status         || 'monitoring',
  ttl_days:   r.ttl_days != null ? r.ttl_days : -1,
  hit_count:  r.hit_count || 0,
  last_hit:   r.last_hit_time || null,
  expires_at: (() => {
    if (r.status === 'confirmed' || r.ttl_days === -1) return null;
    if (!r.last_hit_time) return null;
    const d = new Date(r.last_hit_time);
    d.setDate(d.getDate() + (r.ttl_days ?? 90));
    return d.toISOString().slice(0, 10);
  })(),
}));

const mapEvents = (summary) => {
  const all = [...(summary?.block_events||[]), ...(summary?.pending_events||[])];
  return all.map((e, i) => ({
    id:                 `e${i}`,
    ts:                 e.timestamp,
    src_ip:             e.src_ip || '—',
    dst_ip:             e.dst_ip || '—',
    sig_id:             e.signature_id || '—',
    sig_name:           e.signature || '—',
    action:             e.action || 'suppress',
    verdict:            e.action==='block' ? 'anomalous' : e.action==='suppress' ? 'false_positive' : 'normal',
    recommended_action: e.action || 'suppress',
    stage:              'gate3_rule',
    confidence:         0.85,
    reasoning:          e.reasoning || '—',
    src_zone:null, dst_zone:null, rule_name:null, transport:null, direction:null,
    src_hostname:null, src_dept:null,
  }));
};

/* ── COMPUTED STATS ── */
const computeStats = (summary, edlPending) => ({
  total_events:     summary?.total_events || 0,
  blocked:          summary?.action_counts?.block || 0,
  suppression_rate: summary?.suppression_rate || 0,
  pending_review:   (summary?.action_counts?.monitor||0) + (summary?.action_counts?.investigate||0),
  pending_edl:      edlPending.length,
});

const computeActionDist = (summary) => {
  const ac    = summary?.action_counts || {};
  const total = summary?.total_events  || 1;
  const safeTotal = total > 0 ? total : 1;
  return [
    {action:'Block',      key:'block',       color:'var(--c-block)'},
    {action:'Investigate',key:'investigate', color:'var(--c-investigate)'},
    {action:'Monitor',    key:'monitor',     color:'var(--c-monitor)'},
    {action:'Suppress',   key:'suppress',    color:'var(--c-suppress)'},
  ].map(({action,key,color}) => {
    const count = ac[key] || 0;
    return {action, count, pct: (count/safeTotal*100).toFixed(1), color};
  });
};

const computeDailyData = (summary) =>
  Object.entries(summary?.daily_counts||{}).sort().map(([date,count])=>({date,count}));

const computeTopSigs = (summary) => {
  const total = summary?.total_events || 1;
  return (summary?.top_signatures||[]).map(([sig,count],i)=>({
    rank: i+1, sig, count, pct: (count/total*100).toFixed(1),
  }));
};

Object.assign(window, {
  today, daysAgo, fmt, uid,
  VM, AM, SM, PIPELINE, NAV_GROUPS,
  detectType, mapPending, mapEntries, mapWhitelist, mapEvents,
  computeStats, computeActionDist, computeDailyData, computeTopSigs,
});
