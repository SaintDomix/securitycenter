"""CyberGuard investigation workflow. The platform does not train at investigation time."""
from __future__ import annotations
import json,sqlite3,uuid,time
from contextlib import closing
from datetime import datetime,timezone
from pathlib import Path
import numpy as np,pandas as pd,joblib
META={'label','attack_cat','Label','id','Flow ID','Source IP','Destination IP','Timestamp','Src IP','Dst IP','srcip','dstip','stime','ltime','source_ip','destination_ip','timestamp','timestamp_iso','_row_id','_predicted_attack','_risk_probability'}
IP_SRC=['Source IP','Src IP','srcip','source_ip'];IP_DST=['Destination IP','Dst IP','dstip','destination_ip'];TIME=['Timestamp','timestamp','timestamp_iso','stime'];PORT=['Destination Port','dst_port','dsport','destination_port','dport']
def now():return datetime.now(timezone.utc).isoformat()
def pick(df,names):return next((c for c in names if c in df.columns),None)
def serial(x):return json.loads(json.dumps(x,default=lambda z:z.item() if hasattr(z,'item') else str(z)))
class AuditStore:
 def __init__(self,path):
  self.path=str(path);Path(path).parent.mkdir(parents=True,exist_ok=True)
  with closing(sqlite3.connect(self.path)) as c:
   c.execute('CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,run_id TEXT,ts TEXT,agent TEXT,kind TEXT,payload TEXT)');c.execute('CREATE TABLE IF NOT EXISTS reports(run_id TEXT PRIMARY KEY,created TEXT,payload TEXT)');c.commit()
 def add(self,run,agent,kind,payload):
  with closing(sqlite3.connect(self.path)) as c:c.execute('INSERT INTO events(run_id,ts,agent,kind,payload) VALUES(?,?,?,?,?)',(run,now(),agent,kind,json.dumps(serial(payload))));c.commit()
 def events(self,run):
  with closing(sqlite3.connect(self.path)) as c:rows=c.execute('SELECT ts,agent,kind,payload FROM events WHERE run_id=? ORDER BY id',(run,)).fetchall()
  return [dict(timestamp=a,agent=b,kind=k,payload=json.loads(p)) for a,b,k,p in rows]
 def save(self,run,report):
  with closing(sqlite3.connect(self.path)) as c:c.execute('INSERT OR REPLACE INTO reports VALUES(?,?,?)',(run,now(),json.dumps(serial(report))));c.commit()
class Agent:
 name='agent'
 def __init__(self,ctx):self.ctx=ctx
 def tool(self,label,fn,*a,**kw):
  self.ctx['store'].add(self.ctx['run'],self.name,'tool_call',{'tool':label});return fn(*a,**kw)
 def send(self,recipient,payload):
  env=dict(message_id=str(uuid.uuid4()),run_id=self.ctx['run'],sender=self.name,receiver=recipient,timestamp=now(),payload=serial(payload))
  self.ctx['store'].add(self.ctx['run'],self.name,'message',env);return env
class TelemetryAgent(Agent):
 name='telemetry'
 def run(self,source,limit):
  df=self.tool('read_csv',pd.read_csv,source,nrows=limit,low_memory=False);df.columns=[str(c).strip() for c in df.columns]
  if df.empty or df.columns.duplicated().any():raise ValueError('Empty or duplicate-column CSV')
  df=df.copy();df['_row_id']=np.arange(len(df))
  self.tool('validate_columns',lambda:len(df.columns));self.send('threat_detection',{'rows':len(df),'columns':list(df.columns)})
  return df
class ThreatDetectionAgent(Agent):
 name='threat_detection'
 def run(self,df,bundle):
  fields=bundle['features'];missing=[c for c in fields if c not in df]
  if missing:raise ValueError('Missing required model features: '+', '.join(missing[:15]))
  x=df[fields].apply(pd.to_numeric,errors='coerce').replace([np.inf,-np.inf],np.nan)
  pipe=bundle['model'];pred=self.tool('predict_class',pipe.predict,x)
  rawprob=self.tool('predict_class_probabilities',pipe.predict_proba,x)
  classes=list(map(str,pipe.classes_));normal={'0','Normal','BENIGN','Benign','benign'}
  threat_indices=[i for i,c in enumerate(classes) if c not in normal]
  if not threat_indices:raise ValueError('Model has no threat class')
  # Correct for multiclass: probability of ANY attack, not probability of selected attack only.
  scores=np.asarray(rawprob)[:,threat_indices].sum(axis=1)
  df=df.copy();df['_predicted_class']=list(map(str,pred));df['_risk_probability']=scores;df['_predicted_attack']=[int(str(v) not in normal) for v in pred]
  self.send('correlation',{'suspected':int(df['_predicted_attack'].sum()),'class_counts':df['_predicted_class'].value_counts().to_dict()})
  return df
class CorrelationAgent(Agent):
 name='correlation'
 def run(self,df,bundle):
  src=pick(df,IP_SRC);dst=pick(df,IP_DST);tm=pick(df,TIME);port=pick(df,PORT)
  suspicious=df[df['_predicted_attack']==1].copy();suspicious['_dt']=pd.NaT
  if tm:
   if pd.api.types.is_numeric_dtype(suspicious[tm]):suspicious['_dt']=pd.to_datetime(suspicious[tm],unit='s',utc=True,errors='coerce')
   else:suspicious['_dt']=pd.to_datetime(suspicious[tm],utc=True,errors='coerce')
  if src and suspicious[src].notna().any():suspicious['_group']=suspicious[src].fillna('unknown').astype(str);method='source_ip'
  elif dst and suspicious[dst].notna().any():suspicious['_group']=suspicious[dst].fillna('unknown').astype(str);method='destination_ip'
  else:suspicious['_group']=['flow-'+str(i) for i in suspicious['_row_id']];method='single_flow'
  incidents=[]
  for entity,subset in suspicious.groupby('_group',sort=False):
   if method!='single_flow' and subset['_dt'].notna().all():
    subset=subset.sort_values('_dt');chunks=[v for _,v in subset.groupby((subset['_dt'].diff().dt.total_seconds().fillna(0)>300).cumsum())]
   else:chunks=[subset]
   for part in chunks:
    ids=part['_row_id'].astype(int).tolist();types=part['_predicted_class'].value_counts().to_dict()
    incidents.append({'incident_id':'INC-'+str(len(incidents)+1).zfill(4),'entity':str(entity),'grouping_method':method,'flow_ids':ids[:150],'count':len(part),'truncated_evidence_ids':len(ids)>150,'attack_types':types,'max_score':round(float(part['_risk_probability'].max()),4),'mean_score':round(float(part['_risk_probability'].mean()),4),'first_seen':part['_dt'].min().isoformat() if part['_dt'].notna().any() else None,'last_seen':part['_dt'].max().isoformat() if part['_dt'].notna().any() else None})
  all_count=len(incidents);incidents.sort(key=lambda r:(-r['max_score'],-r['count']));incidents=incidents[:100]
  self.tool('cluster_events',lambda:all_count);self.send('incident_assessment',{'shown':len(incidents),'total':all_count,'method':method})
  return incidents,{'grouping_method':method,'timestamp_available':bool(tm),'source_ip_available':bool(src),'total_candidates':all_count,'displayed_candidates':len(incidents),'truncated':all_count>100,'note':'Events with no IP/timestamp cannot be claimed as a reconstructed attack sequence.'}
def evidence_details(inc,df,bundle):
 subset=df[df['_row_id'].isin(inc['flow_ids'])];imp=bundle.get('feature_importance') or {}
 explanations=[]
 for feat,importance in list(imp.items())[:5]:
  if feat in subset:
   values=pd.to_numeric(subset[feat],errors='coerce').dropna()
   if len(values):explanations.append({'feature':feat,'observed_median':round(float(values.median()),4),'global_importance':round(float(importance),4)})
 useful=[]
 for col in ['proto','service','state','dur','spkts','dpkts','sbytes','dbytes','rate','sload','dload','Destination Port','Flow Duration','Total Fwd Packets','Total Backward Packets']:
  if col in subset:
   values=subset[col].dropna();
   if len(values):useful.append({'name':col,'observed':str(values.iloc[0])[:60]})
 return explanations,useful[:12]
class IncidentAssessmentAgent(Agent):
 name='incident_assessment'
 def run(self,incidents,df,bundle):
  for inc in incidents:
   score=inc['max_score'];n=inc['count'];inc['priority']='HIGH' if n>=3 and score>=.9 else ('MEDIUM' if score>=.65 else 'LOW')
   explanations,features=evidence_details(inc,df,bundle);inc['feature_context']=features;inc['model_feature_summary']=explanations
   inc['summary']=f"Model flagged {n} network flow(s). Predicted categories: {', '.join(inc['attack_types'])}."
   inc['recommended_actions']=['Review flow attributes and supporting firewall/host logs','Validate whether the observed pattern matches authorized activity','Escalate confirmed security events to a human analyst']
  self.tool('enrich_incidents',lambda:len(incidents));self.send('verification',{'assessed':len(incidents)})
  return incidents
class VerificationAgent(Agent):
 name='verification'
 def run(self,incidents,df,meta):
  existing=set(df['_row_id'].astype(int));tests=[]
  for inc in incidents:
   selected=df[df['_row_id'].isin(inc['flow_ids'])]
   rowok=len(selected)==len(inc['flow_ids']) and len(inc['flow_ids'])==len(set(inc['flow_ids']))
   expected=selected['_predicted_class'].astype(str).value_counts().to_dict();typeok=(all(k in expected for k in inc['attack_types']) and (expected==inc['attack_types'] if not inc['truncated_evidence_ids'] else all(expected.get(k,0)<=v for k,v in inc['attack_types'].items())))
   countok=inc['count']>=len(inc['flow_ids']) and (inc['truncated_evidence_ids']==(inc['count']>150))
   scoreok=bool(len(selected)) and (inc['truncated_evidence_ids'] or abs(inc['max_score']-float(selected['_risk_probability'].max()))<0.00011)
   causality=inc['grouping_method']=='single_flow' and inc['count']!=1
   contextok=all(any(c['name']==col and str(c['observed'])==str(selected[col].dropna().iloc[0])[:60] for c in inc['feature_context']) for col in [c['name'] for c in inc['feature_context']] if col in selected and selected[col].notna().any());tests.append({'incident_id':inc['incident_id'],'observed_context_matches':contextok,'valid_row_ids':rowok,'attack_classes_supported':typeok,'count_consistent':countok,'score_recomputed':scoreok,'no_false_correlation':not causality})
  self.tool('verify_evidence',lambda:len(tests));self.send('orchestrator',{'passed':all(all(v for k,v in x.items() if k!='incident_id') for x in tests)})
  return {'passed':all(all(v for k,v in x.items() if k!='incident_id') for x in tests),'checked':len(tests),'checks':tests,'notes':['Model labels represent predictions, not confirmed incidents.','Feature importances are global model properties, not per-event causal explanations.','Incident priorities indicate review order, not impact estimates.']}
def investigate(source,bundle_path='models/unsw_model.joblib',db_path='runs/cyberguard.sqlite',max_rows=15000):
 if max_rows<1 or max_rows>100000:raise ValueError('max_rows must be between 1 and 100000')
 bundle=joblib.load(bundle_path) # Only load artifacts from trusted sources.
 if not {'model','features'}.issubset(bundle):raise ValueError('Invalid model bundle')
 ctx={'store':AuditStore(db_path),'run':'run-'+uuid.uuid4().hex[:10]};start=time.perf_counter();ctx['store'].add(ctx['run'],'orchestrator','start',{'bundle':str(bundle_path)})
 try:
  df=TelemetryAgent(ctx).run(source,max_rows)
  # Reject use of synthetic-trained model on a real UNSW input, rather than make unsupported claims.
  provenance=bundle.get('training_provenance','UNKNOWN')
  name=getattr(source,'name',str(source))
  if 'SYNTHETIC' in provenance.upper() and ('unsw' in Path(name).name.lower() or 'cic' in Path(name).name.lower() or 'attack_cat' in df.columns):raise ValueError('Demo model cannot be used on real benchmark datasets. Train a benchmark model first.')
  scored=ThreatDetectionAgent(ctx).run(df,bundle)
  inc,meta=CorrelationAgent(ctx).run(scored,bundle)
  inc=IncidentAssessmentAgent(ctx).run(inc,scored,bundle)
  verification=VerificationAgent(ctx).run(inc,scored,meta)
  events=ctx['store'].events(ctx['run']);names=['telemetry','threat_detection','correlation','incident_assessment','verification'];counts={a:sum(e['agent']==a and e['kind']=='tool_call' for e in events) for a in names};total=sum(counts.values())
  risk=scored['_risk_probability'];scores={'benign':int((scored['_predicted_attack']==0).sum()),'suspected':int((scored['_predicted_attack']==1).sum())}
  topcols=['_row_id','_predicted_class','_risk_probability']+[c for c in [pick(scored,IP_SRC),pick(scored,IP_DST),pick(scored,TIME),'proto','service','dur','sbytes','dbytes'] if c and c in scored]
  results={'run_id':ctx['run'],'time_utc':now(),'rows':len(scored),'suspicious_flows':scores['suspected'],'class_distribution':scored['_predicted_class'].value_counts().to_dict(),'incidents':inc,'correlation':meta,'verification':verification,'model_metadata':{k:bundle.get(k) for k in ['model_name','mode','dataset','training_provenance','heldout_metrics','feature_importance','training_filename','testing_filename','class_balance','evaluation_protocol']},'agent_calls':counts,'max_agent_share':max(counts.values())/total if total else 0,'under_40_percent':bool(total and max(counts.values())/total<=.4),'seconds':round(time.perf_counter()-start,2),'events':events,'top_flows':scored.sort_values('_risk_probability',ascending=False).head(100)[topcols].replace({np.nan:None}).to_dict('records'),'risk_histogram':np.histogram(risk,bins=np.linspace(0,1,11))[0].tolist()}
  ctx['store'].save(ctx['run'],results);ctx['store'].add(ctx['run'],'orchestrator','completed',{'verified':verification['passed']});return serial(results)
 except Exception as e:
  ctx['store'].add(ctx['run'],'orchestrator','failed',{'error':str(e),'type':type(e).__name__});raise
