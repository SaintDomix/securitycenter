import json,html
from pathlib import Path
import pandas as pd
import streamlit as st
from soc.core import investigate
st.set_page_config(page_title='Security Operations',page_icon='🛡️',layout='wide',initial_sidebar_state='expanded')
st.markdown('''<style>.block-container{padding-top:1.6rem;max-width:1500px}div[data-testid="stMetric"]{background:#192433;border:1px solid #28354a;border-radius:12px;padding:14px}div[data-testid="stSidebar"]{background:#111b29}h1{letter-spacing:-.035em}.stTabs [data-baseweb="tab"]{font-weight:600}</style>''',unsafe_allow_html=True)
st.title('Security Center')
st.caption('Network threat monitoring and investigation')
models=sorted(Path('models').glob('*.joblib'))
with st.sidebar:
 st.subheader('Analyze network traffic')
 uploaded=st.file_uploader('Network events (CSV)',type=['csv'],help='Upload network-flow features compatible with the selected model.')
 choices={p.name:str(p) for p in models}
 if choices:
  selected=st.selectbox('Detection model',list(choices),index=next((i for i,k in enumerate(choices) if 'unsw_binary' in k),0),help='Choose a model trained for this dataset. Synthetic and UNSW models are not interchangeable.')
  bundle=choices[selected]
 else:
  st.warning('No trained model found in models/.')
  bundle=None
 rows=st.slider('Events to analyze',100,50000,5000,100)
 go=st.button('Analyze events',type='primary',use_container_width=True,disabled=not bool(bundle))
 st.divider()
 with st.expander('Training & dataset setup'):
  st.write('Train a detector using labeled records, then analyze new network-flow exports with the saved model.')
  st.code('python tools/train_model.py --train data/UNSW_NB15_training-set.csv --test data/UNSW_NB15_testing-set.csv --out models/unsw_model.joblib --mode binary',language='powershell')
  st.link_button('UNSW-NB15 source','https://research.unsw.edu.au/projects/unsw-nb15-dataset')
if go:
 if uploaded is None:st.warning('Upload a CSV to start an investigation.')
 else:
  try:
   with st.spinner('Analyzing network activity and correlating events…'):
    st.session_state['investigation']=investigate(uploaded,bundle,max_rows=rows)
  except Exception as ex:st.error(f'Investigation could not start: {ex}')
r=st.session_state.get('investigation')
if r is None:
 st.subheader('Network investigation')
 st.write('Upload an exported network-flow CSV to review flagged activity and available incident context.')
 st.info('Choose a compatible detection model, upload events, and select Analyze events.')
 st.stop()
a,b,c,d=st.columns(4)
a.metric('Analyzed flows',f"{r['rows']:,}")
b.metric('Flagged for review',f"{r['suspicious_flows']:,}")
c.metric('Incident candidates',f"{r['correlation']['total_candidates']:,}")
d.metric('Evidence checks','Passed' if r['verification']['passed'] else 'Needs review')
st.caption(f"Analysis {r['run_id']} · {r['seconds']} seconds · Model: {r['model_metadata'].get('model_name','—')} · Source: {r['model_metadata'].get('dataset','—')}")
tabs=st.tabs(['Overview','Incidents','Network activity','Agent workflow','Model performance','Reports'])
with tabs[0]:
 left,right=st.columns([1,1])
 with left:
  st.subheader('Predicted traffic classes')
  classes=pd.Series(r['class_distribution']).sort_values(ascending=False)
  st.bar_chart(classes)
 with right:
  st.subheader('Detection score distribution')
  bins=pd.DataFrame({'Score range':[f'{i/10:.1f}–{(i+1)/10:.1f}' for i in range(10)],'Flows':r['risk_histogram']})
  st.bar_chart(bins.set_index('Score range'))
 st.subheader('Investigation summary')
 if r['correlation']['grouping_method']=='single_flow':st.info('Source IP and timestamps are unavailable: findings are individual network flows, not correlated attack sequences.')
 else:st.success('Event grouping available by '+r['correlation']['grouping_method'].replace('_',' ')+'. Related flows are investigation candidates, not confirmed attacks.')
 if r['correlation']['truncated']:st.warning(f"Displaying the top {r['correlation']['displayed_candidates']} of {r['correlation']['total_candidates']} candidates. Full event-level output is not shown in the incident queue.")
 st.write('Priorities indicate which records to review first. A positive model prediction does not prove compromise.')
with tabs[1]:
 st.subheader('Incident queue')
 if r['incidents']:
  frame=pd.DataFrame([{'ID':v['incident_id'],'Entity':v['entity'],'Priority':v['priority'],'Flows':v['count'],'Predicted types':', '.join(v['attack_types']),'Detection score':v['max_score'],'First seen':v['first_seen']} for v in r['incidents']])
  st.dataframe(frame,hide_index=True,use_container_width=True)
  index=st.selectbox('Incident details',list(range(len(r['incidents']))),format_func=lambda i:f"{r['incidents'][i]['incident_id']} · {r['incidents'][i]['entity']} · {', '.join(r['incidents'][i]['attack_types'])}")
  x=r['incidents'][index]
  st.subheader(f"{x['incident_id']} · {x['priority']}")
  st.write(x['summary'])
  a,b,c=st.columns(3);a.metric('Flows in group',x['count']);b.metric('Detection score',f"{x['max_score']:.1%}");c.metric('Predicted category',', '.join(x['attack_types']))
  st.markdown('#### Observed network attributes')
  if x['feature_context']:st.dataframe(pd.DataFrame(x['feature_context']),hide_index=True,use_container_width=True)
  else:st.info('No additional network attribute fields available for this file.')
  st.markdown('#### Relevant flow attributes (model-wide context)')
  if x['model_feature_summary']:
   st.dataframe(pd.DataFrame(x['model_feature_summary']),hide_index=True,use_container_width=True)
   st.caption('Global feature importance from the trained model, combined with observed median values. This is not a per-flow causal explanation.')
  else:st.info('Global feature importance is unavailable for this model.')
  st.markdown('#### Suggested analyst actions')
  for action in x['recommended_actions']:st.write('• '+action)
  with st.expander('Evidence row IDs'):st.write(x['flow_ids']);st.caption('Row IDs refer to input CSV order, starting from zero.')
 else:st.success('No suspicious flows identified in this sample.')
with tabs[2]:
 st.subheader('Network flows flagged for review')
 top=pd.DataFrame(r['top_flows']);st.dataframe(top,hide_index=True,use_container_width=True)
 st.caption('The detection score represents the sum of predicted attack-class probabilities, and is not guaranteed to be calibrated.')
with tabs[3]:
 st.subheader('How the investigation was processed')
 a,b=st.columns([1,2])
 with a:
  calls=pd.Series(r['agent_calls']);st.bar_chart(calls)
  st.metric('Highest share of tool calls',f"{r['max_agent_share']:.1%}")
  if r['under_40_percent']:st.success('Observed workload is within the 40% tool-call limit.')
  else:st.warning('Workload limit exceeded for this run; see execution trace.')
 with b:
  flow=[{'Step':i+1,'Agent':e['agent'],'Operation':e['kind'],'Time':e['timestamp']} for i,e in enumerate(r['events'])]
  st.dataframe(pd.DataFrame(flow),hide_index=True,use_container_width=True)
 with st.expander('Full inter-agent messages'):st.json(r['events'])
with tabs[4]:
 st.subheader('Detection quality on labeled holdout data')
 info=r['model_metadata'];m=info.get('heldout_metrics') or {}
 if m:
  a,b,c,d=st.columns(4)
  a.metric('Holdout accuracy',f"{m.get('accuracy',0):.1%}")
  b.metric('Macro F1',f"{m.get('macro_f1',m.get('f1',0)):.1%}")
  c.metric('Test records',f"{m.get('heldout_rows',0):,}")
  d.metric('Training records',f"{m.get('train_rows',0):,}")
  labels=m.get('labels',[]);matrix=m.get('confusion_matrix',[])
  if labels and matrix:
   st.markdown('#### Confusion matrix — held-out evaluation')
   st.dataframe(pd.DataFrame(matrix,index=['Actual: '+x for x in labels],columns=['Predicted: '+x for x in labels]),use_container_width=True)
  if m.get('class_report'):
   rows=[{'Class':k,'Precision':v.get('precision'),'Recall':v.get('recall'),'F1':v.get('f1-score'),'Support':v.get('support')} for k,v in m['class_report'].items() if isinstance(v,dict) and k not in ['macro avg','weighted avg']]
   st.markdown('#### Detection quality by class')
   st.dataframe(pd.DataFrame(rows),hide_index=True,use_container_width=True)
   if len(rows)>1:st.bar_chart(pd.DataFrame(rows).set_index('Class')['F1'])
  st.caption('Holdout metrics come from the original separately labeled test CSV, not from the uploaded investigation. They do not guarantee accuracy on another environment.')
 else:st.info('No held-out evaluation metadata stored for this model.')
 if info.get('training_provenance','').startswith('SYNTHETIC'):st.warning('Demonstration model — results are not benchmark evidence.')
 st.write('**Data origin:**',info.get('training_provenance','Unknown'))
 st.write('**Training file:**',info.get('training_filename','Not recorded'))
 st.markdown('#### Evidence consistency checks')
 v=r['verification'];st.write(f"Verified {v['checked']} displayed incident candidates: "+('all checks passed' if v['passed'] else 'some checks failed'))
 with st.expander('Verification details'):st.dataframe(pd.DataFrame(v['checks']),use_container_width=True,hide_index=True)
 with st.expander('Interpretation notes'):
  for note in v['notes']:st.write('• '+note)
with tabs[5]:
 st.subheader('Export investigation')
 st.download_button('Download full JSON audit',json.dumps(r,indent=2),file_name=r['run_id']+'.json',mime='application/json')
 rows_html=''.join('<tr>'+''.join('<td>'+html.escape(str(v))+'</td>' for v in [x['incident_id'],x['entity'],x['priority'],x['count'],', '.join(x['attack_types']),x['max_score']])+'</tr>' for x in r['incidents'])
 bars=''.join('<div style="margin:8px 0"><strong>'+html.escape(str(k))+'</strong> '+str(v)+'<div style="background:#e4ebf5;border-radius:5px;height:13px"><div style="background:#377bbb;height:13px;width:'+str(round(100*v/max(r['class_distribution'].values()),2))+'%;border-radius:5px"></div></div></div>' for k,v in sorted(r['class_distribution'].items(),key=lambda kv:-kv[1]));style='body{font-family:Arial;margin:40px;color:#192333}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:8px;text-align:left}th{background:#e8effa}h1{color:#234c79}'
 report=f'''<!DOCTYPE html><html><head><meta charset="utf-8"><title>Report</title><style>{style}</style></head><body><h1>Security Investigation</h1><p>Run: {html.escape(r['run_id'])}</p><h2>Executive summary</h2><p>Processed {r['rows']} flows; {r['suspicious_flows']} flagged for review; {r['correlation']['total_candidates']} incident candidates.</p><p>Evidence validation: {'passed' if r['verification']['passed'] else 'review required'}.</p><h2>Predicted traffic categories</h2>{bars}<h2>Incident priority queue (top 100)</h2><table><tr><th>ID</th><th>Entity</th><th>Priority</th><th>Flows</th><th>Predicted category</th><th>Score</th></tr>{rows_html}</table><p>Model scores are not confirmed security incidents.</p></body></html>'''
 st.download_button('Download formatted HTML report',report,file_name=r['run_id']+'.html',mime='text/html')
