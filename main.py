import argparse,json
from pathlib import Path
from soc.core import investigate
p=argparse.ArgumentParser(description='Investigate new network flows with an existing model (no fitting).');p.add_argument('--input',required=True);p.add_argument('--model',default='models/unsw_model.joblib');p.add_argument('--db',default='runs/cyberguard.sqlite');p.add_argument('--rows',type=int,default=15000);a=p.parse_args()
r=investigate(a.input,a.model,a.db,a.rows);Path('reports').mkdir(exist_ok=True);path=Path('reports')/(r['run_id']+'.json');path.write_text(json.dumps(r,indent=2),encoding='utf-8');print(json.dumps({k:r[k] for k in ['run_id','rows','suspicious_flows','agent_calls','max_agent_share','under_40_percent']},indent=2));print('Report:',path)
