"""Synthetic smoke-test network flows. NOT A REAL BENCHMARK."""
import numpy as np,pandas as pd
from pathlib import Path
rng=np.random.default_rng(23);Path('data').mkdir(exist_ok=True)
def make(n,offset,labels=True):
 y=(rng.random(n)<.22).astype(int);t=np.arange(n)*12+offset
 data=pd.DataFrame({'dur':rng.exponential(1,n)+y*rng.uniform(.1,2,n),'spkts':rng.poisson(7,n)+y*rng.poisson(30,n),'dpkts':rng.poisson(9,n),'sbytes':rng.gamma(2,100,n)+y*rng.gamma(5,600,n),'dbytes':rng.gamma(2,120,n),'rate':rng.gamma(2,5,n)+y*rng.gamma(7,8,n),'Source IP':np.where(y==1,rng.choice(['10.0.3.45','10.0.3.46'],n),rng.choice(['10.0.1.10','10.0.1.11','10.0.1.12'],n)),'Destination IP':rng.choice(['10.0.2.10','10.0.2.20'],n),'Timestamp':pd.to_datetime(t,unit='s',utc=True).astype(str)})
 if labels:data['label']=y
 return data
make(1500,1714500000).to_csv('data/SYNTHETIC_train.csv',index=False)
make(600,1714800000).to_csv('data/SYNTHETIC_test.csv',index=False)
make(280,1715100000,False).to_csv('data/SYNTHETIC_new_flows.csv',index=False)
print('Created explicitly labeled synthetic demo CSVs in data/')
