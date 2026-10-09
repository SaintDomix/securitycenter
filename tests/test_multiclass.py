import tempfile,unittest
from pathlib import Path
import numpy as np,pandas as pd
from tools.train_model import train
from soc.core import investigate
class MultiClassTests(unittest.TestCase):
 def test_multiclass_train_evaluate_investigate(self):
  with tempfile.TemporaryDirectory() as td:
   td=Path(td);g=np.random.default_rng(17)
   def dataset(n):
    labels=np.resize(np.array(['Normal','DoS','Reconnaissance']),n)
    f=np.array([{'Normal':0,'DoS':4,'Reconnaissance':9}[x] for x in labels],dtype=float)+g.normal(0,.3,n)
    return pd.DataFrame({'dur':f,'sbytes':f*8+g.normal(0,1,n),'dbytes':3*f+g.normal(0,1,n),'attack_cat':labels,'label':(labels!='Normal').astype(int),'Source IP':np.where(labels=='Normal','192.0.2.1','192.0.2.2'),'Timestamp':pd.date_range('2025-01-01',periods=n,freq='min').astype(str)})
   tr=td/'training.csv';te=td/'testing.csv';dataset(180).to_csv(tr,index=False);dataset(90).to_csv(te,index=False)
   bundle=td/'benchmark.joblib';result=train(tr,te,bundle,limit=180,mode='multiclass')
   self.assertIn('DoS',result['classes']);self.assertIn('Reconnaissance',result['classes'])
   audit=investigate(te,bundle,td/'audit.sqlite',90)
   self.assertTrue(audit['verification']['passed']);self.assertTrue(audit['under_40_percent']);self.assertIn('DoS',audit['class_distribution'])
   self.assertTrue(audit['incidents'][0]['model_feature_summary'])
 def test_demo_rejected_for_benchmark_filename(self):
  from sklearn.ensemble import ExtraTreesClassifier
  import joblib
  with tempfile.TemporaryDirectory() as td:
   td=Path(td);df=pd.DataFrame({'dur':[1,2,3,4,5,6],'sbytes':[3,4,5,6,7,8]})
   model=ExtraTreesClassifier(n_estimators=10,random_state=10).fit(df,[0,0,0,1,1,1])
   p=td/'demo.joblib';joblib.dump({'model':model,'features':['dur','sbytes'],'training_provenance':'SYNTHETIC DEMONSTRATION'},p)
   csv=td/'UNSW_NB15_testing-set.csv';df.to_csv(csv,index=False)
   with self.assertRaisesRegex(ValueError,'Demo model cannot'):investigate(csv,p,td/'audit.sqlite',6)
if __name__=='__main__':unittest.main()
