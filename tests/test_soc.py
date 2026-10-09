import tempfile,unittest,sys
from pathlib import Path
import numpy as np,pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.ensemble import ExtraTreesClassifier
import joblib
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from soc.core import investigate
class SOCTests(unittest.TestCase):
 def test_pipeline_and_no_labels_required(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);rs=np.random.RandomState(0)
   X=pd.DataFrame({'f1':rs.normal(size=120),'f2':rs.normal(size=120),'Source IP':['10.0.0.1']*120,'Timestamp':pd.date_range('2024-01-01',periods=120,freq='min').astype(str)})
   y=(X['f1']>.3).astype(int);model=Pipeline([('imp',SimpleImputer()),('clf',ExtraTreesClassifier(n_estimators=20,random_state=1))]);model.fit(X[['f1','f2']],y)
   p=d/'m.joblib';joblib.dump({'model':model,'features':['f1','f2'],'model_name':'ExtraTrees','dataset':'fixture','training_provenance':'SYNTHETIC'},p)
   csv=d/'unlabelled.csv';X.to_csv(csv,index=False);out=investigate(str(csv),str(p),str(d/'run.db'))
   self.assertEqual(len(out['agent_calls']),5);self.assertTrue(out['verification']['passed']);self.assertTrue(out['under_40_percent']);self.assertEqual(out['rows'],120)
 def test_schema_mismatch(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);X=pd.DataFrame({'f1':[1,2,3,4],'f2':[0,1,0,1]});m=ExtraTreesClassifier(n_estimators=5,random_state=2).fit(X,[0,1,0,1]);p=d/'m.joblib';joblib.dump({'model':m,'features':['f1','f2']},p)
   f=d/'missing.csv';pd.DataFrame({'f1':[1,2]}).to_csv(f,index=False)
   with self.assertRaisesRegex(ValueError,'Missing'):investigate(str(f),str(p),str(d/'a.db'))
if __name__=='__main__':unittest.main()
