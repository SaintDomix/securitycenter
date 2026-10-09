import tempfile, unittest
from pathlib import Path
import numpy as np
import pandas as pd
from tools.train_model import train
from soc.core import investigate

class FinalProtocolTests(unittest.TestCase):
    def test_full_holdout_and_binary_without_label_leakage(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); rng=np.random.default_rng(3)
            def make(n):
                x=rng.normal(size=n)
                y=(x>0).astype(int)
                return pd.DataFrame({'flow_feature':x,'flow_volume':abs(x)*3,'label':y,'attack_cat':np.where(y==1,'DoS','Normal')})
            train_csv=root/'train.csv';test_csv=root/'test.csv';make(140).to_csv(train_csv,index=False);make(90).to_csv(test_csv,index=False)
            bundle=train(str(train_csv),str(test_csv),str(root/'binary.joblib'),limit=50,mode='binary')
            self.assertEqual(bundle['heldout_metrics']['heldout_rows'],90)
            self.assertEqual(bundle['heldout_metrics']['train_rows'],50)
            self.assertNotIn('label',bundle['features'])
            self.assertNotIn('attack_cat',bundle['features'])
            self.assertFalse(bundle['class_balance'])
            result=investigate(str(test_csv),str(root/'binary.joblib'),str(root/'audit.sqlite'),max_rows=90)
            self.assertEqual(result['rows'],90)
            self.assertTrue(result['verification']['passed'])

if __name__=='__main__':unittest.main()
