"""Train a trustworthy model on labeled network-flow data. Evaluation is held out."""
import argparse,json,sys
from pathlib import Path
import numpy as np,pandas as pd,joblib
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.ensemble import ExtraTreesClassifier,RandomForestClassifier,HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report,confusion_matrix,accuracy_score,precision_recall_fscore_support
from sklearn.model_selection import train_test_split
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from soc.core import META

def train(tr_path,te_path,out,limit=None,algorithm='extra_trees',dataset='unsw',mode='binary',class_balance=False):
 if Path(tr_path).resolve()==Path(te_path).resolve():raise ValueError('Training and test files must differ')
 train=pd.read_csv(tr_path,low_memory=False); test=pd.read_csv(te_path,low_memory=False)
 for frame in (train,test):frame.columns=frame.columns.str.strip()
 if dataset=='unsw':
  target='attack_cat' if mode=='multiclass' else 'label'
  if target not in train or target not in test:raise ValueError('UNSW target column missing: '+target)
  if mode=='multiclass':
   def lab(df):return df[target].fillna('Normal').astype(str).str.strip().replace({'':'Normal'})
  else:
   def lab(df):return pd.to_numeric(df[target],errors='raise').astype(int)
 else:
  if mode=='multiclass':target='Label'
  else:target='Label'
  if target not in train or target not in test:raise ValueError('CIC Label column missing')
  if mode=='multiclass':
   def lab(df):return df[target].astype(str).str.strip()
  else:
   def lab(df):return (~df[target].astype(str).str.upper().str.strip().eq('BENIGN')).astype(int)
 # Sample across the full original files, rather than taking the first N ordered records.
 # For known classes with >=2 members, stratification keeps approximate class proportions.
 def sample_frame(frame, source_name):
  if limit is None or limit >= len(frame):return frame.reset_index(drop=True)
  if limit <= 0:raise ValueError('--rows must be positive')
  y=lab(frame); counts=y.value_counts()
  if limit < len(counts):
   raise ValueError(f'--rows {limit} is smaller than the number of classes ({len(counts)}) in {source_name}')
  if counts.min() >= 2 and (len(frame)-limit)>=len(counts):
   sampled,_=train_test_split(frame,train_size=limit,stratify=y,random_state=42)
  else:
   # Extremely rare classes: keep one example of each class, then sample the remainder.
   heads=frame.groupby(y,sort=True,dropna=False).sample(n=1,random_state=42)
   remaining=frame.drop(index=heads.index)
   extra=remaining.sample(n=limit-len(heads),random_state=42)
   sampled=pd.concat([heads,extra])
  return sampled.sample(frac=1,random_state=42).reset_index(drop=True)
 train=sample_frame(train,'train')  # Keep the entire official test split untouched.
 ytr=lab(train);yte=lab(test)
 if len(ytr.unique())<2:raise ValueError('Training split needs at least two classes')
 # Strictly never use source labels, classes, row index, IP or time as model features.
 features=[c for c in train.columns if c in test and c not in META and not c.startswith('_') and pd.api.types.is_numeric_dtype(train[c]) and pd.api.types.is_numeric_dtype(test[c])]
 if not features:raise ValueError('No compatible numeric features')
 pre=ColumnTransformer([('num',SimpleImputer(strategy='median'),features)],remainder='drop')
 if algorithm=='extra_trees':clf=ExtraTreesClassifier(n_estimators=100,max_depth=20,min_samples_leaf=2,random_state=42,n_jobs=-1,class_weight=('balanced' if class_balance else None))
 elif algorithm=='random_forest':clf=RandomForestClassifier(n_estimators=100,max_depth=20,min_samples_leaf=2,random_state=42,n_jobs=-1,class_weight=('balanced' if class_balance else None))
 elif algorithm=='logistic_regression':
  pre=Pipeline([('impute',pre),('scale',StandardScaler())]);clf=LogisticRegression(max_iter=1000,class_weight=('balanced' if class_balance else None))
 else:raise ValueError('Unsupported algorithm')
 pipe=Pipeline([('prep',pre),('classifier',clf)])
 def clean(df):return df[features].apply(pd.to_numeric,errors='coerce').replace([np.inf,-np.inf],np.nan)
 pipe.fit(clean(train),ytr)
 pred=pipe.predict(clean(test))
 labels=list(map(str,pipe.classes_));actual=list(map(str,yte));predicted=list(map(str,pred))
 report=classification_report(actual,predicted,labels=labels,output_dict=True,zero_division=0)
 matrix=confusion_matrix(actual,predicted,labels=labels).tolist()
 metrics={'accuracy':round(float(accuracy_score(actual,predicted)),5),'macro_f1':round(float(report['macro avg']['f1-score']),5),'weighted_f1':round(float(report['weighted avg']['f1-score']),5),'precision_weighted':round(float(report['weighted avg']['precision']),5),'recall_weighted':round(float(report['weighted avg']['recall']),5),'class_report':report,'confusion_matrix':matrix,'labels':labels,'train_rows':len(train),'heldout_rows':len(test),'class_distribution_test':pd.Series(actual).value_counts().to_dict(),'class_distribution_train':pd.Series(list(map(str,ytr))).value_counts().to_dict(),'evaluation_protocol':'official_holdout_full_test','model_name':algorithm}
 importances={}
 if hasattr(clf,'feature_importances_'):importances=dict(sorted(zip(features,map(float,clf.feature_importances_)),key=lambda x:-x[1])[:20])
 synthetic='synthetic' in (str(tr_path)+' '+str(te_path)).lower()
 provenance='SYNTHETIC DEMONSTRATION' if synthetic else 'USER-SUPPLIED BENCHMARK'
 package={'model':pipe,'features':features,'dataset':dataset,'model_name':algorithm,'mode':mode,'classes':labels,'heldout_metrics':metrics,'training_provenance':provenance,'feature_importance':importances,'training_filename':Path(tr_path).name,'testing_filename':Path(te_path).name,'train_sampling':'full' if limit is None else 'stratified','class_balance':class_balance}
 Path(out).parent.mkdir(parents=True,exist_ok=True);joblib.dump(package,out)
 report_path=Path(out).with_suffix('.metrics.json');report_path.write_text(json.dumps(metrics,indent=2),encoding='utf-8')
 print(json.dumps({'saved':str(out),'evaluation':str(report_path),'mode':mode,'dataset':dataset,'features':len(features),'accuracy':metrics['accuracy'],'macro_f1':metrics['macro_f1'],'provenance':provenance},indent=2));return package
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--train',required=True);p.add_argument('--test',required=True);p.add_argument('--out',default='models/unsw_model.joblib');p.add_argument('--rows',type=int,default=None);p.add_argument('--model',choices=['extra_trees','random_forest','logistic_regression'],default='extra_trees');p.add_argument('--dataset',choices=['unsw','cic'],default='unsw');p.add_argument('--mode',choices=['binary','multiclass'],default='binary');p.add_argument('--balanced',action='store_true',help='Experimental class weights; disabled by default');a=p.parse_args();train(a.train,a.test,a.out,a.rows,a.model,a.dataset,a.mode,a.balanced)
