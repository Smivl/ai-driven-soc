"""
    Find the probability of a raw log being in a certain category
"""

import lightgbm as lgb

import pandas as pd
import lightgbm as lgb
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

from backend.log_evaluation.soc_event import SOCevent

###### source .venv/bin/activate
##### python -m backend.log_evaluation.ML_scoring

# ---- Severity categories scores -----------------------------------------------------------------------

# NOTE : needs finetuning

CATEGORY_SEVERITY = {
    "authentication-failed"         : 45,
    "authentication-success"        : 5,
    "connection-closed"             : 5,
    "connection-failed"             : 30,
    "connection-opened"             : 10,
    "database-operation"            : 25,
    "directory-changed"             : 35,
    "directory-created"             : 20,
    "directory-deleted"             : 50,
    "file-action-failure"           : 30,
    "file-deleted"                  : 55,
    "file-modification"             : 40,
    "file-read"                     : 15,
    "file-write"                    : 35,
    "hardware-monitoring"           : 10,
    "http-request-failure"          : 30,
    "http-request-success"          : 5,
    "ids-alert"                     : 80,
    "network-filtered"              : 40,
    "network-traffic"               : 10,
    "process-ended"                 : 10,
    "process-error"                 : 35,
    "process-info"                  : 5,
    "process-shutdown"              : 20,
    "process-started"               : 15,
    "system-configuration-changed"  : 60,
    "user-creation"                 : 50,
    "user-deletion"                 : 65,
    "user-logout"                   : 10,
    "user-session-open"             : 15,
}

# ---- Train and use model -----------------------------------------------------------------------

def load_and_train(data_dir: str = "data"):
    dfs = []
    for i in range(6):  
        path = f"{data_dir}/SIEVE_{i:02d}_100K.csv"
        df   = pd.read_csv(path, on_bad_lines='skip')
        dfs.append(df)
        print(f"Loaded {path}: {len(df)} rows")
    
    df = pd.concat(dfs, ignore_index=True)
    print(f"\nTotal: {len(df)} rows")

    logs   = df["log"]
    labels = df["category"]

    X_train, X_test, y_train, y_test = train_test_split(
        logs, labels, test_size=0.2, random_state=42
    )

    vectorizer = TfidfVectorizer(max_features=1000)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec  = vectorizer.transform(X_test)

    model = lgb.LGBMClassifier(n_estimators=100, verbose=-1)
    model.fit(X_train_vec, y_train)

    acc = accuracy_score(y_test, model.predict(X_test_vec))
    print(f"Accuracy: {acc:.3f}")

    return vectorizer, model


def score_log(event: SOCevent, vectorizer, model):
    # Score log based on the mode;
    X = vectorizer.transform([event.raw_log]).toarray()         # transform only
    probs = model.predict_proba(X)[0]                 # probability per category
    
    score = sum(
        prob * CATEGORY_SEVERITY[cat]
        for cat, prob in zip(model.classes_, probs)
    )
    return score
