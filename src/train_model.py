import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# Load features dataset
df = pd.read_csv("data/features.csv")

# Ensure no missing values
df = df.dropna()

# Shuffle dataset
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# Separate X and y
X = df.drop("label", axis=1)
y = df["label"]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42
)

# Build ML Pipeline (Scaler + Model)
pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("model", RandomForestClassifier(
        n_estimators=300,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    ))
])

# Train
pipeline.fit(X_train, y_train)

# Predict
pred = pipeline.predict(X_test)

# Accuracy
acc = accuracy_score(y_test, pred)
print(f"\n🎯 Model Accuracy: {acc * 100:.2f}%\n")

print("\n📌 Classification Report:")
print(classification_report(y_test, pred))

# Save model
joblib.dump(pipeline, "models/phishing_model.pkl")
print("\n✔ Model saved to models/phishing_model.pkl")

