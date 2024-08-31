import pandas as pd
from sklearn.utils import resample
from sklearn.model_selection import train_test_split, cross_validate
from sklearn.tree import DecisionTreeClassifier
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score
import joblib

# Load datasets
df_attack = pd.read_csv('1Server10Attack.csv')
df_jam = pd.read_csv('1Server10Jam.csv')
df_normal = pd.read_csv('1Server10Normal.csv')
df_amplification = pd.read_csv('1Server10ClientsAmplificationAttack.csv')
df_sybil = pd.read_csv('sybil attack logs.csv')

# Label the data
df_attack['Label'] = 1
df_jam['Label'] = 2
df_normal['Label'] = 0
df_amplification['Label'] = 3
df_sybil['Label'] = 4

# Convert 'Time' to numeric
for df in [df_attack, df_jam, df_normal, df_amplification, df_sybil]:
    df['Time'] = pd.to_numeric(df['Time'])
    df['ΔTime'] = df['Time'].diff().fillna(0)

# Concatenate datasets
logs = pd.concat([df_normal, df_attack, df_jam, df_amplification, df_sybil])

# Replace missing values in 'Source' and 'Destination' columns
logs['Source'] = logs['Source'].fillna('Unknown')
logs['Destination'] = logs['Destination'].fillna('Unknown')


# Define features and labels
X = logs.drop('Label', axis=1)
y = logs['Label']

# Upsample minority classes
def upsample_class(df, majority_size):
    return resample(df, replace=True, n_samples=majority_size, random_state=42)

majority_size = df_normal.shape[0]
upsampled_dfs = [upsample_class(logs[logs['Label'] == i], majority_size) for i in range(1, 5)]
upsampled_logs = pd.concat([df_normal] + upsampled_dfs).sample(frac=1, random_state=42).reset_index(drop=True)

# Split the upsampled data into training and test sets
X_upsampled = upsampled_logs.drop('Label', axis=1)
y_upsampled = upsampled_logs['Label']
X_train, X_test, y_train, y_test = train_test_split(X_upsampled, y_upsampled, test_size=0.2, random_state=42)

# Define numerical and categorical features
numerical_features = ['Length', 'Time']
categorical_features = ['Source', 'Destination', 'Protocol']

# Create preprocessing pipeline
preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), numerical_features),
        ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
    ])

# Define the Decision Tree model
model = DecisionTreeClassifier()

# Create a pipeline with preprocessing and model
pipeline = Pipeline(steps=[('preprocessor', preprocessor), ('classifier', model)])

# Perform cross-validation
cv_results = cross_validate(pipeline, X_upsampled, y_upsampled, cv=5, scoring=['accuracy', 'f1_macro', 'roc_auc_ovr'])

print("=== Decision Tree - Cross-Validation Results on Upsampled Data ===")
print(f"Cross-Validation Accuracy: {cv_results['test_accuracy'].mean():.4f} ± {cv_results['test_accuracy'].std():.4f}")
print(f"Cross-Validation F1 Score (Macro Average): {cv_results['test_f1_macro'].mean():.4f} ± {cv_results['test_f1_macro'].std():.4f}")
print(f"Cross-Validation ROC-AUC (One-vs-Rest): {cv_results['test_roc_auc_ovr'].mean():.4f} ± {cv_results['test_roc_auc_ovr'].std():.4f}")

# Fit the model on the upsampled training data
pipeline.fit(X_train, y_train)

# Make predictions on the test data
y_pred = pipeline.predict(X_test)

# Evaluate the model
print("=== Decision Tree on Upsampled Data ===")
print(classification_report(y_test, y_pred))
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")

# ROC-AUC for Decision Tree
try:
    print(f"ROC-AUC: {roc_auc_score(y_test, pipeline.predict_proba(X_test), multi_class='ovr'):.4f}")
except AttributeError:
    print("ROC-AUC cannot be computed for Decision Tree with the given setup.")

# Export the trained model
joblib.dump(pipeline, 'decision_tree_model.pkl')
