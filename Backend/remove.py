import pandas as pd

# Load your CSV
df = pd.read_csv(r"E:\Downloads\QRExtension\all_urls.csv")

# Step 1: Transform the URLs
df['URL'] = df['URL'].str.replace('//ahrefs.com/websites/', 'www.', regex=False)

# Step 2: Remove rows that are just "www."
df_cleaned = df[df['URL'].str.strip() != 'www.']

# Optional: Reset index
df_cleaned = df_cleaned.reset_index(drop=True)

# Step 3: Save cleaned CSV
df_cleaned.to_csv("cleaned_urls.csv", index=False)
