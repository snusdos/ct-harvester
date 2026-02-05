import pandas as pd

# Load the CSV file into a DataFrame
df = pd.read_csv('') # Specify the path to your CSV file

# Count the number of duplicate serial numbers
duplicate_count = df.duplicated(subset=['serialnumber']).sum()

# Filter out duplicate entries based on 'serialnumber'
df_filtered = df.drop_duplicates(subset=['serialnumber'])

# Save the filtered DataFrame back to a new CSV file
df_filtered.to_csv('', index=False) # Specify the path to your output CSV file

print("Duplicates removed:", duplicate_count)
