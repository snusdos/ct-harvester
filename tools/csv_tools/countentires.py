import pandas as pd

# Load the CSV into a df
df = pd.read_csv('') # Specify the path to your CSV file

# Count the number of rows in the df -> entries
row_count = len(df)

print("Total entries in CSV:", row_count)
