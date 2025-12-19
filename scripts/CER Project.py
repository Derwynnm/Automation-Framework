import pandas as pd

# === CONFIGURATION ===
input_file = r'C:\Users\dmckella\Desktop\Phones.xlsx'
output_file = r'C:\Users\dmckella\Desktop\Results.xlsx'
sheet_name = None

# === SCRIPT ===

def normalize_series(s: pd.Series) -> pd.Series:
    s = s.astype(str).str.strip().str.lower().replace("", pd.NA)
    return s

df = pd.read_excel(input_file, sheet_name=0, engine="openpyxl")

required_cols = ["ERL Name", "Location"]
for col in required_cols:
    if col not in df.columns:
        raise ValueError(f"Missing required column: {col}")

erl_norm = normalize_series(df["ERL Name"])
loc_norm = normalize_series(df["Location"])

erl_blank = erl_norm.isna()
mismatch = (erl_norm.notna() & loc_norm.notna() & (erl_norm != loc_norm))
one_side_nan = (erl_norm.isna() & loc_norm.notna()) | (erl_norm.notna() & loc_norm.isna())
issues_mask = erl_blank | mismatch | one_side_nan

location_has_view = df["Location"].astype(str).str.contains("view", case=False, na=False)

# Combine both condition sets and drop duplicates
combined_df = pd.concat([
    df.loc[issues_mask],
    df.loc[location_has_view]
]).drop_duplicates()

# Write output (single deduped sheet)
with pd.ExcelWriter(output_file, engine="openpyxl") as writer:
    combined_df.to_excel(writer, index=False, sheet_name="Results")

print(f"✅ Done! Wrote {len(combined_df)} unique rows to '{output_file}'.")
