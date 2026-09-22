
import csv

# Configuration
input_file = "Devices-07-23-2026.csv"      # Your source CSV file
output_file = "Devices_Output.csv"    # File to save modified data
target_column = "IP Address"        # Column header where text will be appended
append_text = "/32"       # Text to append

try:
    with open(input_file, mode="r", newline="", encoding="utf-8") as infile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames
        
        if target_column not in fieldnames:
            raise ValueError(f"Column '{target_column}' not found in CSV.")

        rows = []
        for row in reader:
            # Append text only if the cell is not empty
            if row[target_column]:
                row[target_column] = row[target_column] + append_text
            rows.append(row)

    # Write updated CSV
    with open(output_file, mode="w", newline="", encoding="utf-8") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"✅ Text appended to column '{target_column}' and saved to '{output_file}'.")

except FileNotFoundError:
    print(f"❌ File '{input_file}' not found.")
except Exception as e:
    print(f"❌ Error: {e}")
