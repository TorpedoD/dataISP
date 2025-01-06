import os
import csv
import pandas as pd

def convert_and_combine(input_folder, output_file):
    """
    Converts all .txt, .csv, and .xlsx files in the specified folder to .txt format,
    combines their content into a single .txt file, and performs data cleaning.

    Parameters:
        input_folder (str): Path to the folder containing the files.
        output_file (str): The path to the output .txt file.
    """
    combined_content = []

    for file_name in os.listdir(input_folder):
        file_path = os.path.join(input_folder, file_name)

        if not os.path.isfile(file_path):
            print(f"Skipping non-file item: {file_path}")
            continue

        try:
            if file_name.endswith('.txt'):
                # Read .txt files
                with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
                    content = file.read()
                    print(f"Read {len(content)} characters from '{file_name}'")
                    combined_content.append(content)

            elif file_name.endswith('.csv'):
                # Convert .csv to .txt
                with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
                    csv_content = list(csv.reader(file))
                    content = '\n'.join([', '.join(row) for row in csv_content])
                    print(f"Read {len(content)} characters from '{file_name}'")
                    combined_content.append(content)

            elif file_name.endswith('.xlsx'):
                # Convert .xlsx to .txt
                df = pd.read_excel(file_path)
                content = df.to_csv(index=False, header=True, sep=',')  # Removed 'line_terminator' argument
                print(f"Read {len(content)} characters from '{file_name}'")
                combined_content.append(content)

            else:
                print(f"Warning: Unsupported file type for '{file_name}'. Skipping.")
        except Exception as e:
            print(f"Error processing file '{file_name}': {e}")

    if not combined_content:
        print("No content was combined. Ensure the files have data.")
    else:
        # Combine all content into a single set of passwords
        combined_text = '\n'.join(combined_content)
        passwords = [line.strip() for line in combined_text.splitlines() if line.strip()]

        # Remove duplicates and filter empty/null values
        unique_passwords = list(set(passwords))
        print(f"Number of unique passwords after cleaning: {len(unique_passwords)}")

        # Write cleaned and combined content to output file
        with open(output_file, 'w', encoding='utf-8', errors='replace') as output:
            output.write('\n'.join(unique_passwords))
            print(f"Cleaned and combined content written to '{output_file}'.")

if __name__ == "__main__":
    # Example usage
    input_folder = "data"  # Folder containing the files
    output_file = "combined_output.txt"  # Output .txt file

    convert_and_combine(input_folder, output_file)
    print(f"All files in '{input_folder}' have been combined into '{output_file}'.")


