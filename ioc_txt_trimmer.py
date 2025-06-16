# This script processes a text file to:
# - Strip leading and trailing whitespace from each line
# - Extract the first word or sequence of characters before the first whitespace on each line
# - Remove duplicate entries based on these extracted values
# - Write the processed and unique entries back to the same file
#
# Usage:
# Simply run the script with the file path defined in 'file_path'. 
# The script will read from and write to the file named 'ioc.txt' by default.

def process_file(file_path):
    # Read and process the lines
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Use a set to store unique results
    unique_results = set()
    processed_lines = []

    for line in lines:
        # Strip leading and trailing whitespace from the line
        line = line.strip()
        if line:  # If the line is not empty
            # Split the line at the first whitespace and keep the first part
            result = line.split(None, 1)[0]
            # Only add if it's not already in the set
            if result not in unique_results:
                unique_results.add(result)
                print(result)
                processed_lines.append(result + '\n')

    # Write the processed lines back to the file
    with open(file_path, 'w') as file:
        file.writelines(processed_lines)

# Path to the file
file_path = 'ioc.txt'

# Process the file
process_file(file_path)