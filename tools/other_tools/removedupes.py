def remove_dupes(input_file_path, output_file_path):
    unique_urls = set()
    
    with open(input_file_path, 'r') as file:
        for line in file:
            url = line.strip()
            if url:  # Avoid adding empty lines
                unique_urls.add(url)
    
    # Write the unique URLs back to a new file
    with open(output_file_path, 'w') as file:
        for url in unique_urls:
            file.write(url + '\n')
            
remove_dupes("data/output.txt", "data/parse1.txt")
