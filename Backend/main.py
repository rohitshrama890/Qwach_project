from bs4 import BeautifulSoup
import csv
import os

# Define the list of your HTML pages (adjust if needed)
html_files = [f"E:\\Downloads\\QRExtension\\Backend\\ahrefs_html_pages\\page_{i}.html" for i in range(1, 11)]  # pages 1 to 10
output_file = "all_urls.csv"

# List to hold all URLs
all_urls = []

# Loop through all HTML files
for file_name in html_files:
    if not os.path.exists(file_name):
        continue  # Skip if file not found

    with open(file_name, "r", encoding="utf-8") as f:
        soup = BeautifulSoup(f, "html.parser")
        tbody = soup.find("tbody")
        if tbody:
            links = tbody.find_all("a", href=True)
            for link in links:
                all_urls.append(link['href'])

# Save all URLs to a single CSV
with open(output_file, "w", newline='', encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["URL"])
    for url in all_urls:
        writer.writerow([url])

print(f"Saved {len(all_urls)} URLs to {output_file}")
