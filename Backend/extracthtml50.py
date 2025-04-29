# import os
# import requests

# # Create a folder to save HTML files
# folder_name = "ahrefs_html_pages"
# os.makedirs(folder_name, exist_ok=True)

# # Base URL with pagination
# base_url = "https://ahrefs.com/websites/{}"

# # Number of pages to scrape
# num_pages = 10  

# for page in range(1, num_pages + 1):
#     url = base_url.format(page)
#     headers = {"User-Agent": "Mozilla/5.0"}
#     response = requests.get(url, headers=headers)

#     if response.status_code == 200:
#         file_path = os.path.join(folder_name, f"page_{page}.html")
#         with open(file_path, "w", encoding="utf-8") as f:
#             f.write(response.text)
#         print(f"Saved: {file_path}")
#     else:
#         print(f"Failed to fetch page {page}")

# print("All pages downloaded and saved in:", folder_name)



import os
import requests

# Folder names and respective number of pages to scrape
tasks = {
    "Backend/ahrefs_html_pages": {
        "base_url": "https://ahrefs.com/websites/{}",
        "pages": 10
    },
    "Backend/phish_tank_html_pages": {
        "base_url": "https://phishtank.org/websites/{}",
        "pages": 50
    }
}

headers = {"User-Agent": "Mozilla/5.0"}

# Loop through each task (folder + base URL + number of pages)
for folder_name, task in tasks.items():
    os.makedirs(folder_name, exist_ok=True)
    base_url = task["base_url"]
    num_pages = task["pages"]

    for page in range(1, num_pages + 1):
        url = base_url.format(page)
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            file_path = os.path.join(folder_name, f"page_{page}.html")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(response.text)
            print(f"Saved: {file_path}")
        else:
            print(f"Failed to fetch page {page} from {folder_name}")

print("All pages downloaded and saved.")
