from bs4 import BeautifulSoup
import os
import pandas as pd

# Folder-specific configurations: folder name and extraction method
folder_configs = {
    "Backend/phish_tank_html_pages": {
        "source": "PhishTank",
        "output_csv": r"E:\Downloads\QRExtension\Backend\phishtank_urls.csv"
    },
    "Backend/ahrefs_html_pages": {
        "source": "Ahrefs",
        "output_csv": r"E:\Downloads\QRExtension\Backend\ahrefs_urls.csv"
    }
}

for folder_name, config in folder_configs.items():
    urls = []

    for filename in os.listdir(folder_name):
        if filename.endswith(".html"):
            file_path = os.path.join(folder_name, filename)

            # Open and parse HTML file
            with open(file_path, "r", encoding="utf-8") as file:
                soup = BeautifulSoup(file, "html.parser")

            if config["source"] == "PhishTank":
                table = soup.find("table", {"class": "data"})
                if table:
                    rows = table.find_all("tr")[1:]  # Skip header
                    for row in rows:
                        cols = row.find_all("td")
                        if len(cols) > 1:
                            url = cols[1].get_text(strip=True).split("added on")[0]
                            urls.append([url])

            elif config["source"] == "Ahrefs":
                links = soup.find_all("a", href=True)
                for link in links:
                    href = link['href']
                    if href.startswith("http"):  # Simple filter for valid URLs
                        urls.append([href])

    # Save to CSV
    df = pd.DataFrame(urls, columns=["URL"])
    df.to_csv(config["output_csv"], index=False)
    print(f"Extracted URLs from {folder_name} saved to {config['output_csv']}")
