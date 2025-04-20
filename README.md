# SARA - Software Analysis & Review Assistant

SARA is a local cybersecurity tool for analyzing third-party software requests. It streamlines the review process using LLMs, web scraping, VirusTotal / AbuseIPDB API integration, threat intelligence, and Microsoft 365 automation.
SARA is ideal for organizations managing software intake and compliance.
---
## Features

- Scrape and analyze vendor websites, privacy policies, and search results for security/privacy risks
- LLM-based summaries using either local Ollama model or ChatGPT
- Integrated VirusTotal and AbuseIPDB lookups
- Microsoft Graph API integration for Excel pipelines allowing for automatic request updates, completion / comment marking, and more
- Optional local or SharePoint export for reports
- Live UI updates and modern dark mode
---

## Configuration

Before running, edit the `config.json` file in the same directory as the executable. This file will contain your API keys and Microsoft Graph credentials.

```json
{
  "tenant_id": "YOUR_TENANT_ID",
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET",
  "drive_id": "YOUR_DRIVE_ID",
  "excel_file_id": "YOUR_EXCEL_FILE_ID",
  "worksheet_name": "Sheet1",
  "virustotal_api_key": "YOUR_VT_KEY",
  "abuseipdb_api_key": "YOUR_ABUSEIPDB_KEY",
  "ollama_model": "qingmian/Qwen2.5-14B-CyberSecurity",
  "chatgpt_api_key": "YOUR_CHATGPT_KEY"
}
All fields are required unless you plan to disable a feature.
Example: You can omit chatgpt_api_key if only using local LLM mode.
```
##  Using the Requests Tab
If your organization collects software requests via **Microsoft Forms**, **Teams**, or **Planner-to-Excel**, you can point SARA directly at the generated Excel file.

### Instructions
- Ensure the Excel sheet includes a column called **Reviewer Comments**
- Leave request rows unmarked (e.g. don't put `"complete"` in the first column)

### SARA will:
- Load only rows that are not marked complete  
- Show all request data in a table  
- Let you enter comments and mark rows complete automatically  
- Write updates directly back to the original Excel file using the **Microsoft Graph API**

---

##  LLM Analysis Modes
SARA supports both local and cloud LLM inference:

###  Local Mode (via Ollama)
- Requires Ollama running on your machine  
- Specify a local model like: `qingmian/Qwen2.5-14B-CyberSecurity`  
- No API key or internet required  
- Great for privacy and offline use  

###  GPT Mode (OpenAI)
- Uses the ChatGPT API (`gpt-4.1-mini`)  
- Requires a valid OpenAI API key  
- Useful for fast, accurate results when internet is available  

---

##  Threat Intelligence
SARA performs security lookups using:

- **VirusTotal**: Checks if the vendor’s URL is flagged as malicious, suspicious, etc.  
- **AbuseIPDB**: Looks up IP/domain abuse reports, ISP, and risk score  

These results are displayed in dedicated tabs within the GUI.

---

##  Report Exporting
After analysis, you can export a Word document containing all results.

### Options:
- **Export Locally**: Saves the `.docx` file to your computer  
- **Export to SharePoint**: Uploads the `.docx` to your Microsoft Teams folder  

### Exports include:
- LLM Summary  
- VirusTotal Results  
- AbuseIPDB Lookup  
- List of scanned links, PDFs, and search terms  

 Filename format: `domain.com_TIMESTAMP.docx`

---

Created and maintained by [@YoungGunFrodo](https://github.com/YoungGunFrodo)
