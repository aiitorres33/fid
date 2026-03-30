# fid

> File Identification tool using magic numbers, polyglot detection, heuristic analysis, YARA and binwalk integration.

![Python](https://img.shields.io/badge/python-3.x-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)

---

## Overview

`fid` is a lightweight but powerful file analysis tool designed for:

- file type detection using magic numbers  
- upload bypass testing  
- malware triage  
- polyglot file detection  
- embedded file discovery  
- CTF and red team workflows  

---

## Features

- Magic number based file identification  
- Offset-aware signature matching  
- Wildcard signature support  
- ZIP container inspection (DOCX, XLSX, PPTX, APK, JAR)  
- Structural validation (PNG, PDF, ELF, PE, ZIP)  
- Polyglot / embedded file detection  
- Heuristic analysis (entropy + suspicious strings)  
- Optional YARA integration  
- Optional binwalk integration  
- Directory scanning  
- HTML report generation  

---

## Installation

```bash
git clone https://github.com/aiitorres33/fid.git
cd fid
python3 fid.py --help
```
No external dependencies required (standard library only).

## Optional tools
```bash
sudo apt install binwalk yara
```
## Usage
### Analyze a single file
```bash
python3 fid.py --file sample.bin
```
### JSON output
```bash
python3 fid.py --file sample.bin --json
```
### Scan a directory
```bash
python3 fid.py --scan-dir ./samples
```
### Generate HTML report
```bash
python3 fid.py --scan-dir ./samples --html-report reports/report.html
```
### YARA Integration
```bash
python3 fid.py --file suspicious.jpg --yara-rules rules/example_rules.yar
```
### Example rule
```yara
rule Suspicious_PHP_In_Image
{
    strings:
        $php = "<?php"
    condition:
        $php
}
```
### Binwalk Integration
```bash
python3 fid.py --file firmware.bin --binwalk
```
### With extraction
```bash
python3 fid.py --file firmware.bin --binwalk --extract --recursive-binwalk
```
### Example Output
```JSON
{
  "file": "sample.png",
  "detected": true,
  "primary_type": {
    "name": "PNG",
    "mime": "image/png"
  },
  "polyglot_analysis": {
    "detected": false
  },
  "heuristic_analysis": {
    "suspicious": false,
    "entropy": 5.23
  }
}
```
### Project Structure
```
fid/
├── fid.py
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
├── rules/
│   └── example_rules.yar
├── reports/
│   └── .gitkeep
├── samples/
│   └── .gitkeep
└── fid/
    ├── __init__.py
    ├── signatures.py
    ├── models.py
    ├── utils.py
    ├── detectors.py
    ├── analyzers.py
    ├── integrations.py
    ├── reporting.py
    └── scanner.py
```
### Limitations

Not a replacement for antivirus or sandboxing
Heuristic analysis is not definitive malware detection

### License
MIT License

### Author
Created by Aarón Israel Ibarra Torres
