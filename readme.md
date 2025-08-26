# Project Documentation

## Overview

This is a C# console application that scans source code for security vulnerabilities. The tool analyzes multiple programming languages and generates detailed reports in various formats (text, JSON, CSV, HTML). It was built based on patterns from three PowerShell security scanners to detect common vulnerabilities like SQL injection, XXE, IDOR, open redirects, and language-specific security issues.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

- **Application Type**: Console application built with .NET 8.0
- **Language Detection**: Supports 20+ file extensions across multiple programming languages
- **Pattern Matching**: Uses regular expressions to detect security vulnerability patterns
- **Report Generation**: Multi-format output with detailed vulnerability information
- **Progress Tracking**: Real-time scan progress with file-by-file updates

### Core Components

- **Models**: Data structures for vulnerabilities, scan results, and patterns
- **Services**: Core scanning logic, pattern definitions, and report generation
- **Utils**: Language detection and progress tracking utilities

### Supported Languages

- C#/.NET (cs, cshtml, razor, aspx)
- Java (java, jsp, jspx)
- PHP (php, phtml, php3-5)
- Python (py, pyw)
- JavaScript/TypeScript (js, jsx, ts, tsx)
- Ruby (rb, erb)
- Go (go)
- PowerShell (ps1, psm1, psd1)
- HTML/XML
- And more

### Vulnerability Categories

- iOS Security Issues
- Android Security Issues
- Financial Security (race conditions, parameter manipulation)
- IDOR (Insecure Direct Object References)
- XXE (XML External Entity)
- Open Redirects
- SQL Injection
- PowerShell-specific vulnerabilities

## External Dependencies

- **Newtonsoft.Json**: JSON serialization for reports
- **CsvHelper**: CSV report generation
- **System.CommandLine**: Command-line interface parsing
- **.NET 8.0 SDK**: Runtime and compilation platform

## Recent Changes (August 2025)

- Built complete C# security scanner application with .NET 8.0 framework
- Added PowerShell file support (.ps1, .psm1, .psd1) with language detection
- Implemented comprehensive vulnerability pattern library with 342 security patterns
- Added multi-format reporting (text, JSON, CSV, HTML) with simultaneous generation support
- **Enhanced with JSON-based pattern storage system for easy pattern management**
- **Implemented file extension filtering to prevent false positives and improve accuracy**
- **Added advanced CLI parameters including custom JSON pattern database path**
- Successfully tested scanner against provided PowerShell security scripts
- Enhanced patterns to support cross-language security detection (PowerShell, iOS, Android, web languages)
- Generated detailed security reports detecting Network Security Issues, Sensitive Information, and PowerShell Execution vulnerabilities
- Verified comprehensive pattern matching including http://, API keys, Invoke-Expression, and other security risks

## Usage

```bash
dotnet run -- --path <source_path> [options]

Options:
  --path, -p           Source code directory to scan (required)
  --format, -f         Output format: text, json, csv, html (default: text)
  --output, -o         Output file path (optional, auto-generated if not specified)
  --languages, -l      Languages to scan (default: all)
  --progress           Show scan progress with file-by-file updates
  --verbose, -v        Enable verbose output with detailed information
  --patterns, -db      Path to JSON patterns file (default: patterns.json in current directory)
  --output-formats, -of Output formats to generate: text, json, csv, html, all (default: text)
```

## Example Commands

```bash
# Basic scan with progress
dotnet run -- --path ./src --progress

# Generate HTML report with custom output file
dotnet run -- --path ./src --format html --output security_report.html

# Scan specific languages only with verbose output
dotnet run -- --path ./src --languages csharp,java,php --verbose

# Use custom JSON patterns database
dotnet run -- --path ./src --patterns ./custom_patterns.json --progress

# Generate all output formats simultaneously
dotnet run -- --path ./src --output-formats all --progress

# PowerShell security scan with JSON patterns
dotnet run -- --path ./powershell_scripts --languages powershell --format html --progress
```

## JSON Patterns Database

The scanner uses a JSON-based pattern storage system for easy customization and expansion:

```json
{
  "patterns": [
    {
      "type": "Vulnerability Category Name",
      "fileExtensions": ["*.ext1", "*.ext2"],
      "patterns": ["regex_pattern_1", "regex_pattern_2"],
      "whitelist": ["safe_pattern_1", "safe_pattern_2"],
      "severity": "HIGH|MEDIUM|LOW|CRITICAL",
      "cweId": "CWE-XXX"
    }
  ]
}
```

### Key Features:
- **File Extension Filtering**: Patterns only apply to specified file types
- **Cross-Language Support**: Same vulnerability patterns work across multiple languages
- **Whitelist Patterns**: Reduce false positives by excluding safe code patterns
- **Severity Classification**: CRITICAL, HIGH, MEDIUM, LOW severity levels
- **CWE Mapping**: Maps vulnerabilities to Common Weakness Enumeration standards