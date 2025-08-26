using SecurityScanner.Models;
using Newtonsoft.Json;
using System.Globalization;
using CsvHelper;
using System.Text;

namespace SecurityScanner.Services
{
    public class ReportGenerator
    {
        public async Task GenerateReportAsync(ScanResult result, string format, string? outputFile = null)
        {
            var content = format.ToLower() switch
            {
                "json" => GenerateJsonReport(result),
                "csv" => GenerateCsvReport(result),
                "html" => GenerateHtmlReport(result),
                _ => GenerateTextReport(result)
            };

            if (string.IsNullOrEmpty(outputFile))
            {
                Console.WriteLine(content);
            }
            else
            {
                await File.WriteAllTextAsync(outputFile, content, Encoding.UTF8);
                Console.WriteLine($"Report saved to: {outputFile}");
            }
        }

        private string GenerateTextReport(ScanResult result)
        {
            var sb = new StringBuilder();
            
            sb.AppendLine("=== SECURITY VULNERABILITY SCAN REPORT ===");
            sb.AppendLine($"Scan Date: {result.ScanDate:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Project Path: {result.ProjectPath}");
            sb.AppendLine($"Scan Duration: {result.ScanDuration.TotalSeconds:F2} seconds");
            sb.AppendLine($"Files Scanned: {result.TotalFilesScanned}");
            sb.AppendLine($"Total Vulnerabilities: {result.TotalVulnerabilities}");
            sb.AppendLine();

            // Summary by severity
            sb.AppendLine("VULNERABILITIES BY SEVERITY:");
            foreach (var severity in result.VulnerabilitiesBySeverity)
            {
                sb.AppendLine($"  {severity.Key}: {severity.Value}");
            }
            sb.AppendLine();

            // Summary by category
            sb.AppendLine("VULNERABILITIES BY CATEGORY:");
            foreach (var category in result.VulnerabilitiesByCategory.OrderByDescending(x => x.Value))
            {
                sb.AppendLine($"  {category.Key}: {category.Value}");
            }
            sb.AppendLine();

            // Summary by language
            sb.AppendLine("VULNERABILITIES BY LANGUAGE:");
            foreach (var language in result.VulnerabilitiesByLanguage.OrderByDescending(x => x.Value))
            {
                sb.AppendLine($"  {language.Key}: {language.Value}");
            }
            sb.AppendLine();

            // Detailed vulnerabilities
            sb.AppendLine("=== DETAILED VULNERABILITIES ===");
            var groupedVulns = result.Vulnerabilities.GroupBy(v => v.Severity)
                .OrderBy(g => GetSeverityOrder(g.Key));

            foreach (var severityGroup in groupedVulns)
            {
                sb.AppendLine($"\n--- {severityGroup.Key} SEVERITY ---");
                
                foreach (var vuln in severityGroup.OrderBy(v => v.FilePath).ThenBy(v => v.LineNumber))
                {
                    sb.AppendLine($"\nCategory: {vuln.Category}");
                    sb.AppendLine($"File: {vuln.FilePath}:{vuln.LineNumber}");
                    sb.AppendLine($"Language: {vuln.Language}");
                    sb.AppendLine($"CWE ID: {vuln.CweId}");
                    sb.AppendLine($"Description: {vuln.Description}");
                    sb.AppendLine($"Code Snippet: {vuln.CodeSnippet}");
                    sb.AppendLine($"Recommendation: {vuln.Recommendation}");
                    
                    if (!string.IsNullOrEmpty(vuln.ContextLines))
                    {
                        sb.AppendLine("Context:");
                        sb.AppendLine(vuln.ContextLines);
                    }
                    sb.AppendLine(new string('-', 80));
                }
            }

            return sb.ToString();
        }

        private string GenerateJsonReport(ScanResult result)
        {
            var jsonSettings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented,
                DateFormatString = "yyyy-MM-dd HH:mm:ss"
            };
            
            return JsonConvert.SerializeObject(result, jsonSettings);
        }

        private string GenerateCsvReport(ScanResult result)
        {
            using var writer = new StringWriter();
            using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
            
            csv.WriteRecords(result.Vulnerabilities);
            return writer.ToString();
        }

        private string GenerateHtmlReport(ScanResult result)
        {
            var sb = new StringBuilder();
            
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang='en'>");
            sb.AppendLine("<head>");
            sb.AppendLine("<meta charset='UTF-8'>");
            sb.AppendLine("<meta name='viewport' content='width=device-width, initial-scale=1.0'>");
            sb.AppendLine("<title>Security Vulnerability Scan Report</title>");
            sb.AppendLine("<style>");
            sb.AppendLine(@"
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
                h2 { color: #34495e; margin-top: 30px; }
                .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
                .summary-card { background: #ecf0f1; padding: 15px; border-radius: 6px; border-left: 4px solid #3498db; }
                .summary-card h3 { margin: 0 0 10px 0; color: #2c3e50; }
                .vulnerability { margin: 20px 0; padding: 15px; border-radius: 6px; border-left: 4px solid; }
                .critical { background-color: #fdf2f2; border-left-color: #e74c3c; }
                .high { background-color: #fef9e7; border-left-color: #f39c12; }
                .medium { background-color: #f0f9ff; border-left-color: #3498db; }
                .low { background-color: #f0fff4; border-left-color: #27ae60; }
                .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
                .severity { font-weight: bold; padding: 4px 8px; border-radius: 4px; color: white; font-size: 12px; }
                .severity.critical { background-color: #e74c3c; }
                .severity.high { background-color: #f39c12; }
                .severity.medium { background-color: #3498db; }
                .severity.low { background-color: #27ae60; }
                .file-path { font-family: monospace; color: #7f8c8d; }
                .code-snippet { background-color: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 4px; font-family: monospace; overflow-x: auto; margin: 10px 0; }
                .context { background-color: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px; margin: 10px 0; overflow-x: auto; }
                .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
                .stat-item { text-align: center; padding: 10px; background: white; border: 1px solid #ddd; border-radius: 4px; }
                .stat-number { font-size: 24px; font-weight: bold; color: #3498db; }
                .stat-label { font-size: 12px; color: #7f8c8d; text-transform: uppercase; }
            ");
            sb.AppendLine("</style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");
            sb.AppendLine("<div class='container'>");
            
            // Header
            sb.AppendLine("<h1>🛡️ Security Vulnerability Scan Report</h1>");
            
            // Summary section
            sb.AppendLine("<div class='summary'>");
            sb.AppendLine("<div class='summary-card'>");
            sb.AppendLine("<h3>📊 Scan Overview</h3>");
            sb.AppendLine($"<p><strong>Scan Date:</strong> {result.ScanDate:yyyy-MM-dd HH:mm:ss}</p>");
            sb.AppendLine($"<p><strong>Project Path:</strong> {result.ProjectPath}</p>");
            sb.AppendLine($"<p><strong>Duration:</strong> {result.ScanDuration.TotalSeconds:F2} seconds</p>");
            sb.AppendLine($"<p><strong>Files Scanned:</strong> {result.TotalFilesScanned}</p>");
            sb.AppendLine($"<p><strong>Total Vulnerabilities:</strong> {result.TotalVulnerabilities}</p>");
            sb.AppendLine("</div>");
            
            sb.AppendLine("<div class='summary-card'>");
            sb.AppendLine("<h3>🚨 By Severity</h3>");
            sb.AppendLine("<div class='stats-grid'>");
            foreach (var severity in result.VulnerabilitiesBySeverity)
            {
                sb.AppendLine("<div class='stat-item'>");
                sb.AppendLine($"<div class='stat-number'>{severity.Value}</div>");
                sb.AppendLine($"<div class='stat-label'>{severity.Key}</div>");
                sb.AppendLine("</div>");
            }
            sb.AppendLine("</div>");
            sb.AppendLine("</div>");
            sb.AppendLine("</div>");

            // Vulnerabilities by category
            if (result.VulnerabilitiesByCategory.Any())
            {
                sb.AppendLine("<h2>📋 Vulnerabilities by Category</h2>");
                foreach (var category in result.VulnerabilitiesByCategory.OrderByDescending(x => x.Value))
                {
                    sb.AppendLine($"<p><strong>{category.Key}:</strong> {category.Value}</p>");
                }
            }

            // Detailed vulnerabilities
            sb.AppendLine("<h2>🔍 Detailed Vulnerabilities</h2>");
            
            var groupedVulns = result.Vulnerabilities.GroupBy(v => v.Severity)
                .OrderBy(g => GetSeverityOrder(g.Key));

            foreach (var severityGroup in groupedVulns)
            {
                foreach (var vuln in severityGroup.OrderBy(v => v.FilePath).ThenBy(v => v.LineNumber))
                {
                    var cssClass = vuln.Severity.ToLower();
                    sb.AppendLine($"<div class='vulnerability {cssClass}'>");
                    sb.AppendLine("<div class='vuln-header'>");
                    sb.AppendLine($"<h3>{vuln.Category}</h3>");
                    sb.AppendLine($"<span class='severity {cssClass}'>{vuln.Severity}</span>");
                    sb.AppendLine("</div>");
                    sb.AppendLine($"<p class='file-path'>📁 {vuln.FilePath}:{vuln.LineNumber} ({vuln.Language})</p>");
                    sb.AppendLine($"<p><strong>CWE ID:</strong> {vuln.CweId}</p>");
                    sb.AppendLine($"<p><strong>Description:</strong> {vuln.Description}</p>");
                    sb.AppendLine($"<div class='code-snippet'>{System.Web.HttpUtility.HtmlEncode(vuln.CodeSnippet)}</div>");
                    sb.AppendLine($"<p><strong>💡 Recommendation:</strong> {vuln.Recommendation}</p>");
                    
                    if (!string.IsNullOrEmpty(vuln.ContextLines))
                    {
                        sb.AppendLine($"<div class='context'>{System.Web.HttpUtility.HtmlEncode(vuln.ContextLines)}</div>");
                    }
                    sb.AppendLine("</div>");
                }
            }
            
            sb.AppendLine("</div>");
            sb.AppendLine("</body>");
            sb.AppendLine("</html>");
            
            return sb.ToString();
        }

        private int GetSeverityOrder(string severity)
        {
            return severity.ToUpper() switch
            {
                "CRITICAL" => 0,
                "HIGH" => 1,
                "MEDIUM" => 2,
                "LOW" => 3,
                _ => 4
            };
        }
    }
}
