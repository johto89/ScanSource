using SecurityScanner.Services;
using SecurityScanner.Utils;
using System.CommandLine;

namespace SecurityScanner
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            // Configure command line interface
            var pathOption = new Option<string>(
                name: "--path",
                description: "Path to the source code directory to scan")
            {
                IsRequired = true
            };
            pathOption.AddAlias("-p");

            var formatOption = new Option<string>(
                name: "--format",
                description: "Output format (text, json, csv, html)",
                getDefaultValue: () => "text");
            formatOption.AddAlias("-f");

            var outputOption = new Option<string?>(
                name: "--output",
                description: "Output file path (if not specified, prints to console)",
                getDefaultValue: () => null);
            outputOption.AddAlias("-o");

            var languagesOption = new Option<string[]>(
                name: "--languages",
                description: "Languages to scan (e.g., csharp, java, php, python, javascript, all)",
                getDefaultValue: () => new[] { "all" });
            languagesOption.AddAlias("-l");

            var progressOption = new Option<bool>(
                name: "--progress",
                description: "Show scan progress",
                getDefaultValue: () => false);
            progressOption.AddAlias("--show-progress");

            var verboseOption = new Option<bool>(
                name: "--verbose",
                description: "Enable verbose output",
                getDefaultValue: () => false);
            verboseOption.AddAlias("-v");

            var patternsOption = new Option<string?>(
                name: "--patterns",
                description: "Path to JSON patterns file (default: patterns.json in current directory)",
                getDefaultValue: () => null);
            patternsOption.AddAlias("-db");

            var outputFormatsOption = new Option<string[]>(
                name: "--output-formats",
                description: "Output formats to generate (text, json, csv, html, all)",
                getDefaultValue: () => new[] { "text" });
            outputFormatsOption.AddAlias("-of");

            var rootCommand = new RootCommand("Security vulnerability scanner for source code")
            {
                pathOption,
                formatOption,
                outputOption,
                languagesOption,
                progressOption,
                verboseOption,
                patternsOption,
                outputFormatsOption
            };

            rootCommand.SetHandler(async (path, format, output, languages, showProgress, verbose, patterns, outputFormats) =>
            {
                try
                {
                    await ScanSourceCodeAsync(path, format, output, languages.ToList(), showProgress, verbose, patterns, outputFormats.ToList());
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error: {ex.Message}");
                    Console.ResetColor();
                    Environment.Exit(1);
                }
            }, pathOption, formatOption, outputOption, languagesOption, progressOption, verboseOption, patternsOption, outputFormatsOption);

            return await rootCommand.InvokeAsync(args);
        }

        static async Task ScanSourceCodeAsync(string path, string format, string? output, 
            List<string> languages, bool showProgress, bool verbose, string? patterns, List<string> outputFormats)
        {
            Console.WriteLine("🛡️  Security Vulnerability Scanner");
            Console.WriteLine("====================================");
            Console.WriteLine($"📂 Scanning: {path}");
            Console.WriteLine($"🌐 Languages: {string.Join(", ", languages)}");
            Console.WriteLine($"📄 Format: {format}");
            if (!string.IsNullOrEmpty(output))
                Console.WriteLine($"💾 Output: {output}");
            
            // Handle patterns file
            string? patternsPath = patterns;
            if (string.IsNullOrEmpty(patternsPath))
            {
                var defaultPatternsPath = Path.Combine(Directory.GetCurrentDirectory(), "patterns.json");
                if (File.Exists(defaultPatternsPath))
                {
                    patternsPath = defaultPatternsPath;
                    Console.WriteLine($"📋 Using patterns: {patternsPath}");
                }
                else
                {
                    Console.WriteLine("📋 Using built-in patterns");
                }
            }
            else
            {
                Console.WriteLine($"📋 Using patterns: {patternsPath}");
            }

            if (outputFormats.Contains("all"))
            {
                Console.WriteLine($"📊 Output formats: text, json, csv, html");
            }
            else
            {
                Console.WriteLine($"📊 Output formats: {string.Join(", ", outputFormats)}");
            }
            Console.WriteLine();

            if (!Directory.Exists(path))
            {
                throw new DirectoryNotFoundException($"Directory not found: {path}");
            }

            var scanner = new FileScanner(showProgress, patternsPath);
            var reportGenerator = new ReportGenerator();

            var startTime = DateTime.Now;
            
            if (showProgress)
            {
                Console.WriteLine("🔍 Starting security scan...");
            }

            var result = await scanner.ScanDirectoryAsync(path, languages);
            
            if (showProgress)
            {
                Console.WriteLine();
                Console.WriteLine("📊 Generating report...");
            }

            // Generate filename if output is not specified but format is not text
            string? outputFile = output;
            if (string.IsNullOrEmpty(output) && format != "text")
            {
                var projectName = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar));
                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                outputFile = $"{projectName}_security_scan_{timestamp}.{format}";
            }

            // Generate reports in multiple formats if requested
            var formatsToGenerate = outputFormats.Contains("all") ? 
                new List<string> { "text", "json", "csv", "html" } : 
                outputFormats;

            foreach (var fmt in formatsToGenerate)
            {
                string? currentOutputFile = null;
                
                if (formatsToGenerate.Count > 1)
                {
                    // Multiple formats - generate filenames
                    var projectName = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar));
                    var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    currentOutputFile = $"{projectName}_security_scan_{timestamp}.{fmt}";
                }
                else if (!string.IsNullOrEmpty(output))
                {
                    currentOutputFile = output;
                }
                else if (fmt != "text")
                {
                    // Single non-text format without specified output
                    var projectName = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar));
                    var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    currentOutputFile = $"{projectName}_security_scan_{timestamp}.{fmt}";
                }

                await reportGenerator.GenerateReportAsync(result, fmt, currentOutputFile);
            }

            // Print summary to console regardless of output format
            Console.WriteLine();
            Console.WriteLine("✅ Scan Summary:");
            Console.WriteLine($"   Files scanned: {result.TotalFilesScanned}");
            Console.WriteLine($"   Total vulnerabilities: {result.TotalVulnerabilities}");
            Console.WriteLine($"   Scan duration: {result.ScanDuration.TotalSeconds:F2} seconds");
            
            if (result.TotalVulnerabilities > 0)
            {
                Console.WriteLine("   Severity breakdown:");
                foreach (var severity in result.VulnerabilitiesBySeverity.Where(x => x.Value > 0))
                {
                    var color = GetSeverityColor(severity.Key);
                    Console.ForegroundColor = color;
                    Console.WriteLine($"     {severity.Key}: {severity.Value}");
                    Console.ResetColor();
                }

                // Show top vulnerability categories
                var topCategories = result.VulnerabilitiesByCategory
                    .OrderByDescending(x => x.Value)
                    .Take(5);
                
                Console.WriteLine("   Top vulnerability categories:");
                foreach (var category in topCategories)
                {
                    Console.WriteLine($"     {category.Key}: {category.Value}");
                }
            }

            if (verbose && result.TotalVulnerabilities > 0)
            {
                Console.WriteLine();
                Console.WriteLine("🔍 File breakdown:");
                var fileGroups = result.Vulnerabilities
                    .GroupBy(v => v.FilePath)
                    .OrderByDescending(g => g.Count())
                    .Take(10);

                foreach (var fileGroup in fileGroups)
                {
                    Console.WriteLine($"   {fileGroup.Key}: {fileGroup.Count()} vulnerabilities");
                }
            }

            Console.WriteLine();
            
            if (result.TotalVulnerabilities > 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("⚠️  Security vulnerabilities found! Please review the detailed report.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("✅ No security vulnerabilities detected.");
            }
            Console.ResetColor();
        }

        static ConsoleColor GetSeverityColor(string severity)
        {
            return severity.ToUpper() switch
            {
                "CRITICAL" => ConsoleColor.Magenta,
                "HIGH" => ConsoleColor.Red,
                "MEDIUM" => ConsoleColor.Yellow,
                "LOW" => ConsoleColor.Green,
                _ => ConsoleColor.Gray
            };
        }
    }
}
