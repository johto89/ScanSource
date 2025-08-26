using SecurityScanner.Models;
using Newtonsoft.Json;
using System.Text.RegularExpressions;

namespace SecurityScanner.Services
{
    public class JsonPatternLoader
    {
        public Dictionary<string, VulnerabilityPattern> LoadPatternsFromJson(string jsonFilePath)
        {
            if (!File.Exists(jsonFilePath))
            {
                throw new FileNotFoundException($"Pattern file not found: {jsonFilePath}");
            }

            var jsonContent = File.ReadAllText(jsonFilePath);
            var database = JsonConvert.DeserializeObject<JsonPatternsDatabase>(jsonContent);

            if (database?.Patterns == null)
            {
                throw new InvalidOperationException($"Invalid pattern file format: {jsonFilePath}");
            }

            var patterns = new Dictionary<string, VulnerabilityPattern>();

            foreach (var jsonPattern in database.Patterns)
            {
                var vulnerabilityPattern = new VulnerabilityPattern
                {
                    Category = jsonPattern.Type,
                    WhitelistPatterns = jsonPattern.Whitelist
                };

                foreach (var pattern in jsonPattern.Patterns)
                {
                    var patternConfig = new PatternConfig
                    {
                        Pattern = pattern,
                        Severity = jsonPattern.Severity,
                        CweId = jsonPattern.CweId,
                        Description = $"{jsonPattern.Type} vulnerability pattern",
                        Recommendation = GetRecommendationForType(jsonPattern.Type),
                        Languages = ConvertFileExtensionsToLanguages(jsonPattern.FileExtensions),
                        RegexOptions = RegexOptions.IgnoreCase | RegexOptions.Multiline
                    };

                    vulnerabilityPattern.Patterns.Add(patternConfig);
                }

                patterns[jsonPattern.Type] = vulnerabilityPattern;
            }

            return patterns;
        }

        public bool IsFileExtensionSupported(string filePath, List<string> supportedExtensions)
        {
            var fileName = Path.GetFileName(filePath);
            var extension = Path.GetExtension(filePath).ToLowerInvariant();

            foreach (var supportedExt in supportedExtensions)
            {
                var pattern = supportedExt.Replace("*", "").ToLowerInvariant();
                if (extension == pattern)
                {
                    return true;
                }
            }

            return false;
        }

        private List<string> ConvertFileExtensionsToLanguages(List<string> fileExtensions)
        {
            var languages = new HashSet<string>();

            var extensionToLanguageMap = new Dictionary<string, string>
            {
                { "*.cs", "csharp" },
                { "*.cshtml", "csharp" },
                { "*.razor", "csharp" },
                { "*.aspx", "csharp" },
                { "*.vb", "vbnet" },
                { "*.php", "php" },
                { "*.phtml", "php" },
                { "*.php3", "php" },
                { "*.php4", "php" },
                { "*.php5", "php" },
                { "*.java", "java" },
                { "*.jsp", "java" },
                { "*.jspx", "java" },
                { "*.kt", "kotlin" },
                { "*.py", "python" },
                { "*.pyw", "python" },
                { "*.js", "javascript" },
                { "*.jsx", "javascript" },
                { "*.ts", "typescript" },
                { "*.tsx", "typescript" },
                { "*.rb", "ruby" },
                { "*.erb", "ruby" },
                { "*.go", "golang" },
                { "*.swift", "swift" },
                { "*.m", "objc" },
                { "*.mm", "objc" },
                { "*.h", "objc" },
                { "*.cpp", "cpp" },
                { "*.cxx", "cpp" },
                { "*.c", "c" },
                { "*.html", "html" },
                { "*.htm", "html" },
                { "*.xml", "xml" },
                { "*.config", "xml" },
                { "*.json", "json" },
                { "*.ps1", "powershell" },
                { "*.psm1", "powershell" },
                { "*.psd1", "powershell" },
                { "*.plist", "plist" },
                { "*.strings", "strings" },
                { "*.sql", "sql" },
                { "*.vue", "vue" },
                { "*.ejs", "ejs" },
                { "*.asp", "asp" }
            };

            foreach (var ext in fileExtensions)
            {
                if (extensionToLanguageMap.TryGetValue(ext.ToLowerInvariant(), out var language))
                {
                    languages.Add(language);
                }
            }

            return languages.Count > 0 ? languages.ToList() : new List<string> { "all" };
        }

        private string GetRecommendationForType(string type)
        {
            return type.ToLower() switch
            {
                var t when t.Contains("sql injection") => "Use parameterized queries and input validation",
                var t when t.Contains("xss") => "Encode output and validate input",
                var t when t.Contains("csrf") => "Implement CSRF tokens and same-origin checks",
                var t when t.Contains("path traversal") => "Validate and sanitize file paths",
                var t when t.Contains("open redirect") => "Validate redirect URLs against whitelist",
                var t when t.Contains("sensitive information") => "Remove hardcoded sensitive data",
                var t when t.Contains("network security") => "Use HTTPS and validate certificates",
                var t when t.Contains("powershell") => "Validate input and use safe PowerShell practices",
                var t when t.Contains("android") => "Follow Android security best practices",
                var t when t.Contains("ios") => "Follow iOS security best practices",
                _ => "Review code for security vulnerabilities and follow secure coding practices"
            };
        }

        public void SavePatternsToJson(Dictionary<string, VulnerabilityPattern> patterns, string jsonFilePath)
        {
            var database = new JsonPatternsDatabase();

            foreach (var pattern in patterns)
            {
                var jsonPattern = new JsonPatternConfig
                {
                    Type = pattern.Value.Category,
                    Whitelist = pattern.Value.WhitelistPatterns,
                    FileExtensions = new List<string>(),
                    Patterns = pattern.Value.Patterns.Select(p => p.Pattern).ToList(),
                    Severity = pattern.Value.Patterns.FirstOrDefault()?.Severity ?? "MEDIUM",
                    CweId = pattern.Value.Patterns.FirstOrDefault()?.CweId ?? ""
                };

                database.Patterns.Add(jsonPattern);
            }

            var jsonContent = JsonConvert.SerializeObject(database, Formatting.Indented);
            File.WriteAllText(jsonFilePath, jsonContent);
        }
    }
}