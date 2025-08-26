using SecurityScanner.Models;
using SecurityScanner.Utils;
using System.Text.RegularExpressions;

namespace SecurityScanner.Services
{
    public class FileScanner
    {
        private readonly VulnerabilityPatterns? _patterns;
        private readonly JsonPatternLoader _jsonPatternLoader;
        private readonly List<string> _safePatterns;
        private readonly ProgressTracker _progressTracker;
        private readonly string? _jsonPatternsPath;

        public FileScanner(bool showProgress = false, string? jsonPatternsPath = null)
        {
            _jsonPatternLoader = new JsonPatternLoader();
            _jsonPatternsPath = jsonPatternsPath;
            
            if (string.IsNullOrEmpty(jsonPatternsPath))
            {
                _patterns = new VulnerabilityPatterns();
                _safePatterns = _patterns.GetSafePatterns();
            }
            else
            {
                _patterns = null;
                _safePatterns = GetDefaultSafePatterns();
            }
            
            _progressTracker = new ProgressTracker(showProgress);
        }

        public async Task<ScanResult> ScanDirectoryAsync(string directoryPath, List<string>? includeLanguages = null)
        {
            var startTime = DateTime.Now;
            var result = new ScanResult { ProjectPath = directoryPath };

            if (!Directory.Exists(directoryPath))
            {
                throw new DirectoryNotFoundException($"Directory not found: {directoryPath}");
            }

            var files = GetSupportedFiles(directoryPath);
            result.TotalFilesScanned = files.Count;
            
            _progressTracker.Initialize(files.Count);

            var allPatterns = GetAllPatterns();

            foreach (var file in files)
            {
                _progressTracker.UpdateProgress(file);
                
                var language = LanguageDetector.DetectLanguage(file);
                
                // Skip if language filtering is specified and this language is not included
                if (includeLanguages != null && includeLanguages.Count > 0 && 
                    !includeLanguages.Contains("all") && !includeLanguages.Contains(language))
                {
                    continue;
                }

                var vulnerabilities = await ScanFileAsync(file, allPatterns);
                result.Vulnerabilities.AddRange(vulnerabilities);
            }

            // Calculate statistics
            result.TotalVulnerabilities = result.Vulnerabilities.Count;
            result.ScanDuration = DateTime.Now - startTime;

            foreach (var vuln in result.Vulnerabilities)
            {
                result.VulnerabilitiesBySeverity[vuln.Severity]++;
                
                if (!result.VulnerabilitiesByCategory.ContainsKey(vuln.Category))
                    result.VulnerabilitiesByCategory[vuln.Category] = 0;
                result.VulnerabilitiesByCategory[vuln.Category]++;

                if (!result.VulnerabilitiesByLanguage.ContainsKey(vuln.Language))
                    result.VulnerabilitiesByLanguage[vuln.Language] = 0;
                result.VulnerabilitiesByLanguage[vuln.Language]++;
            }

            return result;
        }

        private async Task<List<Vulnerability>> ScanFileAsync(string filePath, Dictionary<string, VulnerabilityPattern> patterns)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            try
            {
                var content = await File.ReadAllTextAsync(filePath);
                var lines = await File.ReadAllLinesAsync(filePath);
                var language = LanguageDetector.DetectLanguage(filePath);
                var relativePath = GetRelativePath(filePath);

                foreach (var patternCategory in patterns)
                {
                    var categoryName = patternCategory.Key;
                    var patternConfig = patternCategory.Value;

                    foreach (var pattern in patternConfig.Patterns)
                    {
                        // Skip if language is not supported for this pattern
                        if (pattern.Languages.Count > 0 && !pattern.Languages.Contains("all") && 
                            !pattern.Languages.Contains(language))
                        {
                            continue;
                        }

                        var regex = new Regex(pattern.Pattern, pattern.RegexOptions);
                        var matches = regex.Matches(content);

                        foreach (Match match in matches)
                        {
                            var lineNumber = GetLineNumber(content, match.Index);
                            var codeSnippet = match.Value.Trim();
                            
                            // Check if this is a safe pattern
                            if (IsSafePattern(content, lines, lineNumber, patternConfig.WhitelistPatterns))
                            {
                                continue;
                            }

                            var contextLines = GetContextLines(lines, lineNumber - 1, 3);
                            
                            var vulnerability = new Vulnerability(
                                categoryName,
                                pattern.Severity,
                                relativePath,
                                lineNumber,
                                codeSnippet,
                                pattern.Description,
                                pattern.CweId,
                                pattern.Recommendation,
                                language,
                                contextLines
                            );

                            vulnerabilities.Add(vulnerability);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _progressTracker.LogMessage($"Error scanning file {filePath}: {ex.Message}");
            }

            return vulnerabilities;
        }

        private bool IsSafePattern(string content, string[] lines, int lineNumber, List<string> whitelistPatterns)
        {
            // Check current line and surrounding context for safe patterns
            var contextStart = Math.Max(0, lineNumber - 5);
            var contextEnd = Math.Min(lines.Length - 1, lineNumber + 5);
            
            var contextContent = string.Join("\n", lines[contextStart..contextEnd]);

            // Check whitelist patterns specific to the vulnerability category
            foreach (var safePattern in whitelistPatterns)
            {
                if (Regex.IsMatch(contextContent, safePattern, RegexOptions.IgnoreCase))
                {
                    return true;
                }
            }

            // Check global safe patterns
            foreach (var safePattern in _safePatterns)
            {
                if (Regex.IsMatch(contextContent, safePattern, RegexOptions.IgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private int GetLineNumber(string content, int index)
        {
            var lineNumber = 1;
            for (int i = 0; i < index && i < content.Length; i++)
            {
                if (content[i] == '\n')
                    lineNumber++;
            }
            return lineNumber;
        }

        private string GetContextLines(string[] lines, int lineIndex, int contextSize)
        {
            var start = Math.Max(0, lineIndex - contextSize);
            var end = Math.Min(lines.Length - 1, lineIndex + contextSize);
            
            var contextLines = new List<string>();
            for (int i = start; i <= end; i++)
            {
                var prefix = i == lineIndex ? ">>> " : "    ";
                contextLines.Add($"{prefix}{i + 1}: {lines[i]}");
            }
            
            return string.Join("\n", contextLines);
        }

        private List<string> GetSupportedFiles(string directoryPath)
        {
            var files = new List<string>();
            var supportedExtensions = LanguageDetector.GetSupportedExtensions();

            foreach (var extension in supportedExtensions)
            {
                var pattern = "*" + extension;
                files.AddRange(Directory.GetFiles(directoryPath, pattern, SearchOption.AllDirectories));
            }

            return files.Distinct().ToList();
        }

        private string GetRelativePath(string fullPath)
        {
            var currentDirectory = Directory.GetCurrentDirectory();
            if (fullPath.StartsWith(currentDirectory))
            {
                return fullPath[currentDirectory.Length..].TrimStart(Path.DirectorySeparatorChar);
            }
            return fullPath;
        }

        private Dictionary<string, VulnerabilityPattern> GetAllPatterns()
        {
            if (!string.IsNullOrEmpty(_jsonPatternsPath))
            {
                return _jsonPatternLoader.LoadPatternsFromJson(_jsonPatternsPath);
            }
            else if (_patterns != null)
            {
                return _patterns.GetAllPatterns();
            }
            else
            {
                return new Dictionary<string, VulnerabilityPattern>();
            }
        }

        private List<string> GetDefaultSafePatterns()
        {
            return new List<string>
            {
                // C#/.NET Safe Patterns
                @"\.Where\(.*UserId\s*==.*\)",
                @"\.Where\(.*OwnerId\s*==.*\)",
                @"\[Authorize\]",
                @"GetCurrentUserId\(\)",
                @"CheckOwnership\(",
                @"ValidateAccess\(",
                @"protector\.Protect\(",
                @"IDataProtector",
                @"Guid\.NewGuid\(\)",

                // PHP Safe Patterns
                @"session_id\(\)",
                @"\$_SESSION\[['""]user_id['""]\]",
                @"current_user_id\(\)",
                @"check_ownership\(",
                @"user_can_access\(",

                // Java Safe Patterns
                @"getCurrentUser\(\)",
                @"SecurityContextHolder\.getContext\(\)",
                @"@PreAuthorize",
                @"@Secured",
                @"hasRole\(",
                @"UUID\.randomUUID\(\)",

                // Python Safe Patterns
                @"request\.user\.id",
                @"current_user\.id",
                @"@login_required",
                @"@permission_required",
                @"user\.has_perm\(",

                // JavaScript/Node.js Safe Patterns
                @"req\.user\.id",
                @"passport\.authenticate",
                @"isAuthenticated\(",
                @"checkOwnership\(",
                @"uuid\.v4\(\)",

                // PowerShell Safe Patterns
                @"ValidateSet\(",
                @"Parameter\(Mandatory\=\$true\)",
                @"-ErrorAction\s+(Stop|SilentlyContinue)",
                @"Test-Path\s",
                @"if\s*\(\s*-not\s",
                @"try\s*\{.*catch",
                @"-WhatIf",
                @"-Confirm"
            };
        }

        private async Task<List<Vulnerability>> ScanFileWithExtensionFilter(string filePath, Dictionary<string, VulnerabilityPattern> patterns)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            try
            {
                var content = await File.ReadAllTextAsync(filePath);
                var lines = await File.ReadAllLinesAsync(filePath);
                var language = LanguageDetector.DetectLanguage(filePath);
                var relativePath = GetRelativePath(filePath);

                foreach (var patternCategory in patterns)
                {
                    var categoryName = patternCategory.Key;
                    var patternConfig = patternCategory.Value;

                    foreach (var pattern in patternConfig.Patterns)
                    {
                        // Check if file extension is supported for this pattern
                        if (!string.IsNullOrEmpty(_jsonPatternsPath))
                        {
                            // For JSON patterns, we need to check if the file extension matches
                            var jsonPatterns = _jsonPatternLoader.LoadPatternsFromJson(_jsonPatternsPath);
                            var jsonPattern = jsonPatterns.Values.FirstOrDefault(p => p.Category == categoryName);
                            
                            if (jsonPattern?.Patterns.Any() == true)
                            {
                                var firstPattern = jsonPattern.Patterns.First();
                                // This is a simplified check - in a full implementation, you'd want to store file extensions separately
                                var supportedExtensions = GetFileExtensionsForPattern(categoryName);
                                if (supportedExtensions.Any() && !_jsonPatternLoader.IsFileExtensionSupported(filePath, supportedExtensions))
                                {
                                    continue;
                                }
                            }
                        }

                        // Skip if language is not supported for this pattern
                        if (pattern.Languages.Count > 0 && !pattern.Languages.Contains("all") && 
                            !pattern.Languages.Contains(language))
                        {
                            continue;
                        }

                        var regex = new Regex(pattern.Pattern, pattern.RegexOptions);
                        var matches = regex.Matches(content);

                        foreach (Match match in matches)
                        {
                            var lineNumber = GetLineNumber(content, match.Index);
                            var codeSnippet = match.Value.Trim();
                            
                            // Check if this is a safe pattern
                            if (IsSafePattern(content, lines, lineNumber, patternConfig.WhitelistPatterns))
                            {
                                continue;
                            }

                            var contextLines = GetContextLines(lines, lineNumber - 1, 3);
                            
                            var vulnerability = new Vulnerability(
                                categoryName,
                                pattern.Severity,
                                relativePath,
                                lineNumber,
                                codeSnippet,
                                pattern.Description,
                                pattern.CweId,
                                pattern.Recommendation,
                                language,
                                contextLines
                            );

                            vulnerabilities.Add(vulnerability);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _progressTracker.LogMessage($"Error scanning file {filePath}: {ex.Message}");
            }

            return vulnerabilities;
        }

        private List<string> GetFileExtensionsForPattern(string categoryName)
        {
            // This is a mapping of category names to file extensions
            // In a full implementation, this would be loaded from the JSON patterns
            var extensionMap = new Dictionary<string, List<string>>
            {
                { "iOS Sensitive Information Exposure", new List<string> { "*.swift", "*.m", "*.mm", "*.h", "*.plist", "*.strings", "*.json", "*.xml" } },
                { "iOS Network Security", new List<string> { "*.swift", "*.m", "*.mm", "*.h", "*.plist", "*.xml" } },
                { "iOS URL Scheme Handling", new List<string> { "*.swift", "*.m", "*.mm", "*.h", "*.plist" } },
                { "iOS Data Storage", new List<string> { "*.swift", "*.m", "*.mm", "*.h" } },
                { "iOS WebView Security", new List<string> { "*.swift", "*.m", "*.mm", "*.h" } },
                { "iOS Runtime Manipulation", new List<string> { "*.swift", "*.m", "*.mm", "*.h" } },
                { "Android Intent and WebView", new List<string> { "*.java", "*.kt", "*.xml" } },
                { "Android Content Provider", new List<string> { "*.java", "*.kt", "*.xml" } },
                { "Android Component Export", new List<string> { "*.xml" } },
                { "PowerShell Execution", new List<string> { "*.ps1", "*.psm1", "*.psd1" } },
                { "PowerShell Input Validation", new List<string> { "*.ps1", "*.psm1", "*.psd1" } }
            };

            return extensionMap.TryGetValue(categoryName, out var extensions) ? extensions : new List<string>();
        }
    }
}
