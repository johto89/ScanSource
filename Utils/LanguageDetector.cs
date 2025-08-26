namespace SecurityScanner.Utils
{
    public class LanguageDetector
    {
        private static readonly Dictionary<string, string> LanguageExtensions = new()
        {
            { ".cs", "csharp" },
            { ".cshtml", "csharp" },
            { ".razor", "csharp" },
            { ".aspx", "csharp" },
            { ".vb", "vbnet" },
            { ".php", "php" },
            { ".phtml", "php" },
            { ".php3", "php" },
            { ".php4", "php" },
            { ".php5", "php" },
            { ".java", "java" },
            { ".jsp", "java" },
            { ".jspx", "java" },
            { ".kt", "kotlin" },
            { ".py", "python" },
            { ".pyw", "python" },
            { ".js", "javascript" },
            { ".jsx", "javascript" },
            { ".ts", "typescript" },
            { ".tsx", "typescript" },
            { ".rb", "ruby" },
            { ".erb", "ruby" },
            { ".go", "golang" },
            { ".swift", "swift" },
            { ".m", "objc" },
            { ".h", "objc" },
            { ".cpp", "cpp" },
            { ".cxx", "cpp" },
            { ".c", "c" },
            { ".html", "html" },
            { ".htm", "html" },
            { ".xml", "xml" },
            { ".config", "xml" },
            { ".json", "json" },
            { ".ps1", "powershell" },
            { ".psm1", "powershell" },
            { ".psd1", "powershell" }
        };

        public static string DetectLanguage(string filePath)
        {
            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            return LanguageExtensions.TryGetValue(extension, out var language) ? language : "unknown";
        }

        public static bool IsSupportedFile(string filePath)
        {
            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            return LanguageExtensions.ContainsKey(extension);
        }

        public static List<string> GetSupportedExtensions()
        {
            return LanguageExtensions.Keys.ToList();
        }
    }
}
