using System.Text.RegularExpressions;

namespace SecurityScanner.Models
{
    public class PatternConfig
    {
        public string Pattern { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string CweId { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Recommendation { get; set; } = string.Empty;
        public List<string> Languages { get; set; } = new();
        public RegexOptions RegexOptions { get; set; } = RegexOptions.IgnoreCase | RegexOptions.Multiline;
    }

    public class VulnerabilityPattern
    {
        public string Category { get; set; } = string.Empty;
        public List<PatternConfig> Patterns { get; set; } = new();
        public List<string> WhitelistPatterns { get; set; } = new();
    }
}
