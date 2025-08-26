namespace SecurityScanner.Models
{
    public class ScanResult
    {
        public DateTime ScanDate { get; set; }
        public string ProjectPath { get; set; } = string.Empty;
        public int TotalFilesScanned { get; set; }
        public int TotalVulnerabilities { get; set; }
        public Dictionary<string, int> VulnerabilitiesBySeverity { get; set; } = new();
        public Dictionary<string, int> VulnerabilitiesByCategory { get; set; } = new();
        public Dictionary<string, int> VulnerabilitiesByLanguage { get; set; } = new();
        public List<Vulnerability> Vulnerabilities { get; set; } = new();
        public TimeSpan ScanDuration { get; set; }

        public ScanResult()
        {
            ScanDate = DateTime.Now;
            VulnerabilitiesBySeverity = new Dictionary<string, int>
            {
                { "CRITICAL", 0 },
                { "HIGH", 0 },
                { "MEDIUM", 0 },
                { "LOW", 0 }
            };
        }
    }
}
