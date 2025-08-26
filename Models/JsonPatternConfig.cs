using Newtonsoft.Json;

namespace SecurityScanner.Models
{
    public class JsonPatternConfig
    {
        [JsonProperty("type")]
        public string Type { get; set; } = string.Empty;

        [JsonProperty("fileExtensions")]
        public List<string> FileExtensions { get; set; } = new();

        [JsonProperty("patterns")]
        public List<string> Patterns { get; set; } = new();

        [JsonProperty("whitelist")]
        public List<string> Whitelist { get; set; } = new();

        [JsonProperty("severity")]
        public string Severity { get; set; } = "MEDIUM";

        [JsonProperty("cweId")]
        public string CweId { get; set; } = string.Empty;
    }

    public class JsonPatternsDatabase
    {
        [JsonProperty("patterns")]
        public List<JsonPatternConfig> Patterns { get; set; } = new();
    }
}