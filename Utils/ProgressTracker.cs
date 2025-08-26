namespace SecurityScanner.Utils
{
    public class ProgressTracker
    {
        private readonly bool _showProgress;
        private int _totalFiles;
        private int _processedFiles;
        private readonly object _lock = new();

        public ProgressTracker(bool showProgress)
        {
            _showProgress = showProgress;
        }

        public void Initialize(int totalFiles)
        {
            _totalFiles = totalFiles;
            _processedFiles = 0;
            
            if (_showProgress)
            {
                Console.WriteLine($"Starting scan of {totalFiles} files...");
                Console.WriteLine();
            }
        }

        public void UpdateProgress(string currentFile)
        {
            if (!_showProgress) return;

            lock (_lock)
            {
                _processedFiles++;
                var percentage = (_processedFiles * 100) / _totalFiles;
                
                Console.Write($"\rProgress: {percentage:D3}% ({_processedFiles}/{_totalFiles}) - {Path.GetFileName(currentFile)}");
                
                if (_processedFiles == _totalFiles)
                {
                    Console.WriteLine();
                    Console.WriteLine("Scan completed!");
                }
            }
        }

        public void LogMessage(string message)
        {
            if (_showProgress)
            {
                Console.WriteLine();
                Console.WriteLine(message);
            }
        }
    }
}
