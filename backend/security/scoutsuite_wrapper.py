import subprocess

class ScoutSuiteWrapper:
    """Wrapper for ScoutSuite to run multi-cloud security audits programmatically."""
    
    def __init__(self, report_dir="./scoutsuite-report"):
        self.report_dir = report_dir

    def run_aws_audit(self, profile="default"):
        """Run ScoutSuite audit for AWS"""
        cmd = ["scout", "aws", "--profile", profile, "--report-dir", self.report_dir]
        return self._execute_command(cmd)

    def run_azure_audit(self):
        """Run ScoutSuite audit for Azure"""
        cmd = ["scout", "azure", "--report-dir", self.report_dir]
        return self._execute_command(cmd)
        
    def _execute_command(self, cmd):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return {"status": "success", "output": result.stdout}
        except subprocess.CalledProcessError as e:
            return {"status": "error", "error": e.stderr}
