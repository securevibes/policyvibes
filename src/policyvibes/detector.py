"""Main detector that orchestrates the scanning process."""

from pathlib import Path

from .models import ScanResult
from .patterns import PatternDetector


class PolicyVibesScanner:
    """Scans repositories for Anthropic ToS violations."""

    def __init__(self):
        """Initialize the scanner."""
        self.pattern_detector = PatternDetector()

    def scan(self, path: Path) -> ScanResult:
        """Scan a path (file or directory) for violations."""
        path = Path(path).resolve()

        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")

        result = ScanResult(repo_path=path)
        seen_findings = set()  # Deduplicate findings

        if path.is_file():
            for finding in self.pattern_detector.scan_file(path):
                key = (finding.file_path, finding.line_number, finding.pattern_type)
                if key not in seen_findings:
                    seen_findings.add(key)
                    result.findings.append(finding)
            result.files_scanned = 1
        else:
            files_scanned = 0
            for item in self._walk_directory(path):
                if item.is_file() and self.pattern_detector.should_scan_file(item):
                    files_scanned += 1
                    for finding in self.pattern_detector.scan_file(item):
                        key = (finding.file_path, finding.line_number, finding.pattern_type)
                        if key not in seen_findings:
                            seen_findings.add(key)
                            result.findings.append(finding)
            result.files_scanned = files_scanned

        # Sort findings by severity (active first) then by file path
        result.findings.sort(
            key=lambda f: (
                0 if f.severity.value == "ACTIVE_VIOLATION" else 1,
                str(f.file_path),
                f.line_number,
            )
        )

        return result

    def _walk_directory(self, path: Path):
        """Walk directory, respecting skip rules."""
        try:
            for item in path.iterdir():
                if item.is_dir():
                    if not self.pattern_detector.should_skip_dir(item):
                        yield from self._walk_directory(item)
                else:
                    yield item
        except PermissionError:
            pass
