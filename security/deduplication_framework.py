#!/usr/bin/env python3
"""
Framework for deduplicating candidate security findings.

This script implements the logic to:
1. Identify unique combinations of file path and line number
2. Determine if findings represent real security issues
3. Handle duplicate categorizations across OWASP categories
4. Focus on actual security issues rather than duplicate categorizations
"""

import json
from collections import defaultdict
from typing import List, Dict, Any, Tuple


class FindingDeduplicator:
    """
    Class to handle deduplication of security findings.
    """
    
    def __init__(self):
        self.deduplication_rules = {
            'file_line_combination': self._deduplicate_by_file_and_line,
            'owasp_category_overlap': self._handle_owasp_overlaps,
            'pattern_similarity': self._deduplicate_by_pattern_similarity
        }
    
    def _deduplicate_by_file_and_line(self, findings: List[Dict]) -> List[Dict]:
        """
        Remove duplicate findings based on file path and line number combinations.
        
        Args:
            findings: List of candidate findings
            
        Returns:
            List of deduplicated findings
        """
        seen_combinations = set()
        unique_findings = []
        
        for finding in findings:
            file_path = finding.get('file', '')
            line_number = finding.get('line', None)
            
            # Create a unique identifier for the file-line combination
            key = (file_path, line_number)
            
            if key not in seen_combinations:
                seen_combinations.add(key)
                unique_findings.append(finding)
                
        return unique_findings
    
    def _handle_owasp_overlaps(self, findings: List[Dict]) -> List[Dict]:
        """
        Handle cases where the same underlying issue appears in multiple OWASP categories.
        Focus on identifying the actual security issue rather than duplicate categorizations.
        
        Args:
            findings: List of candidate findings
            
        Returns:
            List of findings with OWASP overlaps handled
        """
        # Group findings by their core security issue (based on file and line)
        grouped_findings = defaultdict(list)
        
        for finding in findings:
            file_path = finding.get('file', '')
            line_number = finding.get('line', None)
            
            # Use file and line as the key for grouping similar issues
            key = (file_path, line_number)
            grouped_findings[key].append(finding)
        
        # For each group, keep only one finding (preferably with the most specific OWASP category)
        final_findings = []
        for key, group in grouped_findings.items():
            # Sort by OWASP category priority or complexity
            # For now, we'll take the first one, but in practice you'd want more sophisticated logic
            final_findings.append(group[0])
            
        return final_findings
    
    def _deduplicate_by_pattern_similarity(self, findings: List[Dict]) -> List[Dict]:
        """
        Remove findings that are essentially the same issue expressed differently.
        
        Args:
            findings: List of candidate findings
            
        Returns:
            List of deduplicated findings
        """
        # This would implement more advanced pattern matching
        # For now, we'll rely on file-line combinations which are more reliable
        
        # Since we're focusing on file-line combinations as primary deduplication criteria,
        # we'll defer to the other methods
        return findings
    
    def deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Main method to deduplicate findings according to our strategy.
        
        Args:
            findings: List of candidate findings
            
        Returns:
            List of deduplicated findings representing actual security issues
        """
        # Step 1: Remove exact duplicates based on file and line
        step1 = self._deduplicate_by_file_and_line(findings)
        
        # Step 2: Handle OWASP category overlaps
        step2 = self._handle_owasp_overlaps(step1)
        
        # Step 3: Apply pattern similarity deduplication
        step3 = self._deduplicate_by_pattern_similarity(step2)
        
        return step3
    
    def analyze_security_issue(self, finding: Dict) -> Dict[str, Any]:
        """
        Analyze a finding to determine if it represents a real security issue.
        
        Args:
            finding: Single candidate finding
            
        Returns:
            Analysis result with security issue assessment
        """
        # Extract key components
        file_path = finding.get('file', '')
        line_number = finding.get('line', None)
        pattern = finding.get('pattern', '')
        vulnerability_class = finding.get('vulnerability_class', '')
        description = finding.get('description', '')
        
        # Basic heuristics to determine if this is a real security issue
        is_real_issue = self._is_real_security_issue(finding)
        
        return {
            'file': file_path,
            'line': line_number,
            'pattern': pattern,
            'vulnerability_class': vulnerability_class,
            'description': description,
            'is_real_security_issue': is_real_issue,
            'analysis_notes': self._generate_analysis_notes(finding)
        }
    
    def _is_real_security_issue(self, finding: Dict) -> bool:
        """
        Heuristic to determine if a finding represents a real security issue.
        
        Args:
            finding: Single candidate finding
            
        Returns:
            Boolean indicating if it's a real security issue
        """
        # Common indicators of real security issues:
        # 1. Missing authorization checks
        # 2. Injection vulnerabilities
        # 3. Cryptographic failures
        # 4. Configuration issues that could lead to exploitation
        
        pattern = finding.get('pattern', '').lower()
        vulnerability_class = finding.get('vulnerability_class', '').lower()
        description = finding.get('description', '').lower()
        
        # Keywords that typically indicate real security issues
        security_indicators = [
            'missing authorization',
            'authorization',
            'access control',
            'id or',
            'injection',
            'sql',
            'command',
            'xss',
            'csrf',
            'session',
            'jwt',
            'crypto',
            'encryption',
            'hash',
            'secret',
            'hardcoded',
            'debug',
            'cors',
            'cookie',
            'ssl',
            'tls',
            'deserialization',
            'unvalidated',
            'unauthorized',
            'privilege',
            'escalation'
        ]
        
        # Check if any security indicators are present
        for indicator in security_indicators:
            if indicator in pattern or indicator in vulnerability_class or indicator in description:
                return True
                
        # If it's in a security-sensitive area of code, consider it more seriously
        sensitive_paths = ['controller', 'auth', 'security', 'middleware', 'filter']
        file_path = finding.get('file', '').lower()
        
        for path in sensitive_paths:
            if path in file_path:
                return True
                
        return False
    
    def _generate_analysis_notes(self, finding: Dict) -> str:
        """
        Generate notes about the finding analysis.
        
        Args:
            finding: Single candidate finding
            
        Returns:
            String with analysis notes
        """
        file_path = finding.get('file', '')
        line_number = finding.get('line', None)
        vulnerability_class = finding.get('vulnerability_class', '')
        description = finding.get('description', '')
        
        notes = []
        
        # Add basic info
        notes.append(f"File: {file_path}")
        if line_number:
            notes.append(f"Line: {line_number}")
        notes.append(f"Vulnerability Class: {vulnerability_class}")
        
        # Add security assessment
        if self._is_real_security_issue(finding):
            notes.append("✓ This appears to be a real security issue")
        else:
            notes.append("✗ This appears to be a false positive or non-security issue")
            
        # Add description if available
        if description:
            notes.append(f"Description: {description[:100]}...")
            
        return "; ".join(notes)


def main():
    """
    Demonstration of the deduplication framework.
    """
    # Sample findings data (simulated)
    sample_findings = [
        {
            "file": "/src/Controllers/UserController.cs",
            "line": 42,
            "pattern": "User can access any user's data without authorization",
            "vulnerability_class": "A01 Broken Access Control",
            "description": "Missing authorization check allows users to view other users' data",
            "source": "sast"
        },
        {
            "file": "/src/Controllers/UserController.cs",
            "line": 42,
            "pattern": "User can access any user's data without authorization",
            "vulnerability_class": "A05 Security Misconfiguration",
            "description": "Missing authorization check allows users to view other users' data",
            "source": "sast"
        },
        {
            "file": "/src/Controllers/AdminController.cs",
            "line": 15,
            "pattern": "Admin endpoint accessible without proper authentication",
            "vulnerability_class": "A01 Broken Access Control",
            "description": "Admin endpoint lacks proper authentication",
            "source": "sast"
        },
        {
            "file": "/src/Models/User.cs",
            "line": 88,
            "pattern": "Hardcoded secret key in configuration",
            "vulnerability_class": "A02 Cryptographic Failures",
            "description": "Hardcoded secret key in application configuration",
            "source": "sast"
        },
        {
            "file": "/src/Models/User.cs",
            "line": 88,
            "pattern": "Hardcoded secret key in configuration",
            "vulnerability_class": "A07 Identification & Auth Failures",
            "description": "Hardcoded secret key in application configuration",
            "source": "sast"
        },
        {
            "file": "/src/Services/UserService.cs",
            "line": 33,
            "pattern": "SQL injection vulnerability in user query",
            "vulnerability_class": "A03 Injection",
            "description": "Direct concatenation of user input in SQL query",
            "source": "sast"
        }
    ]
    
    # Initialize the deduplicator
    deduplicator = FindingDeduplicator()
    
    print("=== Security Finding Deduplication Framework ===\n")
    
    print("Original findings:")
    for i, finding in enumerate(sample_findings, 1):
        print(f"{i}. {finding['file']}:{finding['line']} - {finding['vulnerability_class']}")
        print(f"   Pattern: {finding['pattern'][:50]}...")
        print()
    
    # Deduplicate findings
    deduplicated_findings = deduplicator.deduplicate_findings(sample_findings)
    
    print("After deduplication (by file and line):")
    for i, finding in enumerate(deduplicated_findings, 1):
        print(f"{i}. {finding['file']}:{finding['line']} - {finding['vulnerability_class']}")
        print(f"   Pattern: {finding['pattern'][:50]}...")
        print()
    
    print("Detailed analysis of each finding:")
    for i, finding in enumerate(deduplicated_findings, 1):
        analysis = deduplicator.analyze_security_issue(finding)
        print(f"\nFinding {i}:")
        print(f"  File: {analysis['file']}")
        print(f"  Line: {analysis['line']}")
        print(f"  Vulnerability Class: {analysis['vulnerability_class']}")
        print(f"  Is Real Issue: {analysis['is_real_security_issue']}")
        print(f"  Analysis: {analysis['analysis_notes']}")


if __name__ == "__main__":
    main()