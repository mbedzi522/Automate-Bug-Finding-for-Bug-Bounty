"""
Core Bug Hunter class - Main orchestration engine
"""

import os
import sys
import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import modules
from reconnaissance import ReconModule
from vulnerability_scanner import VulnScanModule
from ai_analyzer import AIAnalyzer
from reporter import ReportGenerator
from utils import NetworkUtils, FileUtils

class BugHunter:
    """Main Bug Hunter orchestration class"""
    
    def __init__(self, config, args):
        """Initialize Bug Hunter"""
        self.config = config
        self.args = args
        self.logger = logging.getLogger(__name__)
        
        # Initialize modules
        self.recon = ReconModule(config)
        self.vuln_scanner = VulnScanModule(config)
        self.ai_analyzer = AIAnalyzer(config) if config.is_ai_enabled() else None
        self.reporter = ReportGenerator(config)
        
        # Utilities
        self.network_utils = NetworkUtils()
        self.file_utils = FileUtils()
        
        # Results storage
        self.results = {
            'targets': [],
            'reconnaissance': {},
            'vulnerabilities': {},
            'ai_analysis': {},
            'metadata': {
                'start_time': datetime.now().isoformat(),
                'tool_version': '1.0.0',
                'scan_id': self._generate_scan_id()
            }
        }
        
        self.logger.info("Bug Hunter initialized successfully")
    
    def _generate_scan_id(self) -> str:
        """Generate unique scan ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"bh_{timestamp}"
    
    def scan_target(self, target: str) -> Dict[str, Any]:
        """Scan a single target"""
        self.logger.info(f"Starting scan for target: {target}")
        
        # Validate target
        if not self._validate_target(target):
            raise ValueError(f"Invalid target: {target}")
        
        self.results['targets'].append(target)
        
        try:
            # Phase 1: Reconnaissance
            if self.args.recon_only or self.args.full_scan:
                self.logger.info("Starting reconnaissance phase...")
                recon_results = self.recon.scan(target)
                self.results['reconnaissance'][target] = recon_results
                self.logger.info(f"Reconnaissance completed. Found {len(recon_results.get('subdomains', []))} subdomains")
            
            # Phase 2: Vulnerability Scanning
            if self.args.vuln_scan or self.args.full_scan:
                self.logger.info("Starting vulnerability scanning phase...")
                vuln_results = self.vuln_scanner.scan(target, self.results['reconnaissance'].get(target, {}))
                self.results['vulnerabilities'][target] = vuln_results
                self.logger.info(f"Vulnerability scanning completed. Found {len(vuln_results.get('vulnerabilities', []))} potential issues")
            
            # Phase 3: AI Analysis
            if (self.args.ai_analysis or self.args.full_scan) and self.ai_analyzer:
                self.logger.info("Starting AI analysis phase...")
                ai_results = self.ai_analyzer.analyze(
                    target, 
                    self.results['reconnaissance'].get(target, {}),
                    self.results['vulnerabilities'].get(target, {})
                )
                self.results['ai_analysis'][target] = ai_results
                self.logger.info("AI analysis completed")
            
            self.results['metadata']['end_time'] = datetime.now().isoformat()
            self.logger.info(f"Scan completed for target: {target}")
            
        except Exception as e:
            self.logger.error(f"Error scanning target {target}: {str(e)}")
            raise
        
        return self.results
    
    def scan_from_file(self, file_path: str) -> Dict[str, Any]:
        """Scan multiple targets from file"""
        self.logger.info(f"Loading targets from file: {file_path}")
        
        try:
            targets = self.file_utils.read_targets_file(file_path)
            self.logger.info(f"Loaded {len(targets)} targets")
            
            if self.args.batch_mode:
                # Parallel scanning for batch mode
                return self._scan_targets_parallel(targets)
            else:
                # Sequential scanning
                return self._scan_targets_sequential(targets)
                
        except Exception as e:
            self.logger.error(f"Error scanning from file {file_path}: {str(e)}")
            raise
    
    def _scan_targets_sequential(self, targets: List[str]) -> Dict[str, Any]:
        """Scan targets sequentially"""
        for i, target in enumerate(targets, 1):
            self.logger.info(f"Scanning target {i}/{len(targets)}: {target}")
            try:
                self.scan_target(target)
            except Exception as e:
                self.logger.error(f"Failed to scan {target}: {str(e)}")
                continue
        
        return self.results
    
    def _scan_targets_parallel(self, targets: List[str]) -> Dict[str, Any]:
        """Scan targets in parallel"""
        max_workers = min(self.args.threads, len(targets))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_target = {
                executor.submit(self._scan_single_target_safe, target): target 
                for target in targets
            }
            
            # Process completed tasks
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    self.logger.info(f"Completed scan for {target}")
                except Exception as e:
                    self.logger.error(f"Failed to scan {target}: {str(e)}")
        
        return self.results
    
    def _scan_single_target_safe(self, target: str):
        """Safely scan a single target (for parallel execution)"""
        try:
            return self.scan_target(target)
        except Exception as e:
            self.logger.error(f"Error in parallel scan of {target}: {str(e)}")
            return None
    
    def _validate_target(self, target: str) -> bool:
        """Validate target format"""
        return self.network_utils.is_valid_target(target)
    
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate comprehensive report"""
        self.logger.info("Generating report...")
        
        try:
            report_path = self.reporter.generate(results, self.args.output_dir)
            self.logger.info(f"Report generated: {report_path}")
            return report_path
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            raise
    
    def save_results(self, output_file: str = None) -> str:
        """Save raw results to JSON file"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"bug_hunter_results_{timestamp}.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            self.logger.info(f"Results saved to: {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")
            raise
    
    def load_results(self, input_file: str):
        """Load results from JSON file"""
        try:
            with open(input_file, 'r') as f:
                self.results = json.load(f)
            
            self.logger.info(f"Results loaded from: {input_file}")
        except Exception as e:
            self.logger.error(f"Error loading results: {str(e)}")
            raise
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary"""
        summary = {
            'scan_id': self.results['metadata']['scan_id'],
            'targets_scanned': len(self.results['targets']),
            'total_subdomains': 0,
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'scan_duration': None
        }
        
        # Calculate totals
        for target in self.results['targets']:
            recon_data = self.results['reconnaissance'].get(target, {})
            vuln_data = self.results['vulnerabilities'].get(target, {})
            
            summary['total_subdomains'] += len(recon_data.get('subdomains', []))
            
            vulnerabilities = vuln_data.get('vulnerabilities', [])
            summary['total_vulnerabilities'] += len(vulnerabilities)
            
            # Count by severity
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'low').lower()
                if severity == 'critical':
                    summary['critical_vulnerabilities'] += 1
                elif severity == 'high':
                    summary['high_vulnerabilities'] += 1
                elif severity == 'medium':
                    summary['medium_vulnerabilities'] += 1
                else:
                    summary['low_vulnerabilities'] += 1
        
        # Calculate duration
        start_time = self.results['metadata'].get('start_time')
        end_time = self.results['metadata'].get('end_time')
        if start_time and end_time:
            start_dt = datetime.fromisoformat(start_time)
            end_dt = datetime.fromisoformat(end_time)
            duration = end_dt - start_dt
            summary['scan_duration'] = str(duration)
        
        return summary
    
    def print_summary(self):
        """Print scan summary to console"""
        summary = self.get_summary()
        
        print("\n" + "="*60)
        print("BUG HUNTER SCAN SUMMARY")
        print("="*60)
        print(f"Scan ID: {summary['scan_id']}")
        print(f"Targets Scanned: {summary['targets_scanned']}")
        print(f"Total Subdomains Found: {summary['total_subdomains']}")
        print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"  - Critical: {summary['critical_vulnerabilities']}")
        print(f"  - High: {summary['high_vulnerabilities']}")
        print(f"  - Medium: {summary['medium_vulnerabilities']}")
        print(f"  - Low: {summary['low_vulnerabilities']}")
        if summary['scan_duration']:
            print(f"Scan Duration: {summary['scan_duration']}")
        print("="*60)

