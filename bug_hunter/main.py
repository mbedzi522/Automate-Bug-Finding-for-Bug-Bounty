#!/usr/bin/env python3
"""
Automated Bug Hunter Tool
A comprehensive tool for automated vulnerability discovery in bug bounty programs.
"""

import argparse
import sys
import os
import logging
from datetime import datetime
from pathlib import Path

# Add modules directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'modules'))

from core import BugHunter
from config.settings import Config

def setup_logging(log_level='INFO'):
    """Setup logging configuration"""
    log_dir = Path(__file__).parent / 'logs'
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = log_dir / f'bug_hunter_{timestamp}.log'
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger(__name__)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Automated Bug Hunter Tool for Bug Bounty Programs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -t example.com --full-scan
  python3 main.py -t example.com --recon-only
  python3 main.py -t example.com --ai-analysis
  python3 main.py -f targets.txt --batch-mode
        """
    )
    
    # Target specification
    parser.add_argument('-t', '--target', 
                       help='Target domain or IP address')
    parser.add_argument('-f', '--file', 
                       help='File containing list of targets')
    
    # Scan modes
    parser.add_argument('--full-scan', action='store_true',
                       help='Perform full automated scan (recon + vuln scan + AI analysis)')
    parser.add_argument('--recon-only', action='store_true',
                       help='Perform reconnaissance only')
    parser.add_argument('--vuln-scan', action='store_true',
                       help='Perform vulnerability scanning only')
    parser.add_argument('--ai-analysis', action='store_true',
                       help='Enable AI-powered analysis using Gemini API')
    
    # Configuration options
    parser.add_argument('--config', 
                       help='Path to configuration file')
    parser.add_argument('--output-dir', 
                       help='Output directory for reports')
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of threads for concurrent operations')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Timeout for network operations (seconds)')
    
    # Logging and debugging
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Set logging level')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    
    # Advanced options
    parser.add_argument('--batch-mode', action='store_true',
                       help='Run in batch mode (no interactive prompts)')
    parser.add_argument('--exclude-ports', 
                       help='Comma-separated list of ports to exclude')
    parser.add_argument('--custom-wordlist', 
                       help='Path to custom wordlist for directory enumeration')
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.log_level)
    
    # Validate arguments
    if not args.target and not args.file:
        parser.error("Either --target or --file must be specified")
    
    if not any([args.full_scan, args.recon_only, args.vuln_scan, args.ai_analysis]):
        args.full_scan = True  # Default to full scan
    
    try:
        # Initialize configuration
        config = Config(args.config)
        
        # Initialize bug hunter
        hunter = BugHunter(config, args)
        
        # Run the scan
        if args.target:
            logger.info(f"Starting scan for target: {args.target}")
            results = hunter.scan_target(args.target)
        elif args.file:
            logger.info(f"Starting batch scan from file: {args.file}")
            results = hunter.scan_from_file(args.file)
        
        # Generate report
        report_path = hunter.generate_report(results)
        logger.info(f"Scan completed. Report saved to: {report_path}")
        
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()

