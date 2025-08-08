"""
AI Analyzer Module - Gemini API integration for intelligent vulnerability analysis
"""

import json
import logging
import time
import requests
from typing import Dict, List, Any, Optional
import re

class AIAnalyzer:
    """AI-powered vulnerability analysis using Google Gemini API"""
    
    def __init__(self, config):
        """Initialize AI analyzer"""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Get Gemini configuration
        ai_config = config.get_gemini_config()
        self.api_key = ai_config.get('gemini_api_key', '')
        self.model = ai_config.get('model', 'gemini-pro')
        self.max_tokens = ai_config.get('max_tokens', 4096)
        self.temperature = ai_config.get('temperature', 0.3)
        
        # API endpoint
        self.api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        
        if not self.api_key:
            self.logger.warning("Gemini API key not provided. AI analysis will be disabled.")
    
    def analyze(self, target: str, recon_data: Dict[str, Any], vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive AI analysis"""
        self.logger.info(f"Starting AI analysis for {target}")
        
        if not self.api_key:
            return {'error': 'Gemini API key not configured'}
        
        results = {
            'target': target,
            'analysis_timestamp': time.time(),
            'vulnerability_prioritization': [],
            'false_positive_analysis': [],
            'attack_vectors': [],
            'remediation_suggestions': [],
            'risk_assessment': {},
            'custom_payloads': [],
            'code_analysis': {},
            'threat_intelligence': {}
        }
        
        try:
            # Vulnerability prioritization
            self.logger.info("Performing vulnerability prioritization...")
            results['vulnerability_prioritization'] = self._prioritize_vulnerabilities(vuln_data)
            
            # False positive detection
            self.logger.info("Analyzing for false positives...")
            results['false_positive_analysis'] = self._detect_false_positives(vuln_data)
            
            # Attack vector analysis
            self.logger.info("Analyzing attack vectors...")
            results['attack_vectors'] = self._analyze_attack_vectors(recon_data, vuln_data)
            
            # Remediation suggestions
            self.logger.info("Generating remediation suggestions...")
            results['remediation_suggestions'] = self._generate_remediation_suggestions(vuln_data)
            
            # Risk assessment
            self.logger.info("Performing risk assessment...")
            results['risk_assessment'] = self._perform_risk_assessment(target, recon_data, vuln_data)
            
            # Custom payload generation
            self.logger.info("Generating custom payloads...")
            results['custom_payloads'] = self._generate_custom_payloads(recon_data, vuln_data)
            
            # Code analysis (if applicable)
            self.logger.info("Performing code analysis...")
            results['code_analysis'] = self._analyze_code_patterns(recon_data, vuln_data)
            
            # Threat intelligence
            self.logger.info("Gathering threat intelligence...")
            results['threat_intelligence'] = self._gather_threat_intelligence(target, recon_data)
            
            self.logger.info("AI analysis completed successfully")
            
        except Exception as e:
            self.logger.error(f"Error during AI analysis: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _make_gemini_request(self, prompt: str, system_instruction: str = None) -> Optional[str]:
        """Make request to Gemini API"""
        try:
            headers = {
                'Content-Type': 'application/json',
            }
            
            # Prepare the request payload
            payload = {
                'contents': [{
                    'parts': [{
                        'text': prompt
                    }]
                }],
                'generationConfig': {
                    'temperature': self.temperature,
                    'maxOutputTokens': self.max_tokens,
                    'topP': 0.8,
                    'topK': 10
                }
            }
            
            # Add system instruction if provided
            if system_instruction:
                payload['systemInstruction'] = {
                    'parts': [{
                        'text': system_instruction
                    }]
                }
            
            # Make the request
            response = requests.post(
                f"{self.api_url}?key={self.api_key}",
                headers=headers,
                json=payload,
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'candidates' in result and len(result['candidates']) > 0:
                    content = result['candidates'][0].get('content', {})
                    parts = content.get('parts', [])
                    if parts:
                        return parts[0].get('text', '')
            else:
                self.logger.error(f"Gemini API error: {response.status_code} - {response.text}")
                
        except Exception as e:
            self.logger.error(f"Error making Gemini request: {str(e)}")
        
        return None
    
    def _prioritize_vulnerabilities(self, vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Use AI to prioritize vulnerabilities based on context and impact"""
        vulnerabilities = vuln_data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return []
        
        # Prepare vulnerability data for AI analysis
        vuln_summary = []
        for i, vuln in enumerate(vulnerabilities):
            vuln_summary.append({
                'id': i,
                'type': vuln.get('type', 'Unknown'),
                'severity': vuln.get('severity', 'Unknown'),
                'title': vuln.get('title', 'Unknown'),
                'description': vuln.get('description', '')[:200],  # Truncate for API limits
                'url': vuln.get('url', ''),
                'evidence': vuln.get('evidence', '')[:100]  # Truncate evidence
            })
        
        prompt = f"""
        As a cybersecurity expert, analyze the following vulnerabilities and prioritize them based on:
        1. Exploitability
        2. Business impact
        3. Attack complexity
        4. Data exposure risk
        5. Compliance implications
        
        Vulnerabilities to analyze:
        {json.dumps(vuln_summary, indent=2)}
        
        Please provide a prioritized list with:
        - Vulnerability ID
        - Priority score (1-10, 10 being highest)
        - Reasoning for the priority
        - Recommended action timeline (immediate, urgent, medium, low)
        
        Format your response as JSON.
        """
        
        system_instruction = """You are a senior cybersecurity analyst specializing in vulnerability assessment and risk prioritization. Provide practical, actionable analysis based on real-world threat landscapes."""
        
        response = self._make_gemini_request(prompt, system_instruction)
        
        if response:
            try:
                # Extract JSON from response
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    analysis = json.loads(json_match.group())
                    return analysis.get('prioritized_vulnerabilities', [])
            except json.JSONDecodeError:
                self.logger.error("Failed to parse AI prioritization response")
        
        return []
    
    def _detect_false_positives(self, vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Use AI to detect potential false positives"""
        vulnerabilities = vuln_data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return []
        
        # Focus on vulnerabilities that are commonly false positives
        suspicious_vulns = []
        for i, vuln in enumerate(vulnerabilities):
            if any(keyword in vuln.get('title', '').lower() for keyword in 
                   ['missing header', 'information disclosure', 'version disclosure']):
                suspicious_vulns.append({
                    'id': i,
                    'type': vuln.get('type', ''),
                    'title': vuln.get('title', ''),
                    'description': vuln.get('description', ''),
                    'evidence': vuln.get('evidence', '')[:200]
                })
        
        if not suspicious_vulns:
            return []
        
        prompt = f"""
        Analyze the following potential vulnerabilities for false positives. Consider:
        1. Whether the finding represents a real security risk
        2. If the evidence supports the vulnerability claim
        3. Common false positive patterns in automated scanners
        4. Context-specific factors that might make this a non-issue
        
        Vulnerabilities to analyze:
        {json.dumps(suspicious_vulns, indent=2)}
        
        For each vulnerability, provide:
        - Vulnerability ID
        - False positive probability (0-100%)
        - Reasoning
        - Recommended verification steps
        
        Format as JSON.
        """
        
        system_instruction = """You are an expert in vulnerability assessment and scanner accuracy. Help identify false positives to reduce noise in security reports."""
        
        response = self._make_gemini_request(prompt, system_instruction)
        
        if response:
            try:
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    analysis = json.loads(json_match.group())
                    return analysis.get('false_positive_analysis', [])
            except json.JSONDecodeError:
                self.logger.error("Failed to parse AI false positive analysis")
        
        return []
    
    def _analyze_attack_vectors(self, recon_data: Dict[str, Any], vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze potential attack vectors using AI"""
        
        # Combine recon and vulnerability data
        attack_surface = {
            'open_ports': recon_data.get('open_ports', []),
            'services': list(recon_data.get('services', {}).keys()),
            'technologies': recon_data.get('technologies', {}),
            'vulnerabilities': [v.get('type') for v in vuln_data.get('vulnerabilities', [])]
        }
        
        prompt = f"""
        Based on the following attack surface information, identify potential attack vectors and attack chains:
        
        Attack Surface:
        {json.dumps(attack_surface, indent=2)}
        
        Please provide:
        1. Primary attack vectors
        2. Potential attack chains (multi-step attacks)
        3. Privilege escalation opportunities
        4. Lateral movement possibilities
        5. Data exfiltration paths
        
        For each attack vector, include:
        - Attack method
        - Prerequisites
        - Difficulty level
        - Potential impact
        - Mitigation strategies
        
        Format as JSON.
        """
        
        system_instruction = """You are a penetration testing expert. Analyze attack surfaces to identify realistic attack scenarios that could be used in bug bounty hunting."""
        
        response = self._make_gemini_request(prompt, system_instruction)
        
        if response:
            try:
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    analysis = json.loads(json_match.group())
                    return analysis.get('attack_vectors', [])
            except json.JSONDecodeError:
                self.logger.error("Failed to parse AI attack vector analysis")
        
        return []
    
    def _generate_remediation_suggestions(self, vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate AI-powered remediation suggestions"""
        vulnerabilities = vuln_data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return []
        
        # Group vulnerabilities by type for more efficient analysis
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        remediation_suggestions = []
        
        for vuln_type, vulns in vuln_types.items():
            prompt = f"""
            Provide detailed remediation guidance for {vuln_type} vulnerabilities:
            
            Number of instances: {len(vulns)}
            Sample vulnerability details:
            {json.dumps(vulns[0], indent=2) if vulns else 'No details available'}
            
            Please provide:
            1. Immediate remediation steps
            2. Long-term security improvements
            3. Code examples (if applicable)
            4. Configuration changes needed
            5. Testing procedures to verify fixes
            6. Prevention strategies
            
            Format as JSON with clear, actionable steps.
            """
            
            system_instruction = """You are a senior security engineer providing remediation guidance. Focus on practical, implementable solutions."""
            
            response = self._make_gemini_request(prompt, system_instruction)
            
            if response:
                try:
                    json_match = re.search(r'\{.*\}', response, re.DOTALL)
                    if json_match:
                        remediation = json.loads(json_match.group())
                        remediation['vulnerability_type'] = vuln_type
                        remediation['affected_count'] = len(vulns)
                        remediation_suggestions.append(remediation)
                except json.JSONDecodeError:
                    self.logger.error(f"Failed to parse remediation for {vuln_type}")
        
        return remediation_suggestions
    
    def _perform_risk_assessment(self, target: str, recon_data: Dict[str, Any], vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive risk assessment using AI"""
        
        # Prepare risk context
        risk_context = {
            'target': target,
            'asset_exposure': {
                'subdomains': len(recon_data.get('subdomains', [])),
                'open_ports': len(recon_data.get('open_ports', [])),
                'web_services': len([s for s in recon_data.get('services', {}) if 'http' in s])
            },
            'vulnerability_summary': vuln_data.get('scan_summary', {}),
            'technologies': recon_data.get('technologies', {})
        }
        
        prompt = f"""
        Perform a comprehensive risk assessment for the target based on:
        
        Risk Context:
        {json.dumps(risk_context, indent=2)}
        
        Provide assessment including:
        1. Overall risk score (1-10)
        2. Risk factors breakdown
        3. Business impact analysis
        4. Compliance considerations
        5. Threat actor interest level
        6. Recommended security posture improvements
        7. Monitoring recommendations
        
        Consider factors like:
        - Attack surface size
        - Vulnerability severity distribution
        - Technology stack risks
        - Exposure level
        
        Format as JSON.
        """
        
        system_instruction = """You are a cybersecurity risk analyst. Provide comprehensive risk assessments that help organizations understand their security posture."""
        
        response = self._make_gemini_request(prompt, system_instruction)
        
        if response:
            try:
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
            except json.JSONDecodeError:
                self.logger.error("Failed to parse AI risk assessment")
        
        return {}
    
    def _generate_custom_payloads(self, recon_data: Dict[str, Any], vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate custom payloads based on target characteristics"""
        
        # Analyze target characteristics
        target_info = {
            'technologies': recon_data.get('technologies', {}),
            'services': list(recon_data.get('services', {}).keys()),
            'vulnerability_types': list(set(v.get('type') for v in vuln_data.get('vulnerabilities', [])))
        }
        
        prompt = f"""
        Generate custom security testing payloads based on the target characteristics:
        
        Target Information:
        {json.dumps(target_info, indent=2)}
        
        Generate payloads for:
        1. XSS testing (context-aware)
        2. SQL injection (database-specific)
        3. Command injection (OS-specific)
        4. Path traversal (technology-specific)
        5. Template injection (framework-specific)
        
        For each payload, provide:
        - Payload string
        - Target vulnerability type
        - Context/technology it targets
        - Expected behavior
        - Evasion techniques used
        
        Focus on payloads that are:
        - Evasive (bypass common filters)
        - Context-specific
        - Non-destructive for testing
        
        Format as JSON.
        """
        
        system_instruction = """You are a security researcher specializing in payload development. Create effective, non-destructive payloads for security testing."""
        
        response = self._make_gemini_request(prompt, system_instruction)
        
        if response:
            try:
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    analysis = json.loads(json_match.group())
                    return analysis.get('custom_payloads', [])
            except json.JSONDecodeError:
                self.logger.error("Failed to parse AI payload generation")
        
        return []
    
    def _analyze_code_patterns(self, recon_data: Dict[str, Any], vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze code patterns and suggest security improvements"""
        
        # Extract technology and framework information
        technologies = recon_data.get('technologies', {})
        
        prompt = f"""
        Based on the detected technologies and frameworks, analyze potential code-level security issues:
        
        Technologies Detected:
        {json.dumps(technologies, indent=2)}
        
        Provide analysis for:
        1. Common security anti-patterns for these technologies
        2. Framework-specific security configurations
        3. Secure coding recommendations
        4. Security testing strategies
        5. Code review focus areas
        
        Format as JSON with actionable recommendations.
        """
        
        system_instruction = """You are a secure code review expert. Provide technology-specific security guidance for developers."""
        
        response = self._make_gemini_request(prompt, system_instruction)
        
        if response:
            try:
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
            except json.JSONDecodeError:
                self.logger.error("Failed to parse AI code analysis")
        
        return {}
    
    def _gather_threat_intelligence(self, target: str, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Gather threat intelligence and context"""
        
        # Prepare intelligence context
        intel_context = {
            'target_domain': target,
            'technologies': recon_data.get('technologies', {}),
            'services': recon_data.get('services', {}),
            'ssl_info': recon_data.get('ssl_info', {})
        }
        
        prompt = f"""
        Provide threat intelligence analysis for the target:
        
        Target Context:
        {json.dumps(intel_context, indent=2)}
        
        Analyze:
        1. Industry-specific threats
        2. Technology-specific attack trends
        3. Common attack patterns for similar targets
        4. Threat actor TTPs relevant to this target
        5. Recent vulnerability trends for detected technologies
        6. Recommended threat hunting activities
        
        Provide actionable intelligence that helps understand the threat landscape.
        
        Format as JSON.
        """
        
        system_instruction = """You are a threat intelligence analyst. Provide contextual threat information to help understand the security landscape."""
        
        response = self._make_gemini_request(prompt, system_instruction)
        
        if response:
            try:
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
            except json.JSONDecodeError:
                self.logger.error("Failed to parse AI threat intelligence")
        
        return {}
    
    def generate_executive_summary(self, analysis_results: Dict[str, Any]) -> str:
        """Generate executive summary of the analysis"""
        
        prompt = f"""
        Create an executive summary of the security analysis results:
        
        Analysis Results:
        {json.dumps(analysis_results, indent=2)[:2000]}  # Truncate for API limits
        
        The summary should include:
        1. Key findings overview
        2. Critical risks identified
        3. Business impact assessment
        4. Priority recommendations
        5. Resource requirements for remediation
        
        Write for a technical executive audience. Be concise but comprehensive.
        """
        
        system_instruction = """You are a cybersecurity consultant writing for executive leadership. Focus on business impact and actionable recommendations."""
        
        response = self._make_gemini_request(prompt, system_instruction)
        
        return response if response else "Executive summary generation failed."

