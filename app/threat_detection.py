# app/threat_detection.py
import re
import logging
from typing import Tuple, Dict, List, Optional

logger = logging.getLogger(__name__)

class ThreatDetectionService:
    """Prompt injection detection using Rebuff + heuristics"""
    
    def __init__(self):
        self.rebuff = None
        self.rebuff_available = False
        
        # Try to initialize Rebuff
        try:
            from rebuff import Rebuff
            self.rebuff = Rebuff()
            self.rebuff_available = True
            logger.info("✅ Rebuff ML detection initialized")
        except Exception as e:
            logger.warning(f"⚠️ Rebuff not available: {e}. Using heuristic detection only.")
        
        # Heuristic patterns for prompt injection (backup)
        self.injection_patterns = [
            # Instruction overriding
            (r"(?i)ignore (all )?(previous|above) (instructions|commands|rules)", "instruction_override", 0.9),
            (r"(?i)forget (all )?(previous|above) (instructions|prompts|rules)", "memory_override", 0.85),
            (r"(?i)disregard (previous|above) (instructions|prompts)", "instruction_override", 0.85),
            (r"(?i)do not follow (previous|above) (instructions|rules)", "instruction_override", 0.8),
            
            # DAN jailbreak and role play
            (r"(?i)you are now (DAN|Jailbreak|in developer mode)", "jailbreak", 0.95),
            (r"(?i)act as if (you are|your role is)", "role_play", 0.7),
            (r"(?i)pretend (you are|to be)", "role_play", 0.7),
            (r"(?i)from now on, you will be called", "role_play", 0.75),
            
            # Prompt leaking
            (r"(?i)show me (your )?(system prompt|instructions|initial prompt)", "prompt_leak", 0.8),
            (r"(?i)repeat (the )?instructions", "prompt_leak", 0.75),
            (r"(?i)what (are|is) (your|the) (system )?prompt", "prompt_leak", 0.8),
            (r"(?i)reveal your (system )?prompt", "prompt_leak", 0.85),
            
            # Encoding attacks
            (r"(?i)base64 decode", "encoding_attack", 0.6),
            (r"(?i)rot13", "encoding_attack", 0.6),
            (r"(?i)ceasar cipher", "encoding_attack", 0.6),
            
            # Bypass attempts
            (r"(?i)bypass (security|restrictions|filters|moderation)", "bypass_attempt", 0.85),
            (r"(?i)circumvent (security|safety|guidelines)", "bypass_attempt", 0.85),
            
            # Token smuggling
            (r"\|{3,}", "token_smuggling", 0.7),
            (r"&{3,}", "token_smuggling", 0.7),
            
            # SQL injection style
            (r"';.*--", "sql_injection", 0.6),
            (r"' OR '1'='1", "sql_injection", 0.7),
        ]
        
        # Suspicious patterns (lower confidence)
        self.suspicious_patterns = [
            (r"(?i)hack", "suspicious_hack", 0.4),
            (r"(?i)exploit", "suspicious_exploit", 0.4),
            (r"(?i)steal", "suspicious_steal", 0.4),
            (r"(?i)secret", "suspicious_secret", 0.3),
            (r"(?i)password", "suspicious_password", 0.3),
            (r"(?i)api[_-]?key", "suspicious_api_key", 0.3),
        ]
        
        logger.info("Threat detection service initialized")
    
    async def detect_prompt_injection(self, prompt: str) -> Tuple[bool, Dict]:
        """
        Detect prompt injection attacks using Rebuff + heuristics.
        
        Returns:
            Tuple[bool, Dict]: (is_malicious, threat_details)
        """
        if not prompt or len(prompt) < 5:
            return False, {"detected": False, "confidence": 0.0}
        
        threat_details = {
            "detected": False,
            "confidence": 0.0,
            "attack_types": [],
            "matched_patterns": [],
            "rebuff_result": None
        }
        
        # 1. Rebuff ML detection (if available)
        if self.rebuff_available:
            try:
                # Rebuff detection
                rebuff_result = self.rebuff.detect_injection(prompt)
                if rebuff_result and rebuff_result.get("is_injection", False):
                    threat_details["detected"] = True
                    threat_details["confidence"] = rebuff_result.get("confidence", 0.8)
                    threat_details["attack_types"].append("rebuff_ml")
                    threat_details["rebuff_result"] = rebuff_result
                    logger.info(f"🔴 Rebuff detected injection: {rebuff_result.get('confidence')}")
            except Exception as e:
                logger.warning(f"Rebuff detection failed: {e}")
        
        # 2. Heuristic pattern matching (always runs)
        for pattern, attack_type, confidence in self.injection_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                threat_details["detected"] = True
                threat_details["confidence"] = max(threat_details["confidence"], confidence)
                threat_details["attack_types"].append(attack_type)
                threat_details["matched_patterns"].append({
                    "pattern": pattern[:50],
                    "attack_type": attack_type,
                    "confidence": confidence
                })
                logger.info(f"⚠️ Heuristic match: {attack_type} (confidence: {confidence})")
        
        # 3. Check suspicious patterns (lower confidence)
        for pattern, attack_type, confidence in self.suspicious_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                if attack_type not in threat_details["attack_types"]:
                    threat_details["attack_types"].append(attack_type)
                    threat_details["confidence"] = max(threat_details["confidence"], confidence)
        
        return threat_details["detected"], threat_details
    
    async def check_response_safety(self, response: str) -> Tuple[bool, List[str]]:
        """
        Check if LLM response is safe (no malicious content).
        
        Returns:
            Tuple[bool, List[str]]: (is_unsafe, violations)
        """
        if not response:
            return False, []
        
        unsafe_patterns = [
            (r"(?i)how to (build|make|create) (a )?bomb", "weapon_instructions"),
            (r"(?i)how to (hack|compromise|crack)", "hacking_instructions"),
            (r"(?i)how to (steal|fraud|scam)", "fraud_instructions"),
            (r"(?i)bypass (security|authentication|firewall)", "security_bypass"),
            (r"rm -rf /", "destructive_command"),
            (r"format\s+[a-z]:", "destructive_command"),
            (r"(?i)drop database", "sql_destruction"),
            (r"(?i)delete from", "sql_destruction"),
            (r"(?i)exec\(.*\)", "code_injection"),
            (r"(?i)eval\(.*\)", "code_injection"),
        ]
        
        violations = []
        for pattern, violation_type in unsafe_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                violations.append(violation_type)
                logger.warning(f"🔴 Unsafe response content: {violation_type}")
        
        return len(violations) > 0, violations
    
    async def generate_canary_token(self) -> str:
        """Generate a canary token for Rebuff (to detect prompt leaks)"""
        if self.rebuff_available:
            try:
                return self.rebuff.generate_canary_token()
            except:
                pass
        return None