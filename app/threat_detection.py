# app/threat_detection.py - Fixed Rebuff initialization
import re
import logging
from typing import Tuple, Dict, List

logger = logging.getLogger(__name__)

class ThreatDetectionService:
    """Prompt injection detection using Rebuff (self-hosted) + heuristics"""
    
    def __init__(self):
        self.rebuff = None
        self.rebuff_available = False
        
        # Try to initialize Rebuff in self-hosted mode
        try:
            from rebuff import Rebuff
            # Self-hosted mode - no API token required
            self.rebuff = Rebuff(api_token="self-hosted")
            self.rebuff_available = True
            logger.info("✅ Rebuff ML detection initialized (self-hosted mode)")
        except Exception as e:
            logger.warning(f"⚠️ Rebuff not available: {e}. Using heuristic detection only.")
        
        # Heuristic patterns for prompt injection (backup)
        self.injection_patterns = [
            (r"(?i)ignore (all )?(previous|above) (instructions|commands|rules)", "instruction_override", 0.9),
            (r"(?i)forget (all )?(previous|above) (instructions|prompts|rules)", "memory_override", 0.85),
            (r"(?i)disregard (previous|above) (instructions|prompts)", "instruction_override", 0.85),
            (r"(?i)you are now (DAN|Jailbreak|in developer mode)", "jailbreak", 0.95),
            (r"(?i)act as if (you are|your role is)", "role_play", 0.7),
            (r"(?i)pretend (you are|to be)", "role_play", 0.7),
            (r"(?i)from now on, you will be called", "role_play", 0.75),
            (r"(?i)show me (your )?(system prompt|instructions|initial prompt)", "prompt_leak", 0.8),
            (r"(?i)repeat (the )?instructions", "prompt_leak", 0.75),
            (r"(?i)what (are|is) (your|the) (system )?prompt", "prompt_leak", 0.8),
            (r"(?i)reveal your (system )?prompt", "prompt_leak", 0.85),
            (r"(?i)base64 decode", "encoding_attack", 0.6),
            (r"(?i)rot13", "encoding_attack", 0.6),
            (r"(?i)bypass (security|restrictions|filters|moderation)", "bypass_attempt", 0.85),
            (r"(?i)circumvent (security|safety|guidelines)", "bypass_attempt", 0.85),
            (r"\|{3,}", "token_smuggling", 0.7),
            (r"&{3,}", "token_smuggling", 0.7),
        ]
        
        self.suspicious_patterns = [
            (r"(?i)hack", "suspicious_hack", 0.4),
            (r"(?i)exploit", "suspicious_exploit", 0.4),
            (r"(?i)steal", "suspicious_steal", 0.4),
            (r"(?i)secret", "suspicious_secret", 0.3),
            (r"(?i)password", "suspicious_password", 0.3),
        ]
        
        logger.info("Threat detection service initialized with 15+ heuristic patterns")
    
    async def detect_prompt_injection(self, prompt: str) -> Tuple[bool, Dict]:
        """Detect prompt injection attacks using heuristics (Rebuff optional)"""
        if not prompt or len(prompt) < 5:
            return False, {"detected": False, "confidence": 0.0}
        
        threat_details = {
            "detected": False,
            "confidence": 0.0,
            "attack_types": [],
            "matched_patterns": []
        }
        
        # Optional: Rebuff ML detection (if available)
        if self.rebuff_available:
            try:
                rebuff_result = self.rebuff.detect_injection(prompt)
                if rebuff_result and rebuff_result.get("is_injection", False):
                    threat_details["detected"] = True
                    threat_details["confidence"] = rebuff_result.get("confidence", 0.8)
                    threat_details["attack_types"].append("rebuff_ml")
                    logger.info(f"🔴 Rebuff detected injection: {rebuff_result.get('confidence')}")
            except Exception as e:
                logger.warning(f"Rebuff detection failed: {e}")
        
        # Heuristic pattern matching (always runs)
        for pattern, attack_type, confidence in self.injection_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                threat_details["detected"] = True
                threat_details["confidence"] = max(threat_details["confidence"], confidence)
                threat_details["attack_types"].append(attack_type)
                logger.info(f"⚠️ Heuristic match: {attack_type} (confidence: {confidence})")
        
        # Check suspicious patterns (lower confidence)
        for pattern, attack_type, confidence in self.suspicious_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                if attack_type not in threat_details["attack_types"]:
                    threat_details["attack_types"].append(attack_type)
                    threat_details["confidence"] = max(threat_details["confidence"], confidence)
        
        return threat_details["detected"], threat_details
    
    async def check_response_safety(self, response: str) -> Tuple[bool, List[str]]:
        """Check if LLM response is safe"""
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
        ]
        
        violations = []
        for pattern, violation_type in unsafe_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                violations.append(violation_type)
                logger.warning(f"🔴 Unsafe response content: {violation_type}")
        
        return len(violations) > 0, violations