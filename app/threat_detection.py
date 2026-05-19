# app/threat_detection.py - Rebuff + Heuristics
import re
import logging
from typing import Tuple, Dict, List

logger = logging.getLogger(__name__)

class ThreatDetectionService:
    """Prompt injection detection using Rebuff + heuristics"""
    
    def __init__(self):
        self.rebuff = None
        self.rebuff_available = False
        
        try:
            from rebuff import Rebuff
            self.rebuff = Rebuff()
            self.rebuff_available = True
            logger.info("✅ Rebuff ML detection initialized")
        except Exception as e:
            logger.warning(f"⚠️ Rebuff not available: {e}")
        
        self.injection_patterns = [
            (r"(?i)ignore (all )?(previous|above) (instructions|commands|rules)", "instruction_override", 0.9),
            (r"(?i)forget (all )?(previous|above) (instructions|prompts)", "memory_override", 0.85),
            (r"(?i)disregard (previous|above) (instructions|prompts)", "instruction_override", 0.85),
            (r"(?i)you are now (DAN|Jailbreak|in developer mode)", "jailbreak", 0.95),
            (r"(?i)act as if (you are|your role is)", "role_play", 0.7),
            (r"(?i)pretend (you are|to be)", "role_play", 0.7),
            (r"(?i)show me (your )?(system prompt|instructions)", "prompt_leak", 0.8),
            (r"(?i)repeat (the )?instructions", "prompt_leak", 0.75),
            (r"(?i)what (are|is) (your|the) (system )?prompt", "prompt_leak", 0.8),
            (r"(?i)base64 decode", "encoding_attack", 0.6),
            (r"(?i)bypass (security|restrictions|filters)", "bypass_attempt", 0.85),
        ]
        
        self.suspicious_patterns = [
            (r"(?i)hack", "suspicious_hack", 0.4),
            (r"(?i)exploit", "suspicious_exploit", 0.4),
            (r"(?i)steal", "suspicious_steal", 0.4),
        ]
    
    async def detect_prompt_injection(self, prompt: str) -> Tuple[bool, Dict]:
        """Detect prompt injection attacks"""
        if not prompt or len(prompt) < 5:
            return False, {"detected": False, "confidence": 0.0}
        
        threat_details = {
            "detected": False,
            "confidence": 0.0,
            "attack_types": [],
            "matched_patterns": []
        }
        
        if self.rebuff_available:
            try:
                rebuff_result = self.rebuff.detect_injection(prompt)
                if rebuff_result and rebuff_result.get("is_injection", False):
                    threat_details["detected"] = True
                    threat_details["confidence"] = rebuff_result.get("confidence", 0.8)
                    threat_details["attack_types"].append("rebuff_ml")
            except Exception as e:
                logger.warning(f"Rebuff failed: {e}")
        
        for pattern, attack_type, confidence in self.injection_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                threat_details["detected"] = True
                threat_details["confidence"] = max(threat_details["confidence"], confidence)
                threat_details["attack_types"].append(attack_type)
        
        return threat_details["detected"], threat_details
    
    async def check_response_safety(self, response: str) -> Tuple[bool, List[str]]:
        """Check if LLM response is safe"""
        unsafe_patterns = [
            (r"(?i)how to (build|make) (a )?bomb", "weapon_instructions"),
            (r"(?i)how to (hack|compromise)", "hacking_instructions"),
            (r"rm -rf /", "destructive_command"),
        ]
        
        violations = []
        for pattern, violation_type in unsafe_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                violations.append(violation_type)
        
        return len(violations) > 0, violations