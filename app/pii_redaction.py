# app/pii_redaction.py
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from typing import List, Dict, Tuple
import re
import logging

logger = logging.getLogger(__name__)

class PIIRedactionService:
    """Microsoft Presidio-based PII redaction service"""
    
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        
        # PII entities to detect (GDPR/HIPAA compliance)
        self.pii_entities = [
            "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
            "SSN", "US_DRIVER_LICENSE", "DATE_TIME", "LOCATION",
            "ORGANIZATION", "IP_ADDRESS", "URL", "MEDICAL_LICENSE",
            "PASSPORT_NUMBER", "BANK_ACCOUNT"
        ]
        
        logger.info("Microsoft Presidio PII Redaction Service initialized")
    
    async def detect_pii(self, text: str) -> List[Dict]:
        """Detect PII in text using Presidio NLP"""
        if not text or len(text) < 3:
            return []
        
        try:
            results = self.analyzer.analyze(
                text=text,
                entities=self.pii_entities,
                language="en",
                score_threshold=0.5
            )
            
            detected = []
            for result in results:
                detected.append({
                    "entity_type": result.entity_type,
                    "start": result.start,
                    "end": result.end,
                    "confidence": result.score,
                    "text": text[result.start:result.end]
                })
            
            return detected
            
        except Exception as e:
            logger.error(f"Presidio detection failed: {e}")
            return []
    
    async def redact_pii(self, text: str) -> Tuple[str, List[Dict]]:
        """Redact PII and return mapping for deanonymization"""
        if not text or len(text) < 3:
            return text, []
        
        try:
            # Analyze for PII
            analyzer_results = self.analyzer.analyze(
                text=text,
                entities=self.pii_entities,
                language="en"
            )
            
            if not analyzer_results:
                return text, []
            
            # Operator config for different entity types
            operators = {
                "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"}),
                "PERSON": OperatorConfig("replace", {"new_value": "[PERSON]"}),
                "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "[EMAIL]"}),
                "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "[PHONE]"}),
                "CREDIT_CARD": OperatorConfig("replace", {"new_value": "[CREDIT_CARD]"}),
                "SSN": OperatorConfig("replace", {"new_value": "[SSN]"}),
                "LOCATION": OperatorConfig("replace", {"new_value": "[LOCATION]"}),
                "IP_ADDRESS": OperatorConfig("replace", {"new_value": "[IP]"}),
                "URL": OperatorConfig("replace", {"new_value": "[URL]"}),
            }
            
            # Anonymize
            result = self.anonymizer.anonymize(
                text=text,
                analyzer_results=analyzer_results,
                operators=operators
            )
            
            # Build mapping for deanonymization
            mapping = []
            for i, (orig, redacted_item) in enumerate(zip(analyzer_results, result.items)):
                mapping.append({
                    "original": text[orig.start:orig.end],
                    "redacted": redacted_item.text,
                    "entity_type": orig.entity_type,
                    "position": i
                })
            
            return result.text, mapping
            
        except Exception as e:
            logger.error(f"Presidio redaction failed: {e}")
            return text, []
    
    async def deanonymize(self, redacted_text: str, mapping: List[Dict]) -> str:
        """Restore original text from redacted version"""
        if not mapping:
            return redacted_text
        
        result = redacted_text
        # Sort by redacted text length (longest first) to avoid partial replacements
        for item in sorted(mapping, key=lambda x: len(x["redacted"]), reverse=True):
            result = result.replace(item["redacted"], item["original"])
        
        return result