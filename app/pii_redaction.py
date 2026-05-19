# app/pii_redaction.py - Microsoft Presidio
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from typing import List, Dict, Tuple
import logging

logger = logging.getLogger(__name__)

class PIIRedactionService:
    """Microsoft Presidio-based PII redaction service"""
    
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        
        self.pii_entities = [
            "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
            "SSN", "US_DRIVER_LICENSE", "DATE_TIME", "LOCATION",
            "ORGANIZATION", "IP_ADDRESS", "URL", "MEDICAL_LICENSE",
            "PASSPORT_NUMBER", "BANK_ACCOUNT"
        ]
        
        logger.info("Microsoft Presidio PII Redaction Service initialized")
    
    async def detect_pii(self, text: str) -> List[Dict]:
        """Detect PII in text"""
        if not text or len(text) < 3:
            return []
        
        try:
            results = self.analyzer.analyze(
                text=text,
                entities=self.pii_entities,
                language="en",
                score_threshold=0.5
            )
            
            return [{
                "entity_type": r.entity_type,
                "start": r.start,
                "end": r.end,
                "confidence": r.score,
                "text": text[r.start:r.end]
            } for r in results]
        except Exception as e:
            logger.error(f"Presidio detection failed: {e}")
            return []
    
    async def redact_pii(self, text: str) -> Tuple[str, List[Dict]]:
        """Redact PII and return mapping"""
        if not text or len(text) < 3:
            return text, []
        
        try:
            analyzer_results = self.analyzer.analyze(
                text=text,
                entities=self.pii_entities,
                language="en"
            )
            
            if not analyzer_results:
                return text, []
            
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
            
            result = self.anonymizer.anonymize(
                text=text,
                analyzer_results=analyzer_results,
                operators=operators
            )
            
            mapping = []
            for i, (orig, redacted_item) in enumerate(zip(analyzer_results, result.items)):
                mapping.append({
                    "original": text[orig.start:orig.end],
                    "redacted": redacted_item.text,
                    "entity_type": orig.entity_type,
                })
            
            return result.text, mapping
        except Exception as e:
            logger.error(f"Presidio redaction failed: {e}")
            return text, []
    
    async def deanonymize(self, redacted_text: str, mapping: List[Dict]) -> str:
        """Restore original text"""
        if not mapping:
            return redacted_text
        
        result = redacted_text
        for item in sorted(mapping, key=lambda x: len(x["redacted"]), reverse=True):
            result = result.replace(item["redacted"], item["original"])
        return result