#!/usr/bin/env python3
"""
Real Qwen2-7B Model - Final Version
No simulation allowed!
"""
import json
import time
import logging
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import os

logger = logging.getLogger(__name__)

# Global variables
_GLOBAL_MODEL = None
_GLOBAL_TOKENIZER = None
_MODEL_LOADED = False

class LLMInference:
    """Real model inference engine"""

    def __init__(self):
        global _GLOBAL_MODEL, _GLOBAL_TOKENIZER, _MODEL_LOADED

        if _MODEL_LOADED:
            print("[OK] Using already loaded model")
            self.model = _GLOBAL_MODEL
            self.tokenizer = _GLOBAL_TOKENIZER
            self.device = "cpu"
            return

        print("\n" + "="*70)
        print("[STARTUP] Starting Real Qwen2-7B Model Loading Process")
        print("="*70)

        self.model_path = "./models/Qwen2-7B"
        self.device = "cpu"

        # Force loading
        if not self._load_real_model():
            raise RuntimeError("[ERROR] Model loading failed! System cannot start!")

        _GLOBAL_MODEL = self.model
        _GLOBAL_TOKENIZER = self.tokenizer
        _MODEL_LOADED = True

        print("="*70)
        print("[SUCCESS] Model loading successful! System ready!")
        print("="*70 + "\n")

    def _load_real_model(self):
        """Force load real model"""
        try:
            start = time.time()

            # Check path
            if not os.path.exists(self.model_path):
                print(f"[ERROR] Path does not exist: {self.model_path}")
                return False

            print(f"[OK] Model path: {self.model_path}")

            # 1. Load Tokenizer
            print("\n[1/3] Loading Tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_path,
                trust_remote_code=True
            )

            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token

            print("      [OK] Tokenizer loaded")

            # 2. Load model
            print("\n[2/3] Loading model weights (estimated 1-3 minutes)...")
            print("      [WAIT] Please be patient...")

            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                trust_remote_code=True,
                torch_dtype=torch.float32,
                low_cpu_mem_usage=True
            )

            self.model = self.model.to('cpu')
            self.model.eval()

            print("      [OK] Model loaded")

            # 3. Verify inference
            print("\n[3/3] Verifying inference capability...")
            test_tokens = self.tokenizer.encode("test", return_tensors="pt")

            with torch.no_grad():
                self.model.generate(test_tokens, max_new_tokens=5)

            print("      [OK] Inference verified")

            elapsed = time.time() - start
            print(f"\n[TIME] Total time: {elapsed:.1f} seconds")

            return True

        except Exception as e:
            print(f"\n[ERROR] Loading failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def generate_response(self, prompt: str, max_new_tokens: int = 100, temperature: float = 0.7) -> str:
        """Generate response - only use real model"""
        global _MODEL_LOADED

        print("\n" + "="*70)
        print("[CALL] generate_response() called")
        print(f"   _MODEL_LOADED: {_MODEL_LOADED}")
        print(f"   self.model: {self.model is not None}")
        print(f"   self.tokenizer: {self.tokenizer is not None}")

        if not _MODEL_LOADED or self.model is None:
            print("   [ERROR] Model not loaded!")
            print("="*70)
            raise RuntimeError("Model not loaded! Rule simulation forbidden!")

        print("   [OK] Model status normal")
        print("="*70)

        try:
            start = time.time()
            print(f"[INFERENCE] Starting real model inference (max_new_tokens={max_new_tokens})...")

            # Encode
            inputs = self.tokenizer.encode(prompt, return_tensors="pt", truncation=True, max_length=512)
            inputs = inputs.to(self.device)

            # Inference
            with torch.no_grad():
                outputs = self.model.generate(
                    inputs,
                    max_new_tokens=max_new_tokens,
                    temperature=temperature,
                    do_sample=True,
                    pad_token_id=self.tokenizer.pad_token_id,
                    eos_token_id=self.tokenizer.eos_token_id
                )

            # Decode
            response = self.tokenizer.decode(outputs[0][inputs.shape[1]:], skip_special_tokens=True)

            elapsed = time.time() - start
            print(f"[OK] Real model inference completed")
            print(f"[TIME] Inference time: {elapsed:.2f} seconds")
            print("="*70)

            if elapsed < 0.5:
                print("[WARNING] Inference time unusually short! Might not be real model!")

            return response.strip()

        except Exception as e:
            print(f"[ERROR] Inference failed: {e}")
            import traceback
            traceback.print_exc()
            raise

# Global instance
_llm_instance = None

def get_llm_inference():
    """Get LLM instance"""
    global _llm_instance

    if _llm_instance is None:
        print("\n[INIT] Creating LLM instance for the first time...")
        _llm_instance = LLMInference()

    return _llm_instance

# Test function
if __name__ == "__main__":
    print("[TEST] Testing real model")
    print("="*70)

    llm = LLMInference()

    test_prompt = "Analyze SQL injection: ' OR '1'='1"
    print(f"\n[INPUT] Test input: {test_prompt}")

    result = llm.generate_response(test_prompt, max_new_tokens=50)

    print(f"\n[OUTPUT] Model output:")
    print(result)
    print("\n" + "="*70)
    print("[COMPLETE] Test finished")