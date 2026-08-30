#!/usr/bin/env python3
"""
GPU优化版 Qwen2-7B 模型推理
专为RTX 4070s 12G显卡优化
彻底解决emoji编码问题
"""

import os
import sys
import time
import json
import logging
import threading
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

os.environ['PYTHONIOENCODING'] = 'utf-8'
os.environ['PYTHONLEGACYWINDOWSSTDIO'] = '0'

logger = logging.getLogger(__name__)

_GLOBAL_MODEL = None
_GLOBAL_TOKENIZER = None
_GLOBAL_DEVICE = None
_MODEL_LOADED = False
_INFERENCE_LOCK = threading.Lock()


def _load_model_settings():
    """Read config/model_config.json when present; fall back to repo defaults."""
    defaults = {
        "model_path": "./models/Qwen2-7B",
        "trust_remote_code": True,
    }
    config_path = Path("config/model_config.json")
    if not config_path.is_file():
        return defaults
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        model_cfg = payload.get("model_config", payload)
        defaults["model_path"] = model_cfg.get("model_path", defaults["model_path"])
        defaults["trust_remote_code"] = bool(model_cfg.get("trust_remote_code", True))
        if defaults["trust_remote_code"]:
            logger.warning("trust_remote_code=True: loading custom model code from %s", defaults["model_path"])
        return defaults
    except Exception as exc:
        logger.warning("Failed to read model config, using defaults: %s", exc)
        return defaults


class GPULLMInference:
    """GPU优化版LLM推理引擎"""

    def __init__(self):
        global _GLOBAL_MODEL, _GLOBAL_TOKENIZER, _GLOBAL_DEVICE, _MODEL_LOADED

        settings = _load_model_settings()
        self.model_path = settings["model_path"]
        self.trust_remote_code = settings["trust_remote_code"]

        if _MODEL_LOADED:
            print("[GPU] 使用已加载的模型")
            self.model = _GLOBAL_MODEL
            self.tokenizer = _GLOBAL_TOKENIZER
            self.device = _GLOBAL_DEVICE or ("cuda" if torch.cuda.is_available() else "cpu")
            return

        print("\n" + "="*80)
        print("[GPU] 启动GPU优化版 Qwen2-7B 模型加载")
        print("[GPU] 专为RTX 4070s 12G显卡优化")
        print("="*80)

        # 检查GPU可用性
        if not torch.cuda.is_available():
            print("[ERROR] 未检测到CUDA支持！")
            print("[INFO] 将使用CPU模式（速度较慢）")
            self.device = "cpu"
        else:
            self.device = "cuda"
            gpu_name = torch.cuda.get_device_name(0)
            gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1024**3
            print(f"[GPU] 检测到: {gpu_name}")
            print(f"[GPU] 显存: {gpu_memory:.1f}GB")

            if gpu_memory < 10:
                print("[WARNING] 显存可能不足，建议释放其他GPU进程")

        # 强制加载模型
        if not self._load_model():
            raise RuntimeError("[FATAL] 模型加载失败！系统无法启动！")

        _GLOBAL_MODEL = self.model
        _GLOBAL_TOKENIZER = self.tokenizer
        _GLOBAL_DEVICE = self.device
        _MODEL_LOADED = True

        print("="*80)
        print("[SUCCESS] GPU优化版模型加载成功！")
        print("="*80 + "\n")

    def _load_model(self):
        """加载模型到GPU"""
        try:
            start_time = time.time()

            # 检查模型路径
            if not os.path.exists(self.model_path):
                print(f"[ERROR] 模型路径不存在: {self.model_path}")
                return False

            print(f"[OK] 模型路径: {self.model_path}")

            # 1. 加载Tokenizer
            print("\n[1/3] 加载Tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_path,
                trust_remote_code=self.trust_remote_code,
                use_fast=True
            )

            # 设置特殊token
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token

            print("      [OK] Tokenizer加载完成")

            # 2. 加载模型
            print("\n[2/3] 加载模型权重到GPU...")
            print("      [INFO] 预计需要1-3分钟，请耐心等待...")

            # GPU优化配置
            model_kwargs = {
                "trust_remote_code": self.trust_remote_code,
                "low_cpu_mem_usage": True,
                "device_map": "auto" if self.device == "cuda" else None,
            }

            # 根据显存大小选择精度
            if self.device == "cuda":
                gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1024**3
                if gpu_memory >= 14:
                    model_kwargs["torch_dtype"] = torch.float16
                    print("      [GPU] 使用半精度(float16)")
                elif gpu_memory >= 10:
                    model_kwargs["torch_dtype"] = torch.bfloat16
                    print("      [GPU] 使用bfloat16精度")
                else:
                    model_kwargs["torch_dtype"] = torch.float32
                    model_kwargs["load_in_8bit"] = True
                    print("      [GPU] 使用8位量化")
            else:
                model_kwargs["torch_dtype"] = torch.float32

            # 加载模型
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                **model_kwargs
            )

            # 确保模型在正确的设备上
            if self.device == "cuda" and not next(self.model.parameters()).is_cuda:
                self.model = self.model.cuda()

            self.model.eval()

            print("      [OK] 模型加载完成")

            # 3. 验证推理能力
            print("\n[3/3] 验证推理能力...")
            test_input = "测试"
            test_tokens = self.tokenizer.encode(test_input, return_tensors="pt")
            test_tokens = test_tokens.to(self.device)

            with torch.no_grad():
                outputs = self.model.generate(
                    test_tokens,
                    max_new_tokens=3,
                    pad_token_id=self.tokenizer.pad_token_id
                )

            print("      [OK] 推理验证通过")

            elapsed_time = time.time() - start_time
            print(f"\n[TIME] 总加载时间: {elapsed_time:.1f}秒")

            # 显示GPU内存使用情况
            if self.device == "cuda":
                memory_allocated = torch.cuda.memory_allocated() / 1024**3
                memory_reserved = torch.cuda.memory_reserved() / 1024**3
                print(f"[GPU] 已分配显存: {memory_allocated:.1f}GB")
                print(f"[GPU] 已预留显存: {memory_reserved:.1f}GB")

            return True

        except Exception as e:
            print(f"\n[ERROR] 模型加载失败: {e}")
            import traceback
            traceback.print_exc()
            return False

    def generate_response(self, prompt: str, max_new_tokens: int = 256, temperature: float = 0.7) -> str:
        """生成响应 - 强制使用真实模型"""
        global _MODEL_LOADED, _GLOBAL_DEVICE

        if not getattr(self, "device", None):
            self.device = _GLOBAL_DEVICE or ("cuda" if torch.cuda.is_available() else "cpu")

        print("\n" + "="*80)
        print("[GPU] 开始真实模型推理")
        print(f"[INFO] 模型已加载: {_MODEL_LOADED}")
        print(f"[INFO] 设备: {self.device}")

        if not _MODEL_LOADED or self.model is None:
            print("[ERROR] 模型未加载！")
            raise RuntimeError("真实Qwen2-7B模型未加载！")

        try:
            start_time = time.time()
            print(f"[INFERENCE] 开始推理 (max_tokens={max_new_tokens}, temperature={temperature})")

            inputs = self.tokenizer(
                prompt,
                return_tensors="pt",
                truncation=True,
                max_length=1024,
                padding=True
            )

            generation_config = {
                "max_new_tokens": max_new_tokens,
                "temperature": temperature,
                "do_sample": True,
                "top_p": 0.9,
                "top_k": 50,
                "pad_token_id": self.tokenizer.pad_token_id,
                "eos_token_id": self.tokenizer.eos_token_id,
                "repetition_penalty": 1.1,
            }

            with _INFERENCE_LOCK:
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
                with torch.no_grad():
                    outputs = self.model.generate(
                        **inputs,
                        **generation_config
                    )

            response = self.tokenizer.decode(
                outputs[0][inputs['input_ids'].shape[1]:],
                skip_special_tokens=True
            )

            elapsed_time = time.time() - start_time
            print(f"[SUCCESS] GPU推理完成")
            print(f"[TIME] 推理时间: {elapsed_time:.2f}秒")

            # 性能分析
            if self.device == "cuda":
                tokens_per_sec = max_new_tokens / elapsed_time
                print(f"[PERF] 生成速度: {tokens_per_sec:.1f} tokens/sec")

            print("="*80)

            return response.strip()

        except Exception as e:
            print(f"[ERROR] 推理失败: {e}")
            import traceback
            traceback.print_exc()
            raise RuntimeError(f"GPU推理失败: {e}")

# 全局实例
_gpu_llm_instance = None

def get_gpu_llm():
    """获取GPU LLM实例"""
    global _gpu_llm_instance

    with _INFERENCE_LOCK:
        if _gpu_llm_instance is None:
            print("[INIT] 创建GPU LLM实例...")
            _gpu_llm_instance = GPULLMInference()

    return _gpu_llm_instance

# 测试函数
if __name__ == "__main__":
    print("[TEST] GPU优化版模型测试")
    print("="*80)

    try:
        llm = GPULLMInference()

        test_prompt = """分析以下SQL注入攻击：
载荷：' OR '1'='1
请分析：
1. 攻击类型
2. 危险等级（1-10分）
3. 攻击原理
4. 防御建议

请用中文回答。"""

        print(f"\n[INPUT] 测试输入: {test_prompt[:50]}...")

        result = llm.generate_response(test_prompt, max_new_tokens=200)

        print(f"\n[OUTPUT] 模型输出:")
        print("-" * 60)
        print(result)
        print("-" * 60)
        print("\n[COMPLETE] GPU测试完成")

    except Exception as e:
        print(f"[ERROR] 测试失败: {e}")
        sys.exit(1)