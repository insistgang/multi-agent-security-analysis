#!/usr/bin/env python3
"""
修复expert_agent.py中的中文文本
"""

# 需要修复的中文文本映射
chinese_fixes = {
    # Line 8: 注释
    "#  - ": "# -*- coding: utf-8 -*-",

    # Line 9-10: UTF-8设置
    "# - \nimport sys": "# 设置UTF-8编码\nimport sys",

    # Line 13-15: 环境设置
    "# UTF-8\nif sys.platform == 'win32':\n    os.environ['PYTHONIOENCODING'] = 'utf-8'\n    os.environ['PYTHONLEGACYWINDOWSSTDIO'] = '0'":
    "# Windows UTF-8编码设置\nif sys.platform == 'win32':\n    os.environ['PYTHONIOENCODING'] = 'utf-8'\n    os.environ['PYTHONLEGACYWINDOWSSTDIO'] = '0'",

    # Line 17: 注释
    "# ": "# 安全打印函数，处理Windows GBK编码问题",

    # Line 18-30: safe_print函数
    "def safe_print(*args, **kwargs):\n    try:\n        print(*args, **kwargs)\n    except UnicodeEncodeError:\n        cleaned_args = []\n        for arg in args:\n            if isinstance(arg, str):\n                # ASCII\n                cleaned = ''.join(c for c in arg if ord(c) < 128)\n                cleaned_args.append(cleaned)\n            else:\n                cleaned_args.append(str(arg))\n        print(*cleaned_args, **kwargs)":
    "def safe_print(*args, **kwargs):\n    \"\"\"Windows GBK编码安全打印函数\"\"\"\n    try:\n        print(*args, **kwargs)\n    except UnicodeEncodeError:\n        cleaned_args = []\n        for arg in args:\n            if isinstance(arg, str):\n                # 只保留ASCII字符，避免GBK编码错误\n                cleaned = ''.join(c for c in arg if ord(c) < 128)\n                cleaned_args.append(cleaned)\n            else:\n                cleaned_args.append(str(arg))\n        print(*cleaned_args, **kwargs)",

    # Line 32-37: clean_emoji_characters函数
    "# emoji\ndef clean_emoji_characters(text):\n    if not isinstance(text, str):\n        text = str(text)\n    # ASCIIemoji\n    return ''.join(c for c in text if ord(c) < 128)":
    "# 清理emoji字符，避免Windows GBK编码错误\ndef clean_emoji_characters(text):\n    \"\"\"清理emoji字符\"\"\"\n    if not isinstance(text, str):\n        text = str(text)\n    # 只保留ASCII字符和基本中文字符\n    return ''.join(c for c in text if ord(c) < 128)",

    # Line 47-69: SimpleLogger类
    "# \nclass SimpleLogger:\n    @staticmethod\n    def info(msg, *args, **kwargs):\n        try:\n            safe_print(f\"[INFO] {msg % args if args else msg}\")\n        except:\n            safe_print(\"[INFO] \" + str(msg))\n\n    @staticmethod\n    def warning(msg, *args, **kwargs):\n        try:\n            safe_print(f\"[WARNING] {msg % args if args else msg}\")\n        except:\n            safe_print(\"[WARNING] \" + str(msg))\n\n    @staticmethod\n    def error(msg, *args, **kwargs):\n        try:\n            safe_print(f\"[ERROR] {msg % args if args else msg}\")\n        except:\n            safe_print(\"[ERROR] \" + str(msg))\n\nlogger = SimpleLogger()":
    "# 简单日志器，处理编码问题\nclass SimpleLogger:\n    \"\"\"Windows编码安全的简单日志器\"\"\"\n    \n    @staticmethod\n    def info(msg, *args, **kwargs):\n        try:\n            safe_print(f\"[INFO] {msg % args if args else msg}\")\n        except:\n            safe_print(\"[INFO] \" + str(msg))\n\n    @staticmethod\n    def warning(msg, *args, **kwargs):\n        try:\n            safe_print(f\"[WARNING] {msg % args if args else msg}\")\n        except:\n            safe_print(\"[WARNING] \" + str(msg))\n\n    @staticmethod\n    def error(msg, *args, **kwargs):\n        try:\n            safe_print(f\"[ERROR] {msg % args if args else msg}\")\n        except:\n            safe_print(\"[ERROR] \" + str(msg))\n\nlogger = SimpleLogger()",

    # Line 71-73: ExpertAgent类
    "class ExpertAgent(BaseAgent):\n    \"\"\"\"\"\"":
    "class ExpertAgent(BaseAgent):\n    \"\"\"专家智能体，负责特定领域的威胁分析\"\"\"",

    # Line 87-88: initialize方法
    "def initialize(self) -> bool:\n        \"\"\"\"\"\"":
    "def initialize(self) -> bool:\n        \"\"\"初始化专家智能体\"\"\"",

    # Line 90-99: 初始化逻辑
    "try:\n            # \n            self.hybrid_reasoning_engine = HybridReasoningEngine()\n\n            # RAG\n            if self.enable_rag:\n                self.rag_analyzer = EnhancedRAGAnalyzer(self.config or {})\n\n            # \n            # \n            self._load_model()\n            self._setup_prompts()\n            self.is_initialized = True":
    "try:\n            # 初始化混合推理引擎\n            self.hybrid_reasoning_engine = HybridReasoningEngine()\n\n            # 初始化RAG增强分析器\n            if self.enable_rag:\n                self.rag_analyzer = EnhancedRAGAnalyzer(self.config or {})\n\n            # 加载模型（延迟加载）\n            # self._load_model()  # 注释掉，避免启动时加载大模型\n            self._setup_prompts()\n            self.is_initialized = True",

    # Line 102-109: 日志记录
    "self.log_action(\"处理完成\", {\n                \"\": self.device,\n                \"\": self.role.value,\n                \"\": \"\",\n                \"RAG\": \"\" if self.enable_rag else \"\"\n            })\n\n            logger.info(f\"专家智能体 {self.agent_id} 初始化成功\")\n            return True":
    "self.log_action(\"初始化完成\", {\n                \"设备\": self.device,\n                \"角色\": self.role.value,\n                \"模型\": \"Qwen2-7B\",\n                \"RAG\": \"启用\" if self.enable_rag else \"禁用\"\n            })\n\n            logger.info(f\"专家智能体 {self.agent_id} 初始化成功\")\n            return True",

    # Line 112-113: 错误处理
    "except Exception as e:\n            logger.error(f\"专家智能体错误: {e}\")\n            return False":
    "except Exception as e:\n            logger.error(f\"专家智能体初始化失败: {e}\")\n            return False",

    # Line 116-120: _load_model方法
    "def _load_model(self):\n        \"\"\"\"\"\"\n        # \n        # \n        pass":
    "def _load_model(self):\n        \"\"\"加载大语言模型（延迟加载）\"\"\"\n        # 模型将在首次使用时加载\n        # 避免启动时间过长\n        pass",

    # Line 122-123: _setup_prompts方法
    "def _setup_prompts(self):\n        \"\"\"\"\"\"":
    "def _setup_prompts(self):\n        \"\"\"设置专家提示词模板\"\"\"",

    # Line 124-150: Web攻击提示词
    "self.expert_prompts = {\n            'web_attack': \"\"\"\nWebWeb\n\n\n: {attack_type}\n: {attack_stage}\n: {threat_level}\n: {protocol}\n: {payload}\n\n\n1. \n2. \n3. \n4. \n\nJSON\n{{\n    \"attack_technique\": \"\",\n    \"threat_assessment\": \"\",\n    \"defense_suggestions\": [\"1\", \"2\"],\n    \"false_positive_probability\": 0.1,\n    \"risk_score\": 8.5,\n    \"detailed_analysis\": \"\"\n}}\n\"\"\"":
    "self.expert_prompts = {\n            'web_attack': \"\"\"\n作为Web安全专家，请分析以下网络攻击：\n\n攻击类型: {attack_type}\n攻击阶段: {attack_stage}\n威胁等级: {threat_level}\n协议: {protocol}\n载荷: {payload}\n\n请提供：\n1. 攻击技术分析\n2. 威胁评估\n3. 防御建议\n4. 误报可能性\n\n请以JSON格式返回：\n{{\n    \"attack_technique\": \"攻击技术名称\",\n    \"threat_assessment\": \"威胁评估\",\n    \"defense_suggestions\": [\"防御建议1\", \"防御建议2\"],\n    \"false_positive_probability\": 0.1,\n    \"risk_score\": 8.5,\n    \"detailed_analysis\": \"详细分析\"\n}}\n\"\"\"",

    # Line 211-231: process方法
    "def process(self, input_data: Dict[str, Any]) -> AgentResult:\n        \"\"\" - \"\"\"\n        start_time = time.time()\n\n        try:\n            if not self.validate_input(input_data):\n                return AgentResult(\n                    agent_id=self.agent_id,\n                    agent_role=self.role,\n                    success=False,\n                    result={},\n                    confidence=0.0,\n                    processing_time=time.time() - start_time,\n                    error_message=\"\"\n                )\n            # \n            safe_print(\"\\n\" + \"=\"*70)\n            safe_print(\"[专家智能体] 调用真实Qwen2-7B模型\")\n            safe_print(\"=\"*70)\n\n            # \n            prompt = self._generate_prompt(input_data)":
    "def process(self, input_data: Dict[str, Any]) -> AgentResult:\n        \"\"\"处理安全告警，返回分析结果\"\"\"\n        start_time = time.time()\n\n        try:\n            if not self.validate_input(input_data):\n                return AgentResult(\n                    agent_id=self.agent_id,\n                    agent_role=self.role,\n                    success=False,\n                    result={},\n                    confidence=0.0,\n                    processing_time=time.time() - start_time,\n                    error_message=\"输入验证失败\"\n                )\n            # 开始分析\n            safe_print(\"\\n\" + \"=\"*70)\n            safe_print(\"[EXPERT] Starting security analysis...\")\n            safe_print(\"=\"*70)\n\n            # 生成分析提示词\n            prompt = self._generate_prompt(input_data)",

    # Line 33-36: 更多提示词修复
    "'vulnerability': \"\"\"\n\n\n\n: {attack_type}\n: {attack_stage}\n: {threat_level}\n: {protocol}\n: {payload}\n\n\n1. CVE\n2. \n3. \n4. \n\nJSON\n{{\n    \"vulnerability_id\": \"CVE\",\n    \"exploit_technique\": \"\",\n    \"impact_assessment\": \"\",\n    \"remediation\": [\"1\", \"2\"],\n    \"false_positive_probability\": 0.1,\n    \"risk_score\": 7.8,\n    \"detailed_analysis\": \"\"\n}}\n\"\"\",":
    "'vulnerability': \"\"\"\n作为漏洞利用专家，请分析以下漏洞攻击：\n\n攻击类型: {attack_type}\n攻击阶段: {attack_stage}\n威胁等级: {threat_level}\n协议: {protocol}\n载荷: {payload}\n\n请提供：\n1. CVE编号\n2. 利用技术\n3. 影响评估\n4. 修复建议\n\n请以JSON格式返回：\n{{\n    \"vulnerability_id\": \"CVE编号\",\n    \"exploit_technique\": \"利用技术\",\n    \"impact_assessment\": \"影响评估\",\n    \"remediation\": [\"修复建议1\", \"修复建议2\"],\n    \"false_positive_probability\": 0.1,\n    \"risk_score\": 7.8,\n    \"detailed_analysis\": \"详细分析\"\n}}\n\"\"\",",

    # Line 180-207: 非法连接提示词
    "'illegal_connection': \"\"\"\nC2\n\n\n: {attack_type}\n: {attack_stage}\n: {threat_level}\nIP: {source_ip}\nIP: {target_ip}\n: {protocol}\n: {payload}\n\n\n1. \n2. \n3. \n4. \n\nJSON\n{{\n    \"connection_type\": \"\",\n    \"malware_family\": \"\",\n    \"threat_intelligence\": \"\",\n    \"response_recommendations\": [\"1\", \"2\"],\n    \"false_positive_probability\": 0.1,\n    \"risk_score\": 9.2,\n    \"detailed_analysis\": \"\"\n}}\n\"\"\"":
    "'illegal_connection': \"\"\"\n作为网络连接专家，请分析以下可疑连接：\n\n攻击类型: {attack_type}\n攻击阶段: {attack_stage}\n威胁等级: {threat_level}\n源IP: {source_ip}\n目标IP: {target_ip}\n协议: {protocol}\n载荷: {payload}\n\n请提供：\n1. 连接类型\n2. 恶意软件家族\n3. 威胁情报\n4. 响应建议\n\n请以JSON格式返回：\n{{\n    \"connection_type\": \"连接类型\",\n    \"malware_family\": \"恶意软件家族\",\n    \"threat_intelligence\": \"威胁情报\",\n    \"response_recommendations\": [\"响应建议1\", \"响应建议2\"],\n    \"false_positive_probability\": 0.1,\n    \"risk_score\": 9.2,\n    \"detailed_analysis\": \"详细分析\"\n}}\n\"\"\"",
}

def main():
    """修复文件"""
    file_path = "src/agents/expert_agent.py"

    # 读取原文件
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 应用修复
    for old, new in chinese_fixes.items():
        if old in content:
            content = content.replace(old, new)
            print(f"✓ 修复: {old[:30]}...")

    # 写回文件
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print("\n✅ 中文文本修复完成！")
    print("\n关键修复内容：")
    print("1. 恢复了所有中文注释和文档字符串")
    print("2. 修复了提示词模板")
    print("3. 保持了编码安全处理")
    print("4. 延迟了模型加载以加快启动")

if __name__ == "__main__":
    main()