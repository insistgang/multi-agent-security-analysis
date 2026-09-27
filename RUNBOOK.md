# pj2.0 运行手册

本文档记录当前仓库的推荐演示入口、真实模型版前置条件，以及路径和资产检查注意事项。

## 当前推荐入口

推荐使用 Excel 可视化演示版：

```powershell
Set-Location E:\vscode_project\pj2.0\web_demo
streamlit run .\excel_final.py --server.port 8886
```

浏览器访问：

```text
http://localhost:8886
```

`web_demo/excel_final.py` 会读取：

```text
../data/processed/excel_attack_data.json
```

该路径是按当前工作目录计算的。因此应先进入 `web_demo` 目录再运行。不要直接在仓库根目录执行 `streamlit run web_demo/excel_final.py`，否则 `../data/...` 可能解析到仓库外层目录，导致数据文件找不到。

## 演示版和真实模型版

### 演示版

演示版以 `web_demo/excel_final.py` 为主，展示 Excel 转 JSON 后的威胁数据可视化、智能体协同展示和报告页面。该入口主要依赖本地 JSON 数据，不需要加载 Qwen2-7B 权重，也不需要执行模型推理。

演示版关键资产：

```text
web_demo/excel_final.py
data/processed/excel_attack_data.json
data/processed/excel_data_stats.json
data/攻击日志V2.xlsx
data/风险信息_AqDzAqIh_20250319093813.xlsx
```

### 真实模型版

真实模型版涉及 `src/models/llm_inference.py`、`src/models/llm_inference_gpu.py`、`src/api/server.py`、`web_app/app.py` 等代码路径。这些路径会尝试加载本地 Qwen2-7B 模型，并可能依赖 `torch`、`transformers`、CUDA/GPU 环境和实际模型权重。

当前配置文件：

```text
config/model_config.json
```

其中模型路径为：

```text
./models/Qwen2-7B
```

当前仓库内 `models/Qwen2-7B` 没有可用模型权重。也就是说，真实模型版在未补齐模型目录前不能按“真实推理”方式启动。需要真实模型时，应先把模型文件放到 `models/Qwen2-7B`，或修改 `config/model_config.json` 中的 `model_config.model_path` 指向实际目录。

## fallback 模式

`config/model_config.json` 当前包含：

```json
"fallback_mode": true
```

这表示在模型不可用时，系统配置层面允许使用降级路径。演示版本身不加载模型，通常不会受模型目录为空影响。真实模型相关代码中也存在 fallback 处理路径，但部分推理模块会强制要求真实模型存在；因此不要把演示版页面上的 Qwen2-7B 展示文案理解为当前仓库已经包含可用权重。

判断方式：

- 只演示页面和图表：使用 `web_demo/excel_final.py`。
- 需要真实大模型推理：先补齐 `models/Qwen2-7B`，确认依赖和 CUDA/GPU，再启动 API 或真实模型入口。
- 只想确认演示资产是否齐全：运行只读检查脚本。

## 只读资产检查

从仓库根目录运行：

```powershell
Set-Location E:\vscode_project\pj2.0
python .\scripts\check_demo_assets.py
```

检查范围：

- 推荐入口 `web_demo/excel_final.py`
- Excel 源数据文件
- `data/processed` 下的 JSON 演示数据
- `config/model_config.json`
- `models/Qwen2-7B` 或配置中指定的模型目录状态

该脚本只读文件元数据和 JSON 内容，不导入 Streamlit、pandas、torch、transformers，不下载模型，不生成数据。

## 常见问题

### 页面提示数据为空

优先确认运行目录是否正确。推荐命令是先进入 `web_demo`：

```powershell
Set-Location E:\vscode_project\pj2.0\web_demo
streamlit run .\excel_final.py --server.port 8886
```

然后确认：

```text
E:\vscode_project\pj2.0\data\processed\excel_attack_data.json
```

文件存在且可读。

### 模型目录为空

这是当前仓库状态下的预期情况。演示版仍可运行，因为它读取已处理 JSON 数据。真实模型版需要额外准备 Qwen2-7B 权重文件。

### 从其他目录运行脚本

`scripts/check_demo_assets.py` 会按脚本所在位置推导仓库根目录，因此可以从任意当前目录执行它。但 Streamlit 演示入口 `web_demo/excel_final.py` 使用相对路径读取数据，应从 `web_demo` 目录启动。
