#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
威胁数据可视化工具
生成图表和可视化报告
"""

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
import os

# 设置中文字体
plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'Arial Unicode MS']
plt.rcParams['axes.unicode_minus'] = False

# 设置样式
sns.set_style("whitegrid")
plt.style.use('seaborn-v0_8-darkgrid')

class ThreatDataVisualizer:
    """威胁数据可视化器"""

    def __init__(self):
        self.colors = {
            'primary': '#1f77b4',
            'danger': '#d62728',
            'warning': '#ff7f0e',
            'success': '#2ca02c',
            'info': '#17becf'
        }

    def load_analysis_results(self, file_path: str) -> List[Dict]:
        """加载分析结果"""
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def prepare_data(self, results: List[Dict]) -> pd.DataFrame:
        """准备数据用于可视化"""
        data = []

        for result in results:
            if result.get('success') and 'result' in result:
                res = result['result']
                expert = res.get('expert_analysis', {})

                row = {
                    'alert_id': res.get('alert_id', ''),
                    'timestamp': res.get('timestamp', ''),
                    'processing_time': result.get('processing_time', 0),
                    'attack_type': expert.get('attack_type', 'Unknown'),
                    'risk_score': expert.get('risk_score', 5.0),
                    'confidence': expert.get('confidence', 0.5)
                }

                # 提取详细信息
                if 'analysis_details' in expert and isinstance(expert['analysis_details'], dict):
                    details = expert['analysis_details']
                    row['attack_technique'] = details.get('attack_technique', 'Unknown')
                    row['threat_assessment'] = details.get('threat_assessment', 'Unknown')

                data.append(row)

        return pd.DataFrame(data)

    def plot_attack_distribution(self, df: pd.DataFrame, save_path: str = None):
        """绘制攻击类型分布图"""
        plt.figure(figsize=(12, 8))

        # 攻击类型统计
        attack_counts = df['attack_type'].value_counts()

        # 创建子图
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

        # 饼图
        colors = plt.cm.Set3(np.linspace(0, 1, len(attack_counts)))
        wedges, texts, autotexts = ax1.pie(
            attack_counts.values,
            labels=attack_counts.index,
            autopct='%1.1f%%',
            startangle=90,
            colors=colors,
            explode=[0.05] * len(attack_counts)
        )
        ax1.set_title('攻击类型分布（饼图）', fontsize=16, fontweight='bold', pad=20)

        # 柱状图
        bars = ax2.bar(attack_counts.index, attack_counts.values, color=colors)
        ax2.set_title('攻击类型分布（柱状图）', fontsize=16, fontweight='bold', pad=20)
        ax2.set_xlabel('攻击类型', fontsize=12)
        ax2.set_ylabel('攻击次数', fontsize=12)
        ax2.tick_params(axis='x', rotation=45)

        # 在柱状图上添加数值
        for bar in bars:
            height = bar.get_height()
            ax2.text(
                bar.get_x() + bar.get_width() / 2.,
                height,
                f'{int(height)}',
                ha='center',
                va='bottom'
            )

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def plot_risk_distribution(self, df: pd.DataFrame, save_path: str = None):
        """绘制风险评分分布"""
        plt.figure(figsize=(15, 10))

        # 创建子图
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))

        # 1. 风险评分直方图
        ax1.hist(df['risk_score'], bins=20, color=self.colors['danger'], alpha=0.7, edgecolor='black')
        ax1.set_title('风险评分分布直方图', fontsize=14, fontweight='bold')
        ax1.set_xlabel('风险评分', fontsize=12)
        ax1.set_ylabel('频次', fontsize=12)
        ax1.axvline(df['risk_score'].mean(), color='red', linestyle='--', label=f'平均值: {df["risk_score"].mean():.2f}')
        ax1.legend()

        # 2. 风险等级饼图
        risk_levels = pd.cut(df['risk_score'], bins=[0, 4, 7, 10], labels=['低风险', '中风险', '高风险'])
        risk_counts = risk_levels.value_counts()
        colors_risk = [self.colors['success'], self.colors['warning'], self.colors['danger']]
        wedges, texts, autotexts = ax2.pie(
            risk_counts.values,
            labels=risk_counts.index,
            autopct='%1.1f%%',
            colors=colors_risk,
            startangle=90
        )
        ax2.set_title('风险等级分布', fontsize=14, fontweight='bold')

        # 3. 攻击类型vs风险评分箱线图
        box_data = []
        attack_types = df['attack_type'].unique()
        for attack in attack_types:
            box_data.append(df[df['attack_type'] == attack]['risk_score'])

        bp = ax3.boxplot(box_data, labels=attack_types, patch_artist=True)
        for patch in bp['boxes']:
            patch.set_facecolor(self.colors['info'])
            patch.set_alpha(0.7)
        ax3.set_title('各攻击类型风险评分分布', fontsize=14, fontweight='bold')
        ax3.set_xlabel('攻击类型', fontsize=12)
        ax3.set_ylabel('风险评分', fontsize=12)
        ax3.tick_params(axis='x', rotation=45)

        # 4. 时间序列（如果有时间数据）
        if 'timestamp' in df.columns:
            # 转换时间戳
            df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df_sorted = df.dropna(subset=['datetime']).sort_values('datetime')

            # 按小时聚合
            df_sorted['hour'] = df_sorted['datetime'].dt.hour
            hourly_avg = df_sorted.groupby('hour')['risk_score'].mean()

            ax4.plot(hourly_avg.index, hourly_avg.values, marker='o', color=self.colors['primary'], linewidth=2)
            ax4.set_title('24小时风险评分趋势', fontsize=14, fontweight='bold')
            ax4.set_xlabel('小时', fontsize=12)
            ax4.set_ylabel('平均风险评分', fontsize=12)
            ax4.grid(True, alpha=0.3)
        else:
            ax4.text(0.5, 0.5, '无时间数据', ha='center', va='center', transform=ax4.transAxes, fontsize=14)
            ax4.set_title('时间趋势', fontsize=14, fontweight='bold')

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def plot_performance_metrics(self, df: pd.DataFrame, save_path: str = None):
        """绘制性能指标图"""
        plt.figure(figsize=(15, 10))

        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))

        # 1. 处理时间分布
        ax1.hist(df['processing_time'], bins=30, color=self.colors['info'], alpha=0.7, edgecolor='black')
        ax1.set_title('处理时间分布', fontsize=14, fontweight='bold')
        ax1.set_xlabel('处理时间（秒）', fontsize=12)
        ax1.set_ylabel('频次', fontsize=12)
        ax1.axvline(df['processing_time'].mean(), color='red', linestyle='--',
                    label=f'平均: {df["processing_time"].mean():.3f}秒')
        ax1.legend()

        # 2. 置信度分布
        if 'confidence' in df.columns:
            ax2.hist(df['confidence'], bins=20, color=self.colors['warning'], alpha=0.7, edgecolor='black')
            ax2.set_title('分析置信度分布', fontsize=14, fontweight='bold')
            ax2.set_xlabel('置信度', fontsize=12)
            ax2.set_ylabel('频次', fontsize=12)

        # 3. 处理时间vs风险评分散点图
        scatter = ax3.scatter(df['processing_time'], df['risk_score'],
                            c=df['risk_score'], cmap='RdYlGn_r', alpha=0.6, s=50)
        ax3.set_title('处理时间 vs 风险评分', fontsize=14, fontweight='bold')
        ax3.set_xlabel('处理时间（秒）', fontsize=12)
        ax3.set_ylabel('风险评分', fontsize=12)
        plt.colorbar(scatter, ax=ax3, label='风险评分')

        # 4. 综合性能仪表盘
        metrics = {
            '平均处理时间': df['processing_time'].mean(),
            '最大处理时间': df['processing_time'].max(),
            '平均风险评分': df['risk_score'].mean(),
            '高威胁比例': (df['risk_score'] >= 7).sum() / len(df) * 100
        }

        y_pos = np.arange(len(metrics))
        bars = ax4.barh(y_pos, list(metrics.values()), color=[self.colors['primary'], self.colors['danger'],
                                                              self.colors['warning'], self.colors['info']])
        ax4.set_yticks(y_pos)
        ax4.set_yticklabels(list(metrics.keys()))
        ax4.set_xlabel('数值', fontsize=12)
        ax4.set_title('关键性能指标', fontsize=14, fontweight='bold')

        # 添加数值标签
        for i, (bar, value) in enumerate(zip(bars, metrics.values())):
            ax4.text(value + 0.01, bar.get_y() + bar.get_height()/2,
                    f'{value:.3f}' if value < 100 else f'{value:.1f}%',
                    ha='left', va='center')

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def create_dashboard(self, df: pd.DataFrame, save_dir: str = 'visualizations'):
        """创建完整的仪表板"""
        # 创建保存目录
        os.makedirs(save_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # 生成所有图表
        print("生成攻击类型分布图...")
        self.plot_attack_distribution(df, f'{save_dir}/attack_distribution_{timestamp}.png')

        print("生成风险分布图...")
        self.plot_risk_distribution(df, f'{save_dir}/risk_distribution_{timestamp}.png')

        print("生成性能指标图...")
        self.plot_performance_metrics(df, f'{save_dir}/performance_metrics_{timestamp}.png')

        print(f"所有图表已保存到: {save_dir}")

    def generate_summary_report(self, df: pd.DataFrame, save_path: str = None):
        """生成摘要报告"""
        fig, ax = plt.subplots(figsize=(12, 8))
        ax.axis('off')

        # 统计信息
        summary_text = f"""
威胁数据分析摘要报告
{'='*50}
生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📊 数据概览
- 总记录数: {len(df):,}
- 成功分析: {len(df):,}
- 分析成功率: 100%

🎯 攻击分析
- 最常见攻击: {df['attack_type'].mode().iloc[0] if not df['attack_type'].mode().empty else 'N/A'}
- 平均风险评分: {df['risk_score'].mean():.2f}/10.0
- 高风险威胁: {(df['risk_score'] >= 7).sum()} 条 ({(df['risk_score'] >= 7).sum()/len(df)*100:.1f}%)

⚡ 性能指标
- 平均处理时间: {df['processing_time'].mean():.3f} 秒
- 最快处理时间: {df['processing_time'].min():.3f} 秒
- 最慢处理时间: {df['processing_time'].max():.3f} 秒

🛡️ 安全建议
1. 加强防火墙规则配置
2. 实施输入验证和输出编码
3. 定期更新安全补丁
4. 建立实时监控和告警系统
5. 进行定期安全审计

"""

        ax.text(0.05, 0.95, summary_text, transform=ax.transAxes, fontsize=12,
                verticalalignment='top', fontfamily='monospace',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

        plt.title('威胁数据分析摘要', fontsize=18, fontweight='bold', pad=20)

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

def main():
    """主程序"""
    print("=" * 80)
    print("威胁数据可视化工具")
    print("=" * 80)

    # 查找最新的分析结果文件
    import glob
    result_files = glob.glob('threat_analysis_results_*.json')

    if not result_files:
        print("\n错误：未找到分析结果文件")
        print("请先运行 data_processor.py 生成分析结果")
        return

    # 使用最新的文件
    result_file = max(result_files)
    print(f"\n加载分析结果: {result_file}")

    # 初始化可视化器
    visualizer = ThreatDataVisualizer()

    # 加载数据
    results = visualizer.load_analysis_results(result_file)
    df = visualizer.prepare_data(results)

    if df.empty:
        print("\n错误：没有可用的分析结果")
        return

    print(f"\n成功加载 {len(df)} 条分析记录")

    # 创建可视化
    print("\n生成可视化图表...")

    # 1. 攻击类型分布
    visualizer.plot_attack_distribution(df)

    # 2. 风险分布
    visualizer.plot_risk_distribution(df)

    # 3. 性能指标
    visualizer.plot_performance_metrics(df)

    # 4. 摘要报告
    visualizer.generate_summary_report(df)

    # 5. 创建完整仪表板
    visualizer.create_dashboard(df)

    print("\n可视化完成！")
    print("图表已保存到 'visualizations' 目录")

if __name__ == "__main__":
    main()