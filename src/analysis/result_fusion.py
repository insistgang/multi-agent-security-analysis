#!/usr/bin/env python3
"""
结果融合算法和自适应学习系统
实现多专家结果的智能融合和持续学习能力
"""
import json
import time
import math
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
import statistics
from loguru import logger

@dataclass
class ExpertResult:
    """专家分析结果"""
    expert_id: str
    expert_role: str
    attack_type: str
    confidence: float
    risk_score: float
    processing_time: float
    analysis_details: str
    evidence: List[str]
    timestamp: float

@dataclass
class FusionResult:
    """融合结果"""
    final_attack_type: str
    final_confidence: float
    final_risk_score: float
    consensus_level: float
    conflict_resolution: str
    contributing_experts: List[str]
    fusion_confidence: float
    reasoning_summary: str
    weighted_analysis: Dict[str, Any]

class ExpertWeightManager:
    """专家权重管理器"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.expert_weights = {
            'web_attack_expert': 1.0,
            'vulnerability_expert': 1.0,
            'illegal_connection_expert': 1.0
        }
        self.expert_performance = defaultdict(lambda: {
            'total_requests': 0,
            'successful_requests': 0,
            'avg_confidence': 0.0,
            'avg_processing_time': 0.0,
            'accuracy_history': deque(maxlen=50),
            'confidence_history': deque(maxlen=50),
            'processing_time_history': deque(maxlen=50)
        })
        self.learning_rate = self.config.get('learning_rate', 0.1)
        self.min_weight = self.config.get('min_weight', 0.1)
        self.max_weight = self.config.get('max_weight', 2.0)

    def update_expert_performance(self, expert_id: str, result: ExpertResult, success: bool, feedback_score: float = None):
        """更新专家性能数据"""
        perf = self.expert_performance[expert_id]

        # 更新基础统计
        perf['total_requests'] += 1
        if success:
            perf['successful_requests'] += 1

        # 更新历史数据
        perf['confidence_history'].append(result.confidence)
        perf['processing_time_history'].append(result.processing_time)

        if feedback_score is not None:
            perf['accuracy_history'].append(feedback_score)

        # 更新平均值
        perf['avg_confidence'] = statistics.mean(perf['confidence_history']) if perf['confidence_history'] else 0.0
        perf['avg_processing_time'] = statistics.mean(perf['processing_time_history']) if perf['processing_time_history'] else 0.0

        # 自适应调整权重
        self._adaptive_weight_adjustment(expert_id)

    def _adaptive_weight_adjustment(self, expert_id: str):
        """自适应权重调整"""
        perf = self.expert_performance[expert_id]

        if perf['total_requests'] < 5:  # 数据不足时暂不调整
            return

        # 计算性能指标
        success_rate = perf['successful_requests'] / perf['total_requests']
        avg_confidence = perf['avg_confidence']
        speed_factor = max(0.1, 1.0 / (1.0 + perf['avg_processing_time']))  # 处理速度因子

        # 如果有准确性反馈，使用准确性；否则使用成功率
        if perf['accuracy_history']:
            accuracy = statistics.mean(perf['accuracy_history'])
        else:
            accuracy = success_rate

        # 计算新权重
        performance_score = accuracy * avg_confidence * speed_factor
        weight_adjustment = self.learning_rate * (performance_score - 0.5)  # 以0.5为基准

        # 调整权重
        current_weight = self.expert_weights[expert_id]
        new_weight = current_weight + weight_adjustment

        # 限制权重范围
        new_weight = max(self.min_weight, min(self.max_weight, new_weight))

        self.expert_weights[expert_id] = new_weight

        logger.info(f"专家 {expert_id} 权重调整: {current_weight:.3f} -> {new_weight:.3f} "
                   f"(成功率: {success_rate:.3f}, 置信度: {avg_confidence:.3f})")

    def get_expert_weight(self, expert_id: str) -> float:
        """获取专家权重"""
        return self.expert_weights.get(expert_id, 1.0)

    def get_normalized_weights(self, expert_ids: List[str]) -> Dict[str, float]:
        """获取归一化权重"""
        weights = {}
        total_weight = 0.0

        for expert_id in expert_ids:
            weight = self.get_expert_weight(expert_id)
            weights[expert_id] = weight
            total_weight += weight

        # 归一化
        if total_weight > 0:
            for expert_id in weights:
                weights[expert_id] /= total_weight

        return weights

    def get_performance_stats(self) -> Dict[str, Any]:
        """获取性能统计"""
        stats = {
            'expert_weights': self.expert_weights.copy(),
            'expert_performance': {}
        }

        for expert_id, perf in self.expert_performance.items():
            if perf['total_requests'] > 0:
                stats['expert_performance'][expert_id] = {
                    'total_requests': perf['total_requests'],
                    'success_rate': perf['successful_requests'] / perf['total_requests'],
                    'avg_confidence': perf['avg_confidence'],
                    'avg_processing_time': perf['avg_processing_time'],
                    'accuracy': statistics.mean(perf['accuracy_history']) if perf['accuracy_history'] else None
                }

        return stats

class ConsensusAnalyzer:
    """共识分析器"""

    def __init__(self):
        self.consensus_threshold = 0.7
        self.conflict_threshold = 0.3

    def analyze_consensus(self, expert_results: List[ExpertResult]) -> Dict[str, Any]:
        """分析专家共识"""
        if not expert_results:
            return {
                'consensus_level': 0.0,
                'conflict_level': 0.0,
                'dominant_opinion': None,
                'conflict_type': 'none'
            }

        # 按攻击类型分组
        attack_type_groups = defaultdict(list)
        for result in expert_results:
            attack_type_groups[result.attack_type].append(result)

        # 计算共识程度
        largest_group_size = max(len(group) for group in attack_type_groups.values())
        consensus_level = largest_group_size / len(expert_results)

        # 确定主导意见
        dominant_attack_type = max(attack_type_groups.keys(), key=lambda k: len(attack_type_groups[k]))
        dominant_results = attack_type_groups[dominant_attack_type]

        # 计算冲突程度
        conflict_level = 0.0
        if len(attack_type_groups) > 1:
            # 如果有多个不同意见，计算冲突程度
            second_largest_size = sorted(len(group) for group in attack_type_groups.values())[-2] if len(attack_type_groups) > 1 else 0
            conflict_level = second_largest_size / len(expert_results)

        # 确定冲突类型
        conflict_type = 'none'
        if consensus_level < self.consensus_threshold:
            if conflict_level > self.conflict_threshold:
                conflict_type = 'high_conflict'
            else:
                conflict_type = 'low_consensus'

        return {
            'consensus_level': consensus_level,
            'conflict_level': conflict_level,
            'dominant_attack_type': dominant_attack_type,
            'dominant_results': dominant_results,
            'conflict_type': conflict_type,
            'attack_type_distribution': {k: len(v) for k, v in attack_type_groups.items()}
        }

class ConflictResolver:
    """冲突解决器"""

    def __init__(self, weight_manager: ExpertWeightManager):
        self.weight_manager = weight_manager
        self.resolution_strategies = {
            'weighted_voting': self._weighted_voting_resolution,
            'confidence_based': self._confidence_based_resolution,
            'expertise_based': self._expertise_based_resolution
        }

    def resolve_conflicts(self, expert_results: List[ExpertResult], consensus_analysis: Dict) -> Dict[str, Any]:
        """解决专家意见冲突"""
        conflict_type = consensus_analysis.get('conflict_type', 'none')

        if conflict_type == 'none':
            # 无冲突，直接返回主导意见
            return {
                'resolution_strategy': 'no_conflict',
                'final_attack_type': consensus_analysis['dominant_attack_type'],
                'resolution_confidence': consensus_analysis['consensus_level'],
                'explanation': '专家意见一致，无需冲突解决'
            }

        # 选择解决策略
        strategy = self._select_resolution_strategy(expert_results, consensus_analysis)

        # 执行冲突解决
        resolution_func = self.resolution_strategies[strategy]
        resolution_result = resolution_func(expert_results, consensus_analysis)

        resolution_result['resolution_strategy'] = strategy
        resolution_result['conflict_type'] = conflict_type

        return resolution_result

    def _select_resolution_strategy(self, expert_results: List[ExpertResult], consensus_analysis: Dict) -> str:
        """选择冲突解决策略"""
        # 如果有高置信度的专家，优先采用基于置信度的策略
        high_confidence_experts = [r for r in expert_results if r.confidence > 0.8]
        if high_confidence_experts:
            return 'confidence_based'

        # 如果权重差异明显，采用加权投票
        weights = [self.weight_manager.get_expert_weight(r.expert_id) for r in expert_results]
        weight_variance = statistics.variance(weights) if len(weights) > 1 else 0
        if weight_variance > 0.1:
            return 'weighted_voting'

        # 默认使用专业导向策略
        return 'expertise_based'

    def _weighted_voting_resolution(self, expert_results: List[ExpertResult], consensus_analysis: Dict) -> Dict[str, Any]:
        """加权投票解决冲突"""
        attack_type_scores = defaultdict(float)
        total_weight = 0.0

        for result in expert_results:
            weight = self.weight_manager.get_expert_weight(result.expert_id)
            attack_type_scores[result.attack_type] += weight * result.confidence
            total_weight += weight

        # 选择得分最高的攻击类型
        best_attack_type = max(attack_type_scores.keys(), key=lambda k: attack_type_scores[k])
        best_score = attack_type_scores[best_attack_type]
        resolution_confidence = best_score / total_weight if total_weight > 0 else 0.0

        return {
            'final_attack_type': best_attack_type,
            'resolution_confidence': resolution_confidence,
            'attack_type_scores': dict(attack_type_scores),
            'explanation': f'采用加权投票策略，{best_attack_type}获得最高加权得分'
        }

    def _confidence_based_resolution(self, expert_results: List[ExpertResult], consensus_analysis: Dict) -> Dict[str, Any]:
        """基于置信度的冲突解决"""
        # 选择置信度最高的专家结果
        best_result = max(expert_results, key=lambda r: r.confidence)

        return {
            'final_attack_type': best_result.attack_type,
            'resolution_confidence': best_result.confidence,
            'selected_expert': best_result.expert_id,
            'explanation': f'选择置信度最高的专家{best_result.expert_id}的分析结果'
        }

    def _expertise_based_resolution(self, expert_results: List[ExpertResult], consensus_analysis: Dict) -> Dict[str, Any]:
        """基于专业导向的冲突解决"""
        # 根据攻击类型选择最合适的专家
        attack_type_groups = defaultdict(list)
        for result in expert_results:
            attack_type_groups[result.attack_type].append(result)

        # 为每个攻击类型计算综合得分
        type_scores = {}
        for attack_type, results in attack_type_groups.items():
            # 综合考虑专家权重和置信度
            total_score = 0.0
            total_weight = 0.0

            for result in results:
                weight = self.weight_manager.get_expert_weight(result.expert_id)
                total_score += weight * result.confidence
                total_weight += weight

            type_scores[attack_type] = total_score / total_weight if total_weight > 0 else 0.0

        # 选择得分最高的攻击类型
        best_attack_type = max(type_scores.keys(), key=lambda k: type_scores[k])
        resolution_confidence = type_scores[best_attack_type]

        return {
            'final_attack_type': best_attack_type,
            'resolution_confidence': resolution_confidence,
            'type_scores': type_scores,
            'explanation': f'基于专业导向选择最适合的攻击类型分析'
        }

class ResultFusionEngine:
    """结果融合引擎"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.weight_manager = ExpertWeightManager(config)
        self.consensus_analyzer = ConsensusAnalyzer()
        self.conflict_resolver = ConflictResolver(self.weight_manager)

        # 融合参数
        self.confidence_weight = self.config.get('confidence_weight', 0.6)
        self.risk_weight = self.config.get('risk_weight', 0.4)
        self.min_contributing_experts = self.config.get('min_contributing_experts', 1)

    def fuse_results(self, expert_results: List[ExpertResult]) -> FusionResult:
        """融合多个专家的分析结果"""
        if not expert_results:
            return FusionResult(
                final_attack_type="unknown",
                final_confidence=0.0,
                final_risk_score=0.0,
                consensus_level=0.0,
                conflict_resolution="no_results",
                contributing_experts=[],
                fusion_confidence=0.0,
                reasoning_summary="没有专家结果可供融合",
                weighted_analysis={}
            )

        try:
            # 1. 分析专家共识
            consensus_analysis = self.consensus_analyzer.analyze_consensus(expert_results)

            # 2. 解决冲突
            conflict_resolution = self.conflict_resolver.resolve_conflicts(expert_results, consensus_analysis)

            # 3. 计算最终融合结果
            final_result = self._calculate_fusion_result(expert_results, consensus_analysis, conflict_resolution)

            # 4. 生成推理总结
            reasoning_summary = self._generate_reasoning_summary(expert_results, consensus_analysis, conflict_resolution, final_result)

            return FusionResult(
                final_attack_type=final_result['attack_type'],
                final_confidence=final_result['confidence'],
                final_risk_score=final_result['risk_score'],
                consensus_level=consensus_analysis['consensus_level'],
                conflict_resolution=conflict_resolution['resolution_strategy'],
                contributing_experts=[r.expert_id for r in expert_results],
                fusion_confidence=final_result['fusion_confidence'],
                reasoning_summary=reasoning_summary,
                weighted_analysis=final_result
            )

        except Exception as e:
            logger.error(f"结果融合失败: {e}")
            return FusionResult(
                final_attack_type="fusion_error",
                final_confidence=0.0,
                final_risk_score=0.0,
                consensus_level=0.0,
                conflict_resolution="error",
                contributing_experts=[],
                fusion_confidence=0.0,
                reasoning_summary=f"融合过程出现错误: {str(e)}",
                weighted_analysis={}
            )

    def _calculate_fusion_result(self, expert_results: List[ExpertResult], consensus_analysis: Dict, conflict_resolution: Dict) -> Dict[str, Any]:
        """计算最终融合结果"""
        final_attack_type = conflict_resolution['final_attack_type']

        # 获取支持最终攻击类型的专家结果
        supporting_results = [r for r in expert_results if r.attack_type == final_attack_type]

        if not supporting_results:
            # 如果没有支持的结果，使用所有结果计算加权平均
            supporting_results = expert_results

        # 计算加权置信度
        total_confidence_weight = 0.0
        weighted_confidence = 0.0
        total_risk_weight = 0.0
        weighted_risk = 0.0

        for result in supporting_results:
            weight = self.weight_manager.get_expert_weight(result.expert_id)

            # 置信度加权
            confidence_contribution = weight * result.confidence
            weighted_confidence += confidence_contribution
            total_confidence_weight += weight

            # 风险评分加权
            risk_contribution = weight * result.risk_score
            weighted_risk += risk_contribution
            total_risk_weight += weight

        # 计算最终值
        final_confidence = weighted_confidence / total_confidence_weight if total_confidence_weight > 0 else 0.0
        final_risk_score = weighted_risk / total_risk_weight if total_risk_weight > 0 else 5.0

        # 计算融合置信度（考虑共识程度）
        fusion_confidence = final_confidence * consensus_analysis['consensus_level']

        # 应用冲突解决的置信度调整
        if 'resolution_confidence' in conflict_resolution:
            fusion_confidence = min(fusion_confidence, conflict_resolution['resolution_confidence'])

        return {
            'attack_type': final_attack_type,
            'confidence': final_confidence,
            'risk_score': final_risk_score,
            'fusion_confidence': fusion_confidence,
            'supporting_experts': [r.expert_id for r in supporting_results],
            'supporting_expert_count': len(supporting_results),
            'weight_distribution': {r.expert_id: self.weight_manager.get_expert_weight(r.expert_id) for r in supporting_results}
        }

    def _generate_reasoning_summary(self, expert_results: List[ExpertResult], consensus_analysis: Dict, conflict_resolution: Dict, final_result: Dict) -> str:
        """生成推理总结"""
        summary_parts = []

        # 基础信息
        summary_parts.append(f"收到{len(expert_results)}个专家的分析结果")

        # 共识情况
        consensus_level = consensus_analysis['consensus_level']
        if consensus_level >= 0.8:
            summary_parts.append("专家意见高度一致")
        elif consensus_level >= 0.6:
            summary_parts.append("专家意见基本一致")
        else:
            summary_parts.append("专家意见存在分歧")

        # 冲突解决
        summary_parts.append(f"采用{conflict_resolution.get('explanation', '默认策略')}")

        # 最终结果
        summary_parts.append(f"最终确定为{final_result['attack_type']}，置信度{final_result['confidence']:.3f}")

        # 支持专家
        if final_result.get('supporting_experts'):
            summary_parts.append(f"主要支持专家: {', '.join(final_result['supporting_experts'][:3])}")

        return "；".join(summary_parts)

    def update_feedback(self, expert_results: List[ExpertResult], fusion_result: FusionResult, actual_outcome: str, accuracy_score: float = None):
        """更新反馈，用于自适应学习"""
        try:
            # 为每个专家更新性能数据
            for result in expert_results:
                # 判断该专家的预测是否正确
                expert_correct = (result.attack_type == actual_outcome)

                # 计算反馈分数
                if accuracy_score is not None:
                    feedback_score = accuracy_score if expert_correct else 0.0
                else:
                    feedback_score = 1.0 if expert_correct else 0.0

                # 更新专家性能
                self.weight_manager.update_expert_performance(
                    result.expert_id,
                    result,
                    expert_correct,
                    feedback_score
                )

            logger.info(f"融合反馈更新完成，实际结果: {actual_outcome}")

        except Exception as e:
            logger.error(f"更新融合反馈失败: {e}")

    def get_fusion_statistics(self) -> Dict[str, Any]:
        """获取融合统计信息"""
        return {
            'weight_manager_stats': self.weight_manager.get_performance_stats(),
            'fusion_config': {
                'confidence_weight': self.confidence_weight,
                'risk_weight': self.risk_weight,
                'min_contributing_experts': self.min_contributing_experts
            }
        }