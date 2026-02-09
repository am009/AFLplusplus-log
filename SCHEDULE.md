# 基于环境变量的种子调度逻辑的部分禁用

需要修改AFL++，使它在检查到特定环境变量的时候，禁用相关的种子调度策略考量，包括是否倾向于更短的种子，是否倾向于coverage更多的种子，是否倾向于执行速度更快的种子。设置了环境变量后，就不再考虑对应的因素。

2. 必须在代码逻辑被禁用的时候，打印出信息提示。并且使用static的bool变量保证这个只打印一次，防止淹没输出。
3. 同样使用static bool变量的方式降低getenv的开销，不用每次都查环境变量。

此外, 还需要在相关分数计算逻辑的地方调用fuzzerlog_conf函数记录下使用过的策略.类似下方的形式,使用static bool保证仅打印一次.如果有多处地方有类似逻辑,则依次命名为prefer_higher_coverage_seeds1 prefer_higher_coverage_seeds2...
```
        /* FUZZERLOG: log strategy */
        static bool fuzzerlog_conf_done = false;
        if (!fuzzerlog_conf_done) {
            fuzzerlog_conf_done = true;
            fuzzerlog_conf("prefer_higher_coverage_seeds");
        }
```

需要尽量完整的记录种子调度策略,优先从下方已有名字中选用,没有的话就取一个名字.
- prefer_higher_coverage_seeds
- prefer_faster_seeds
- prefer_fresh_seeds
- prefer_shorter_seeds
- prefer_deeper_stack_seeds
- prefer_diverse_path_seeds
- prefer_less_selected_seeds
- prefer_shallow_depth_seeds


# AFL++ 种子调度机制分析

AFL++ 使用复杂的种子调度机制来决定从队列中选择哪个种子进行模糊测试。调度机制的核心目标是：
- 优先选择更有价值的种子（更可能发现新路径）
- 平衡探索（exploration）和利用（exploitation）
- 根据不同的调度策略调整选择概率

## 核心数据结构

### Queue Entry (队列条目)
每个种子在队列中都有以下关键属性：
- `weight`: 种子的权重，影响被选中的概率
- `perf_score`: 性能分数，决定模糊测试的能量分配
- `exec_us`: 执行时间（微秒）
- `bitmap_size`: 覆盖的位图大小
- `len`: 种子文件长度
- `depth`: 种子的深度（从初始种子派生的代数）
- `favored`: 是否为优选种子
- `was_fuzzed`: 是否已经被模糊测试过
- `fuzz_level`: 模糊测试的级别
- `n_fuzz_entry`: 被模糊测试的次数索引

## 调度机制的三个层次

### 1. 权重计算 (Weight Calculation)

权重计算在 `create_alias_table()` 函数中进行（src/afl-fuzz-queue.c:117-269）。

#### 基础权重因子

**执行时间因子** (lines 135-181):
```
t = q->exec_us / avg_exec_us

- t < 0.1:        weight *= 1.0    (非常快)
- 0.1 ≤ t ≤ 0.25: weight *= 0.95
- 0.25 < t ≤ 0.5: weight *= 1.0
- 0.5 < t ≤ 0.75: weight *= 1.05
- 0.75 < t ≤ 1.0: weight *= 1.1
- 1.0 < t < 1.25: weight *= 0.2    (异常：代码注释 "WTF ??? makes no sense")
- 1.25 ≤ t ≤ 1.5: weight *= 1.0
- 1.5 < t ≤ 2.0:  weight *= 1.1
- 2.0 < t ≤ 2.5:  weight *= 1.0
- 2.5 < t ≤ 5.0:  weight *= 1.15
- 5.0 < t ≤ 20.0: weight *= 1.1
- t > 20.0:       weight *= 1.0
```

**长度因子** (lines 184-217):
```
l = q->len / avg_len

- l < 0.1:        weight *= 0.5    (非常短的输入)
- 0.1 ≤ l ≤ 0.5:  weight *= 1.0
- 0.5 < l ≤ 1.25: weight *= 1.05
- 1.25 < l ≤ 1.75: weight *= 1.0
- 1.75 < l ≤ 2.0:  weight *= 0.95
- 2.0 < l ≤ 5.0:   weight *= 1.0
- 5.0 < l ≤ 10.0:  weight *= 1.05
- l > 10.0:        weight *= 1.15   (非常长的输入)
```

**位图覆盖因子** (lines 219-256):
```
bms = q->bitmap_size / avg_bitmap_size

- bms < 0.1:       weight *= 0.01   (覆盖率极低)
- 0.1 ≤ bms ≤ 0.25: weight *= 0.55
- 0.25 < bms ≤ 0.5: weight *= 1.0
- 0.5 < bms ≤ 0.75: weight *= 1.2
- 0.75 < bms ≤ 1.25: weight *= 1.3
- 1.25 < bms ≤ 1.75: weight *= 1.25
- 1.75 < bms ≤ 2.0:  weight *= 1.0
- 2.0 < bms ≤ 2.5:   weight *= 1.3
- bms > 2.5:         weight *= 0.75  (覆盖率过高可能不稳定)
```

**特殊修正因子** (lines 258-259):
- 未被模糊测试过: `weight *= 2.5`
- 冗余种子: `weight *= 0.75`

**模糊次数因子** (lines 126-130, 仅用于 FAST/COE/LIN/QUAD/MMOPT/RARE 策略):
```
hits = afl->n_fuzz[q->n_fuzz_entry]
if (hits > 0) {
    weight /= (log10(hits) + 1)
}
```
这确保被频繁模糊测试的种子权重降低。

#### MMOPT 策略的额外权重 (lines 271-283)
对于 MMOPT 调度策略，最近发现的 5 个种子权重翻倍：
```c
if (afl->schedule == MMOPT && afl->queued_discovered) {
    u32 cnt = min(afl->queued_discovered, 5);
    for (i = n - cnt; i < n; i++) {
        q->weight *= 2.0;
    }
}
```

### 2. Alias Method 选择算法

AFL++ 使用 **Alias Method**（别名方法）实现 O(1) 时间复杂度的加权随机选择。

#### Alias Table 构建 (lines 332-380)

1. **归一化概率**: 将权重转换为概率分布
   ```c
   P[i] = (queue_buf[i]->weight * n) / sum
   ```

2. **分类**: 将概率分为 Small (< 1) 和 Large (≥ 1) 两组

3. **构建别名表**:
   - 从 Small 和 Large 中各取一个
   - Small 的概率保持不变
   - Small 指向 Large 作为别名
   - 更新 Large 的剩余概率
   - 重复直到所有概率处理完毕

#### 选择算法 (lines 48-61)

```c
u32 select_next_queue_entry(afl_state_t *afl) {
    u32 s = rand_below(afl, afl->queued_items);  // 随机选择一个索引
    double p = rand_next_percent(afl);            // 随机生成 [0,1) 的概率

    // 如果 p < alias_probability[s]，返回 s
    // 否则返回 alias_table[s]（别名）
    return (p < afl->alias_probability[s] ? s : afl->alias_table[s]);
}
```

这个算法保证：
- 每个种子被选中的概率正比于其权重
- 选择操作的时间复杂度为 O(1)
- 不需要遍历整个队列

### 3. 性能分数计算 (Performance Score)

性能分数在 `calculate_score()` 函数中计算（src/afl-fuzz-queue.c:1197-1485），用于决定对每个种子分配多少模糊测试能量（havoc 阶段的迭代次数）。

#### 基础分数: 100

#### 执行速度调整 (lines 1219-1251)
仅用于 schedule < RARE 且非固定种子模式：

```
- q->exec_us * 0.1 > avg:  perf_score = 10   (非常慢，10%)
- q->exec_us * 0.25 > avg: perf_score = 25   (慢，25%)
- q->exec_us * 0.5 > avg:  perf_score = 50   (较慢，50%)
- q->exec_us * 0.75 > avg: perf_score = 75   (略慢，75%)
- q->exec_us * 4 < avg:    perf_score = 300  (非常快，3x)
- q->exec_us * 3 < avg:    perf_score = 200  (很快，2x)
- q->exec_us * 2 < avg:    perf_score = 150  (快，1.5x)
```

**设计理念**: 执行速度快的种子获得更多能量，因为可以在相同时间内执行更多次变异。
**争议**: 代码注释中提到这可能不是好主意（lines 1213-1217），因为执行时间长可能意味着覆盖更深。

#### 位图覆盖调整 (lines 1256-1280)

```
- q->bitmap_size * 0.3 > avg:  perf_score *= 3    (大覆盖，3x)
- q->bitmap_size * 0.5 > avg:  perf_score *= 2    (较大覆盖，2x)
- q->bitmap_size * 0.75 > avg: perf_score *= 1.5  (中等偏上，1.5x)
- q->bitmap_size * 3 < avg:    perf_score *= 0.25 (小覆盖，0.25x)
- q->bitmap_size * 2 < avg:    perf_score *= 0.5  (较小覆盖，0.5x)
- q->bitmap_size * 1.5 < avg:  perf_score *= 0.75 (中等偏下，0.75x)
```

**设计理念**: 覆盖率高的种子更有价值，应该获得更多能量。

#### Handicap 调整 (lines 1286-1296)

```
- handicap >= 4: perf_score *= 4, handicap -= 4
- handicap > 0:  perf_score *= 2, handicap -= 1
```

**设计理念**: 后期发现的种子获得临时加成，让它们有机会"追赶"早期种子。

#### 深度调整 (lines 1302-1318)

```
- depth 0-3:   perf_score *= 1
- depth 4-7:   perf_score *= 2
- depth 8-13:  perf_score *= 3
- depth 14-25: perf_score *= 4
- depth > 25:  perf_score *= 5
```

**设计理念**: 深度越大的种子（经过更多代变异）可能触发更深层的漏洞。

#### 调度策略特定调整 (lines 1324-1454)

AFL++ 支持多种调度策略，每种策略对性能分数有不同的调整：

**1. EXPLORE (探索模式)**
- 无额外调整，使用基础分数

**2. SEEK (寻找模式)**
- 无额外调整，使用基础分数

**3. EXPLOIT (利用模式)**
- `factor = MAX_FACTOR`
- 最大化利用已知有效的种子

**4. COE (Cut-Off Exponential)**
- 计算所有种子的平均模糊次数 `fuzz_mu`
- 如果当前种子的模糊次数超过平均值且不是 favored，则 `factor = 0`（跳过）
- 否则按 FAST 策略处理

**5. FAST (快速模式)**
- 根据模糊次数的对数调整：
  ```
  log2(n_fuzz) = 0-1:  factor = 4
  log2(n_fuzz) = 2-3:  factor = 3
  log2(n_fuzz) = 4:    factor = 2
  log2(n_fuzz) = 5:    factor = 1
  log2(n_fuzz) = 6:    factor = 0.8 (非 favored)
  log2(n_fuzz) = 7:    factor = 0.6 (非 favored)
  log2(n_fuzz) >= 8:   factor = 0.4 (非 favored)
  ```
- favored 种子额外获得 1.15x 加成

**6. LIN (线性模式)**
- `factor = fuzz_level / (n_fuzz + 1)`
- 线性递减

**7. QUAD (二次模式)**
- `factor = fuzz_level² / (n_fuzz + 1)`
- 二次递减

**8. MMOPT (Most Recently Modified Optimization)**
- 对最近 5 层深度的种子: `perf_score *= 2`
- 专注于最新发现的种子

**9. RARE (稀有模式)**
- `perf_score += (tc_ref * 10)` - 为每个 top_rated 引用加 10 分
- `perf_score *= (1 - n_fuzz / total_execs)` - 根据执行频率递减
- 专注于稀有路径

#### 最终调整 (lines 1456-1481)

```c
// EXPLOIT/COE/FAST/LIN/QUAD 策略应用 factor
if (schedule >= EXPLOIT && schedule <= QUAD) {
    if (factor > MAX_FACTOR) factor = MAX_FACTOR;
    perf_score *= factor / POWER_BETA;
}

// MOpt 模式：最近 3 层深度的种子加倍
if (limit_time_sig != 0 && max_depth - q->depth < 3) {
    perf_score *= 2;
}

// 下限保护（COE 除外）
if (schedule != COE && perf_score < 1) {
    perf_score = 1;
}

// 上限保护
if (perf_score > havoc_max_mult * 100) {
    perf_score = havoc_max_mult * 100;
}
```

## Top-Rated 选择机制

### update_bitmap_score() 函数 (lines 810-921)

AFL++ 为覆盖位图的每个字节维护一个 `top_rated[]` 数组，存储触发该字节的"最佳"种子。

#### 选择标准

对于每个被触发的位图字节，比较当前种子和已有的 top_rated：

1. **Fuzz Level 比较**:
   - FAST/COE/LIN/QUAD/MMOPT: 跳过 fuzz_p2 比较
   - RARE: `fuzz_p2 = next_pow2(n_fuzz[q->n_fuzz_entry])`
   - 其他: `fuzz_p2 = q->fuzz_level`
   - 如果当前种子的 fuzz_p2 更大，则不替换

2. **Favor Factor 比较**:
   - RARE 或固定种子模式: `fav_factor = len << 2`
   - 其他: `fav_factor = exec_us * len`
   - 如果当前种子的 fav_factor 更大，则不替换

3. **替换逻辑**:
   - 如果当前种子更优，替换 top_rated[i]
   - 减少旧种子的引用计数 `tc_ref`
   - 如果旧种子的 tc_ref 降为 0，释放其 trace_mini
   - 增加新种子的引用计数
   - 为新种子创建 trace_mini（压缩的位图）

**设计理念**:
- 执行快且文件小的种子更优（效率高）
- 每个位图字节只保留最优种子，减少冗余

### cull_queue() 函数 (lines 929-1009)

队列剔除过程标记"favored"（优选）种子，这些种子构成覆盖所有已知路径的最小集合。

#### 算法流程

1. **初始化**: 创建临时位图 `temp_v`，所有位设为 1

2. **清除 favored 标记**: 将所有种子的 favored 标记清零

3. **选择 favored 种子**:
   ```
   for each bitmap byte i:
       if top_rated[i] exists and temp_v[i] is set:
           mark top_rated[i] as favored
           remove top_rated[i]'s coverage from temp_v
   ```

4. **标记冗余**: 非 favored 的种子被标记为 `fs_redundant`
   - 如果启用 `AFL_DISABLE_REDUNDANT`，冗余种子会被禁用

5. **触发重建**: 设置 `reinit_table = 1`，下次调度时重建 alias table

**设计理念**:
- 集中资源在最小覆盖集上
- 减少对冗余种子的模糊测试
- 动态调整，随着新路径发现而更新

## 调度策略选择与切换

### 默认策略

AFL++ 默认使用 **EXPLORE** 策略 (src/afl-fuzz-state.c:90)。

### 动态策略切换

通过环境变量 `AFL_CYCLE_SCHEDULES=1` 启用动态切换，每完成一轮队列循环自动切换策略 (src/afl-fuzz.c:3507-3539)：

- **非AFLfast 组**：EXPLORE → EXPLOIT → MMOPT → SEEK → EXPLORE (循环)
- **AFLfast 组**：FAST → COE → LIN → QUAD → RARE → FAST (循环)

两组策略不能混合，因为 AFLfast 系列依赖 `n_fuzz` 数组跟踪模糊次数。

## 调度流程总结

### 完整的种子选择流程

1. **队列更新时** (新种子加入或路径发现):
   - 调用 `update_bitmap_score()` 更新 top_rated[]
   - 调用 `cull_queue()` 重新标记 favored 种子
   - 设置 `reinit_table = 1` 标记需要重建

2. **选择种子前** (如果 reinit_table == 1):
   - 调用 `create_alias_table()` 重建别名表
   - 计算所有种子的 weight 和 perf_score
   - 构建 alias_probability[] 和 alias_table[]

3. **选择种子**:
   - 调用 `select_next_queue_entry()` 使用 Alias Method
   - O(1) 时间复杂度，按权重概率选择

4. **模糊测试**:
   - 使用 perf_score 决定 havoc 阶段的迭代次数
   - 更高的 perf_score = 更多的变异尝试

## 关键设计要点

### 1. 多维度评估
AFL++ 不依赖单一指标，而是综合考虑：
- **执行速度**: 快速执行允许更多尝试
- **覆盖率**: 高覆盖率种子更有价值
- **文件大小**: 影响变异空间和执行效率
- **深度**: 深层种子可能触发复杂漏洞
- **新鲜度**: 未测试的种子和新发现的种子优先
- **稀有性**: 独特路径的种子更重要

### 2. 自适应调整
- **动态权重**: 根据模糊测试历史调整权重
- **Handicap 机制**: 给新种子追赶机会
- **Favored 标记**: 动态维护最小覆盖集
- **策略切换**: 支持多种调度策略适应不同场景

### 3. 效率优化
- **Alias Method**: O(1) 选择复杂度
- **Testcase Cache**: 缓存高权重种子减少 I/O
- **Top-rated 机制**: 避免冗余种子浪费资源
- **延迟重建**: 只在必要时重建 alias table

## 设计权衡与争议

### 3. 调度策略的选择
不同的调度策略适用于不同场景：

| 策略 | 适用场景 | 优点 | 缺点 |
|------|---------|------|------|
| EXPLORE | 初期探索 | 平衡探索 | 可能浪费资源在低价值种子 |
| FAST | 一般场景 | 快速收敛 | 可能过早放弃某些种子 |
| COE | 长时间运行 | 避免过度模糊测试 | 可能错过深层路径 |
| RARE | 寻找稀有路径 | 专注独特路径 | 可能忽略常见但重要的路径 |
| MMOPT | 持续发现新路径 | 专注最新发现 | 可能忽略旧但有价值的种子 |

## 源代码参考

### 核心函数位置 (src/afl-fuzz-queue.c)

| 函数名 | 行号 | 功能 |
|--------|------|------|
| `select_next_queue_entry()` | 48-61 | 使用 Alias Method 选择下一个种子 |
| `create_alias_table()` | 65-421 | 构建别名表和计算权重 |
| `calculate_score()` | 1197-1485 | 计算性能分数 |
| `update_bitmap_score()` | 810-921 | 更新 top_rated 数组 |
| `update_bitmap_rescore()` | 1096-1191 | 重新评估 top_rated（无需 trace_bits） |
| `cull_queue()` | 929-1009 | 标记 favored 种子 |
| `recalculate_all_scores()` | 1018-1090 | 重新计算所有分数 |
| `add_to_queue()` | 680-769 | 添加新种子到队列 |

## Favored 和 Top-Rated 标记的影响机制

### 概述

AFL++ 使用两个关键标记来优化种子调度：
- **Top-Rated**: 为每个位图字节标记最优种子（中间机制）
- **Favored**: 标记构成最小覆盖集的种子（直接影响调度）

这两个机制协同工作，形成 `Top-Rated → Favored → Weight/PerfScore → 选择概率/执行次数` 的影响链。

### Top-Rated 标记的影响

**Top-Rated** 是一个中间机制，主要用于确定哪些种子应该被标记为 favored，但在某些策略下也直接影响性能分数。

#### 1. 维护方式 (update_bitmap_score, lines 810-921)

- AFL++ 为位图的每个字节维护一个 `top_rated[]` 数组
- 存储触发该字节的"最佳"种子
- **选择标准**：
  - RARE 或固定种子模式：`fav_factor = len << 2`（文件大小优先）
  - 其他策略：`fav_factor = exec_us * len`（执行时间 × 文件大小）
  - fav_factor 越小越好（执行快 + 文件小）

#### 2. 对 RARE 策略的直接影响 (line 243)

```c
perf_score += (tc_ref * 10)
```

- `tc_ref`：该种子被多少个位图字节引用为 top_rated
- 每被一个位图字节引用，性能分数增加 10 分
- **结果**：在 RARE 策略下，top_rated 种子获得更多执行次数

#### 3. 对 Favored 标记的间接影响

Top-Rated 种子是 favored 种子的候选集：
- `cull_queue()` 从 top_rated[] 中选择种子标记为 favored
- 只有 top_rated 种子才可能成为 favored
- 形成最小覆盖集

### Favored 标记对选择概率的影响

**Favored** 标记通过影响种子的 **weight**（权重）来改变其被选中的概率。

#### 1. 冗余种子权重惩罚 (create_alias_table, lines 258-259)

```c
// 非 favored 种子被标记为 fs_redundant
if (q->fs_redundant) {
    weight *= 0.75;
}
```

- **影响**：非 favored（冗余）种子的选择概率降低到 75%
- **原因**：这些种子的覆盖路径已被 favored 种子覆盖
- **结果**：资源更多地分配给 favored 种子

#### 2. 选择概率计算

通过 Alias Method 算法，种子被选中的概率正比于其权重：

```
P(选中种子 i) ∝ weight_i
```

因此：
- Favored 种子：保持原始权重
- 非 favored 种子：权重 × 0.75
- **实际效果**：favored 种子被选中的概率约为非 favored 种子的 1.33 倍（假设其他因素相同）

### Favored 标记对执行次数的影响

**Favored** 标记通过影响 **perf_score**（性能分数）来决定每个种子被选中后的执行次数（havoc 阶段的迭代次数）。不同调度策略下影响程度不同。

#### 1. COE 策略：最严格的影响 (calculate_score, lines 1362-1378)

```c
// 计算平均模糊次数
fuzz_mu = afl->total_execs / afl->queued_items;

if (q->fuzz_level >= fuzz_mu && !q->favored) {
    factor = 0;  // 完全跳过
} else {
    // 按 FAST 策略处理
}
```

**影响**：
- 如果种子的模糊次数 ≥ 平均值 **且** 不是 favored：`factor = 0`
- **结果**：该种子被完全跳过，不分配任何执行次数
- **设计理念**：避免在已充分测试的非关键种子上浪费资源

#### 2. FAST 策略：渐进式影响 (calculate_score, lines 1380-1418)

```c
// 根据模糊次数的对数调整 factor
switch (log2_fuzz) {
    case 0 ... 1: factor = 4; break;
    case 2 ... 3: factor = 3; break;
    case 4:       factor = 2; break;
    case 5:       factor = 1; break;
    case 6:       factor = q->favored ? 1 : 0.8; break;
    case 7:       factor = q->favored ? 1 : 0.6; break;
    default:      factor = q->favored ? 1 : 0.4; break;
}

// Favored 种子额外加成
if (q->favored) {
    factor *= 1.15;
}
```

**影响**：
- **低模糊次数**（0-5 次）：favored 和非 favored 种子获得相同的 factor
- **中等模糊次数**（6-7 次）：非 favored 种子的 factor 降低到 0.6-0.8
- **高模糊次数**（≥8 次）：非 favored 种子的 factor 降低到 0.4
- **Favored 加成**：所有 favored 种子额外获得 1.15x 倍增
- **结果**：随着模糊次数增加，favored 和非 favored 种子的执行次数差距逐渐拉大

#### 3. 其他策略的影响

- **EXPLORE/SEEK**：无特殊处理，favored 和非 favored 种子平等对待
- **EXPLOIT**：使用最大 factor，不区分 favored
- **LIN/QUAD**：使用线性/二次递减，不直接区分 favored
- **MMOPT**：专注最近发现的种子，不直接区分 favored
- **RARE**：通过 tc_ref 间接优待 top_rated 种子（通常是 favored）

### 影响机制总结

#### 完整影响链

```
1. update_bitmap_score()
   └─> 为每个位图字节选择 top_rated 种子（执行快 + 文件小）

2. cull_queue()
   └─> 从 top_rated 中选择 favored 种子（最小覆盖集）
   └─> 标记非 favored 种子为 fs_redundant

3. create_alias_table()
   └─> 计算 weight：非 favored 种子 *= 0.75
   └─> 影响选择概率

4. calculate_score()
   └─> 计算 perf_score：
       - COE: 非 favored 且高模糊次数 → factor = 0
       - FAST: favored 种子 *= 1.15，非 favored 在高模糊次数时降低
   └─> 影响执行次数
```

#### 对比表：Favored vs 非 Favored 种子

| 维度 | Favored 种子 | 非 Favored 种子 | 差异倍数 |
|------|-------------|----------------|---------|
| **选择概率 (Weight)** | 1.0x | 0.75x | 1.33x |
| **COE 策略执行次数** | 正常分配 | 高模糊次数时 factor=0 | ∞（可能被跳过） |
| **FAST 策略执行次数** | 1.15x 加成 | 高模糊次数时 0.4-0.8x | 1.44-2.88x |
| **RARE 策略** | 通常有高 tc_ref | 通常 tc_ref=0 | +10 分/引用 |
| **资源分配优先级** | 高 | 低 | - |

#### 量化示例

假设一个 favored 种子和一个非 favored 种子，其他条件相同：

**选择阶段**：
- Favored 种子被选中概率：P
- 非 Favored 种子被选中概率：0.75P
- **差异**：favored 种子被选中的概率高 33%

**执行阶段（FAST 策略，高模糊次数）**：
- Favored 种子：perf_score × 1.15
- 非 Favored 种子：perf_score × 0.4
- **差异**：favored 种子的执行次数是非 favored 的 2.88 倍

**综合效果（FAST 策略）**：
- Favored 种子获得的总资源 ≈ 非 favored 的 **3.8 倍**（1.33 × 2.88）

### 关键设计原则

#### 1. 最小覆盖集策略

**目标**：用最少的种子覆盖所有已知路径

- Favored 种子构成最小覆盖集
- 非 favored 种子的路径已被 favored 覆盖（冗余）
- 资源集中在最小集合上，提高效率

#### 2. 渐进式资源削减

**策略**：不是立即放弃非 favored 种子，而是逐步减少资源

- 初期：favored 和非 favored 差异较小（仅 weight 0.75x）
- 中期：随着模糊次数增加，差异逐渐拉大
- 后期：COE 策略可能完全跳过非 favored 种子

**优点**：
- 给非 favored 种子一定机会，避免过早放弃
- 如果非 favored 种子表现好，可能重新成为 favored
- 平衡探索和利用

#### 3. 动态调整机制

**特点**：Favored 标记不是静态的

- 每次发现新路径时，调用 `update_bitmap_score()` 和 `cull_queue()`
- Top-rated 和 favored 标记会动态更新
- 种子的地位可能随时间变化

**实际影响**：
- 新发现的高价值种子可能快速成为 favored
- 原有 favored 种子可能被更优种子替代
- 保持调度策略的适应性

### 实践意义

#### 对模糊测试效率的影响

1. **减少冗余测试**：避免在覆盖相同路径的多个种子上重复工作
2. **加速收敛**：资源集中在高价值种子上，更快发现新路径
3. **长期运行优化**：COE 策略在长时间运行时避免资源浪费

#### 对调度策略选择的指导

- **FAST**：适合一般场景，favored 机制发挥明显作用
- **COE**：适合长时间运行，favored 机制作用最强
- **EXPLORE/SEEK**：favored 机制作用较弱，更平等对待所有种子
- **RARE**：通过 top_rated 机制间接利用 favored 概念

# 实现方式

### 修改位置

所有修改集中在 `src/afl-fuzz-queue.c` 的 `create_alias_table()` 函数中，对三个权重因子分别添加环境变量开关。

### 环境变量定义

| 环境变量 | 作用 | 禁用效果 |
|---------|------|---------|
| `AFL_DISABLE_EXEC_TIME_BIAS` | 禁用执行时间偏好 | 跳过执行时间权重调整，所有种子不再因执行速度差异而获得不同权重 |
| `AFL_DISABLE_SEED_LEN_BIAS` | 禁用种子长度偏好 | 跳过长度权重调整，所有种子不再因文件长度差异而获得不同权重 |
| `AFL_DISABLE_COVERAGE_BIAS` | 禁用覆盖率偏好 | 跳过覆盖率权重调整，所有种子不再因 bitmap_size 差异而获得不同权重 |

设置方式：将环境变量设置为任意非空值即可生效，例如 `export AFL_DISABLE_EXEC_TIME_BIAS=1`。

### 实现模式

每个环境变量开关遵循相同的代码模式：

```c
// 1. 使用 static 变量，初始化为 0xFF 作为"未检查"标记
static u8 disable_xxx_bias = 0xFF;
static u8 xxx_bias_msg_shown = 0;

// 2. 仅在首次调用时检查环境变量（0xFF 表示未检查过）
if (unlikely(disable_xxx_bias == 0xFF)) {
    u8 *env_val = getenv("AFL_DISABLE_XXX_BIAS");
    disable_xxx_bias = (env_val && env_val[0]) ? 1 : 0;
}

// 3. 未禁用时执行原有权重调整逻辑
if (likely(!disable_xxx_bias)) {
    // ... 原有的权重调整代码 ...

// 4. 禁用时仅打印一次提示信息
} else if (unlikely(!xxx_bias_msg_shown)) {
    ACTF("Xxx bias disabled (AFL_DISABLE_XXX_BIAS set)");
    xxx_bias_msg_shown = 1;
}
```

### 设计要点

1. **static 变量缓存环境变量状态**：`disable_xxx_bias` 初始值为 `0xFF`，首次进入时调用 `getenv()` 并将结果缓存为 `0` 或 `1`，后续调用不再查询环境变量，避免重复的 `getenv()` 开销。

2. **static 变量控制单次打印**：`xxx_bias_msg_shown` 确保禁用提示只打印一次，因为 `create_alias_table()` 在模糊测试过程中会被反复调用，不控制打印次数会淹没输出。

3. **使用 likely/unlikely 分支提示**：正常路径（未禁用）使用 `likely()`，异常路径（已禁用、首次检查）使用 `unlikely()`，帮助编译器优化分支预测。

4. **禁用时权重保持为 1.0**：当某个因子被禁用时，对应的 `weight *= ...` 代码被完整跳过，该维度的权重乘数保持默认的 1.0，即该因子对种子选择概率不产生任何影响。

### 每个 commit 的具体修改

每个特性的修改作为独立 commit 提交：

**Commit 1: 禁用执行时间偏好**
- 环境变量: `AFL_DISABLE_EXEC_TIME_BIAS`
- 修改位置: `create_alias_table()` 中执行时间权重调整代码块
- 效果: 跳过基于 `q->exec_us / avg_exec_us` 的权重调整

**Commit 2: 禁用覆盖率偏好**
- 环境变量: `AFL_DISABLE_COVERAGE_BIAS`
- 修改位置: `create_alias_table()` 中覆盖率权重调整代码块
- 效果: 跳过基于 `q->bitmap_size / avg_bitmap_size` 的权重调整

**Commit 3: 禁用种子长度偏好**
- 环境变量: `AFL_DISABLE_SEED_LEN_BIAS`
- 修改位置: `create_alias_table()` 中种子长度权重调整代码块
- 效果: 跳过基于 `q->len / avg_len` 的权重调整