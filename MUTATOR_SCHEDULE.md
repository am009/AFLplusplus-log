# 基于环境变量的Mutator调度策略禁用

首先分析AFL++的Mutator调度策略，运行命令行如下：

```
./afl-fuzz -i /out/seeds -o /out/corpus -m none -t 1000+ -z -x ./afl++.dict -c /out/cmplog/ossfuzz -x /out/ossfuzz.dict -- /out/ossfuzz 2147483647
```

如果没有指定策略的话，默认的Mutator调度策略是什么？

2. 必须在代码逻辑被禁用的时候，打印出信息提示。并且使用static的bool变量保证这个只打印一次，防止淹没输出。
3. 同样使用static bool变量的方式降低getenv的开销，不用每次都查环境变量。



## AFL++ Mutator调度策略分析

### 给定命令行分析

```
./afl-fuzz -i /out/seeds -o /out/corpus -m none -t 1000+ -z -x ./afl++.dict -c /out/cmplog/ossfuzz -x /out/ossfuzz.dict -- /out/ossfuzz 2147483647
```

关键参数：
- `-z`：当前版本AFL++默认使用增强版确定性模糊测试，`-z`设置 `skip_deterministic = 1`
- `-x ./afl++.dict -x /out/ossfuzz.dict`：加载两个字典文件
- `-c /out/cmplog/ossfuzz`：启用CmpLog（比较日志），用于Input-to-State变异
- 未指定 `-p`：使用默认功率调度 **EXPLORE**（`include/afl-fuzz.h:344`）
- 未指定 `-u`：未启用splicing（`use_splicing = 0`）
- 未指定 `-L`：未启用MOpt模式（`limit_time_sig = 0`）
- 未指定 `-P`：未指定fuzz模式，默认 `fuzz_mode = 0`（exploration模式），且 `switch_fuzz_mode` 非零时会在一段时间无发现后自动切换到exploitation模式

### 默认功率调度：EXPLORE

未指定 `-p` 参数时，默认使用 `EXPLORE` 调度（`include/afl-fuzz.h:586`）。AFL++共支持9种功率调度（`include/afl-fuzz.h:344-356`）：

| 调度策略 | ID | 说明 |
|---------|-----|------|
| EXPLORE | 0 | 默认，基于探索的常量调度 |
| MMOPT | 1 | 修改版MOPT调度 |
| EXPLOIT | 2 | 基于利用的常量调度 |
| FAST | 3 | 指数调度 |
| COE | 4 | 截断指数调度 |
| LIN | 5 | 线性调度 |
| QUAD | 6 | 二次调度 |
| RARE | 7 | 稀有边调度 |
| SEEK | 8 | 忽略时间的EXPLORE |

功率调度影响 `calculate_score()`（`src/afl-fuzz-queue.c:1197-1485`）计算出的 `perf_score`，`perf_score` 决定了havoc阶段的迭代次数。

### Mutator执行流程

入口函数为 `fuzz_one()`（`src/afl-fuzz-one.c:6496`），根据 `limit_time_sig` 决定运行路径：
- `limit_time_sig == 0`（本命令行情况）：只运行 `fuzz_one_original()`
- `limit_time_sig > 0`：只运行MOpt（`pilot_fuzzing()` 或 `core_fuzzing()`）
- `limit_time_sig < 0`：两者都运行

#### `fuzz_one_original()` 的阶段顺序（`src/afl-fuzz-one.c:328`）

整个变异流程是**顺序执行、有条件跳过**，不是加权随机选择：

```
1. 校准阶段 (calibration)
2. 修剪阶段 (trimming)
3. 确定性阶段 (deterministic) —— 本命令行中被 -z 跳过
   ├── bitflip 1/1, 2/1, 4/1, 8/8, 16/8, 32/8
   ├── arith 8/8, 16/8, 32/8
   ├── interest 8/8, 16/8, 32/8
   └── extras (user/auto, overwrite/insert)
4. Custom Mutator阶段 —— 本命令行未加载自定义mutator，跳过
5. Havoc阶段（随机堆叠变异）—— 主要变异阶段
6. Splice阶段（拼接+havoc）—— 本命令行未启用 -u，跳过
```

**在本命令行配置下，实际只执行 Havoc 阶段。**

### Havoc阶段详解（`src/afl-fuzz-one.c:2091-3517`）

Havoc是AFL++的核心非确定性变异阶段，执行流程如下：

**1. 迭代次数计算**（`src/afl-fuzz-one.c:2125-2150`）：

```c
stage_max = (HAVOC_CYCLES * perf_score / havoc_div) >> 8;
// HAVOC_CYCLES = 256 (include/config.h:213)
// 如果做了确定性阶段则用 HAVOC_CYCLES_INIT = 1024
// 最小值 HAVOC_MIN = 12
```

**2. 变异数组选择**（`src/afl-fuzz-one.c:2187-2243`）：

根据 `input_mode` 和 `fuzz_mode` 选择不同的变异算子概率分布数组：

| input_mode | fuzz_mode=0 (exploration) | fuzz_mode=1 (exploitation) |
|-----------|---------------------------|---------------------------|
| 默认/TEXT (0/1) | `binary_array` | `text_array` |
| BINARY (2) | `mutation_strategy_exploration_binary` | `mutation_strategy_exploitation_binary` |

**3. 堆叠变异执行**（`src/afl-fuzz-one.c:2262-2277`）：

```c
stack_max = 1 << (1 + rand_below(afl, havoc_stack_pow2));
// havoc_stack_pow2 默认 = 4 (HAVOC_STACK_POW2, include/config.h:239)
// 所以 stack_max ∈ {2, 4, 8, 16}
// 每轮执行 use_stacking = 1 + rand_below(stack_max) 次堆叠变异
```

每次迭代随机从变异数组中选择 1~stack_max 个变异算子依次叠加执行。

**4. 37种Havoc变异算子**（`include/afl-mutations.h:44-86`）：

| ID | 算子名称 | 说明 |
|----|---------|------|
| 0 | MUT_FLIPBIT | 翻转随机位 |
| 1 | MUT_INTERESTING8 | 替换为8位特殊值 |
| 2 | MUT_INTERESTING16 | 替换为16位特殊值(LE) |
| 3 | MUT_INTERESTING16BE | 替换为16位特殊值(BE) |
| 4 | MUT_INTERESTING32 | 替换为32位特殊值(LE) |
| 5 | MUT_INTERESTING32BE | 替换为32位特殊值(BE) |
| 6-15 | MUT_ARITH8_~MUT_ARITH32BE | 各种算术加减操作 |
| 16 | MUT_RAND8 | 随机设置字节 |
| 17 | MUT_CLONE_COPY | 克隆复制区域 |
| 18 | MUT_CLONE_FIXED | 克隆固定值 |
| 19 | MUT_OVERWRITE_COPY | 覆写复制区域 |
| 20 | MUT_OVERWRITE_FIXED | 覆写固定值 |
| 21 | MUT_BYTEADD | 字节加法 |
| 22 | MUT_BYTESUB | 字节减法 |
| 23 | MUT_FLIP8 | 翻转字节 |
| 24 | MUT_SWITCH | 交换两个区域 |
| 25 | MUT_DEL | 删除一段区域 |
| 26 | MUT_SHUFFLE | 打乱区域 |
| 27 | MUT_DELONE | 删除单字节 |
| 28 | MUT_INSERTONE | 插入单字节 |
| 29 | MUT_ASCIINUM | ASCII数字变异 |
| 30 | MUT_INSERTASCIINUM | 插入ASCII数字 |
| 31 | MUT_EXTRA_OVERWRITE | 字典项覆写 |
| 32 | MUT_EXTRA_INSERT | 字典项插入 |
| 33 | MUT_AUTO_EXTRA_OVERWRITE | 自动字典项覆写 |
| 34 | MUT_AUTO_EXTRA_INSERT | 自动字典项插入 |
| 35 | MUT_SPLICE_OVERWRITE | 拼接覆写 |
| 36 | MUT_SPLICE_INSERT | 拼接插入 |

这些算子在不同的变异数组中以不同频率出现，实现了概率加权选择。

### CmpLog的额外影响

命令行中 `-c` 启用了CmpLog，这意味着在 `fuzz_one_original()` 之外，还会执行：
- **Colorization阶段**（STAGE_COLORIZATION）：对输入着色以确定哪些字节影响比较操作
- **Input-to-State阶段**（STAGE_ITS / RedQueen）：基于比较日志直接替换输入字节来绕过比较

这些由 `afl-fuzz-redqueen.c` 中的逻辑处理，作为额外的变异手段补充Havoc阶段。

### Custom Mutator的交互

如果加载了自定义mutator（通过 `AFL_CUSTOM_MUTATOR_LIBRARY`），它会在两个位置参与：
1. **独立的Custom Mutator阶段**（`src/afl-fuzz-one.c:1938-2086`）：在确定性阶段之后、havoc之前执行
2. **Havoc阶段内嵌**（`src/afl-fuzz-one.c:2279-2312`）：如果自定义mutator支持 `stacked_custom`，在havoc的每轮堆叠中有概率被调用
3. **AFL_CUSTOM_MUTATOR_ONLY**：设置后跳过所有内置变异，只用自定义mutator

### 总结

在给定命令行下（`-z` 跳过确定性，无 `-u`/`-L`/`-P`，默认EXPLORE调度），AFL++的Mutator调度策略为：
1. 种子选择由 `create_alias_table()` + `select_next_queue_entry()` 基于加权概率完成
2. 变异几乎全部发生在 **Havoc阶段**，通过从概率加权数组中随机选择1~16个变异算子堆叠执行
3. Havoc迭代次数由 `perf_score`（受EXPLORE功率调度影响）决定
4. CmpLog的Input-to-State变异提供额外的智能字节替换
5. 变异算子的选择概率由变异数组（如 `binary_array`）的权重分布决定，exploration和exploitation模式使用不同的数组

---

## MOpt模式详解

MOpt（Mutator Optimization）是AFL++集成的一种基于粒子群优化（PSO）的变异算子调度策略，通过学习各变异算子的效率来动态调整它们的选择概率。

### 启用MOpt模式

通过 `-L` 参数启用MOpt模式（`src/afl-fuzz.c:1408-1523`）：

```bash
# 只运行MOpt（limit_time_sig > 0）
./afl-fuzz -L 5 -i seeds -o corpus -- ./target

# 同时运行默认mutator和MOpt（limit_time_sig < 0）
./afl-fuzz -L -1 -i seeds -o corpus -- ./target

# limit_time_puppet = 0 时启用 pacemaker 模式
./afl-fuzz -L 0 -i seeds -o corpus -- ./target
```

**`-L` 参数含义**：
- `-L <minutes>`：MOpt的pacemaker计时器周期（分钟）
- `-L 0`：启用pacemaker模式（`key_puppet = 1`）
- `-L -1`：同时运行默认mutator和MOpt（`limit_time_sig = -1`）
- `-L N`（N > 0）：只运行MOpt，N分钟后评估swarm效率（`limit_time_sig = 1`）

### MOpt的关键参数

定义在 `include/afl-fuzz.h:323-340`：

```c
#define operator_num 19      // 19种变异算子
#define swarm_num 5          // 5个粒子群（swarm）
#define period_core 500000   // core模式评估周期（执行次数）
#define period_pilot 50000   // pilot模式评估周期（执行次数）
```

### MOpt的三种模式切换

MOpt通过 `key_module` 变量（`src/afl-fuzz-one.c:6618-6630`）在三种模式间切换：

```c
if (afl->key_module == 0) {
    key_val_lv_2 = pilot_fuzzing(afl);    // Pilot模式
} else if (afl->key_module == 1) {
    key_val_lv_2 = core_fuzzing(afl);     // Core模式
} else if (afl->key_module == 2) {
    pso_updating(afl);                     // PSO更新
}
```

**模式切换流程**：

```
┌─────────────────────────────────────────────────────────────┐
│                    key_module = 0                            │
│                    Pilot模式                                 │
│  遍历5个swarm，每个swarm运行period_pilot(50000)次           │
│  收集各算子效率数据                                          │
└────────────────────────┬────────────────────────────────────┘
                         │ 5个swarm都完成后
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    key_module = 1                            │
│                    Core模式                                  │
│  选择最优swarm，运行period_core(500000)次                   │
│  使用学习到的最优概率分布                                    │
└────────────────────────┬────────────────────────────────────┘
                         │ Core周期完成后
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    key_module = 2                            │
│                    PSO更新                                   │
│  根据各算子效果更新概率，重新开始Pilot                       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼ key_module = 0，循环
```

### MOpt的19种变异算子

MOpt使用与标准Havoc不同的算子编号（`src/afl-fuzz-one.c:5356-6029`）：

| Case ID | 算子 | 说明 | 统计变量 |
|---------|------|------|----------|
| 0 | FLIP_BIT1 | 翻转1位 | STAGE_FLIP1 |
| 1 | FLIP_BIT2 | 翻转2位 | STAGE_FLIP2 |
| 2 | FLIP_BIT4 | 翻转4位 | STAGE_FLIP4 |
| 3 | FLIP_BIT8 | 翻转8位（1字节） | STAGE_FLIP8 |
| 4 | FLIP_BIT16 | 翻转16位（2字节） | STAGE_FLIP16 |
| 5 | FLIP_BIT32 | 翻转32位（4字节） | STAGE_FLIP32 |
| 6 | ARITH8 | 8位算术加减 | STAGE_ARITH8 |
| 7 | ARITH16 | 16位算术加减 | STAGE_ARITH16 |
| 8 | ARITH32 | 32位算术加减 | STAGE_ARITH32 |
| 9 | INTERESTING8 | 8位特殊值 | STAGE_INTEREST8 |
| 10 | INTERESTING16 | 16位特殊值 | STAGE_INTEREST16 |
| 11 | INTERESTING32 | 32位特殊值 | STAGE_INTEREST32 |
| 12 | RAND8 | 随机字节 | STAGE_RANDOMBYTE |
| 13 | DELETE | 删除块 | STAGE_DELETEBYTE |
| 14 | CLONE | 克隆/插入块 | STAGE_Clone75 |
| 15 | OVERWRITE | 覆写块 | STAGE_OverWrite75 |
| 16 | EXTRA_OVERWRITE | 字典覆写 | STAGE_OverWriteExtra |
| 17 | EXTRA_INSERT | 字典插入 | STAGE_InsertExtra |
| 18 | SPLICE | 拼接（需要expand_havoc） | STAGE_Splice |

### PSO算法核心

MOpt使用粒子群优化算法动态调整各算子的选择概率（`src/afl-fuzz-one.c:6403-6492`）：

**状态变量**（`include/afl-fuzz.h:536-552`）：
```c
double x_now[swarm_num][operator_num];      // 当前位置（概率）
double v_now[swarm_num][operator_num];      // 当前速度
double L_best[swarm_num][operator_num];     // 局部最优
double G_best[operator_num];                 // 全局最优
double probability_now[swarm_num][operator_num];  // 累积概率分布
double swarm_fitness[swarm_num];            // swarm适应度
```

**算子选择**（`src/afl-fuzz-one.c:35-73`）：
```c
static int select_algorithm(afl_state_t *afl, u32 max_algorithm) {
    // 根据累积概率分布选择算子
    double sele = rand_below(afl, 10000) * 0.0001 * range_sele;
    for (i = 0; i < operator_num; i++) {
        if (sele < probability_now[swarm_now][i]) break;
    }
    return i;
}
```

**PSO更新公式**（`src/afl-fuzz-one.c:6445-6449`）：
```c
// 速度更新
v_now[swarm][i] = w_now * v_now[swarm][i]
    + RAND_C * (L_best[swarm][i] - x_now[swarm][i])   // 局部引导
    + RAND_C * (G_best[i] - x_now[swarm][i]);         // 全局引导

// 位置更新
x_now[swarm][i] += v_now[swarm][i];

// 限制范围 [v_min, v_max] = [0.05, 1]
if (x_now[swarm][i] > v_max) x_now[swarm][i] = v_max;
if (x_now[swarm][i] < v_min) x_now[swarm][i] = v_min;
```

其中：
- `w_now`：惯性权重，从 `w_init=0.9` 线性递减到 `w_end=0.3`
- `RAND_C`：随机因子 `rand() % 1000 * 0.001`
- `L_best`：该swarm历史最优
- `G_best`：全局历史最优

### Pilot vs Core模式差异

| 特性 | Pilot模式 | Core模式 |
|------|----------|----------|
| `is_pilot_mode` | 1 | 0 |
| 评估周期 | 50,000次执行 | 500,000次执行 |
| swarm数量 | 遍历5个swarm | 只用最优swarm |
| 阶段名称 | "MOpt-havoc" | "MOpt-core-havoc" |
| 目的 | 探索各算子效率 | 利用最优配置 |

### 效率计算

每个算子的效率（`src/afl-fuzz-one.c:6289-6293`）：
```c
temp_eff = (finds_v2[i] - finds[i]) / (cycles_v2[i] - cycles[i]);
// finds: 该算子发现的新路径数
// cycles: 该算子执行次数
// 效率 = 新发现数 / 执行次数
```

Swarm的适应度（`src/afl-fuzz-one.c:6276-6278`）：
```c
swarm_fitness[swarm_now] = (total_puppet_find - temp_puppet_find)
                          / (tmp_pilot_time / period_pilot_tmp);
// 该swarm周期内发现数 / 归一化时间
```

### MOpt的副作用

启用 `-L` 参数时还会触发：
1. `havoc_max_mult = HAVOC_MAX_MULT_MOPT`（64，与默认相同）
2. `old_seed_selection = 1`：使用旧版种子选择
3. 初始化5个swarm的PSO参数（`src/afl-fuzz.c:1456-1517`）

### 与标准Havoc的对比

| 特性 | 标准Havoc | MOpt Havoc |
|------|----------|------------|
| 算子选择 | 从固定数组随机选择 | PSO动态调整概率 |
| 算子数量 | 37种（MUT_*） | 19种（简化版） |
| 概率分布 | 静态（数组权重） | 动态学习 |
| 字典支持 | 通过数组权重 | 独立case处理 |
| 拼接 | 独立Splice阶段 | 集成在算子中（case 18） |

### 使用建议

1. **短期测试**：使用默认模式，MOpt需要时间学习
2. **长期模糊测试**：启用 `-L` 可能提高效率
3. **同时运行**：`-L -1` 可以同时获得两种策略的好处
4. **pacemaker模式**：`-L 0` 适合持续运行的场景
