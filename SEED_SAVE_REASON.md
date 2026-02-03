# 基于环境变量修改种子保留原因

通常对于Fuzzer，除了crash，有两个重要的种子保留原因，一个是发现了新的边，另外一个是边的运行次数发生了变化。

现在需要，当设置了环境变量DISABLE_COV_BIN_COUNT的时候，不再考虑边的运行次数，而是仅在发现新的边的时候，才认为种子是interesting的，保留到队列中。

## AFL++的种子保留逻辑

### 1. 种子保留的整体流程

**主入口函数：`save_if_interesting()`**
- 文件：`src/afl-fuzz-bitmap.c:531-1119`
- 作用：执行每次目标程序运行后，判断该输入是否值得保留

### 2. "Interesting"的判定标准

种子被认为是"interesting"需要满足以下条件之一：

#### 2.1 新覆盖率检测（最重要）

**位置**：`save_if_interesting()` - 第679-696行
**函数调用链**：`calculate_new_bits_if_necessary()` -> `has_new_bits_unclassified()` -> `has_new_bits()`

**返回值含义：**
- `new_bits = 0`：无任何新的覆盖信息，种子**不保留**（除非是crash/hang）
- `new_bits = 1`：检测到**现有边的hit count变化**（打击计数增加），种子**保留**
- `new_bits = 2`：检测到**完全新的边（new edge）**，种子**保留**（优先级最高）

**相应标记：**
- `new_bits == 2` 时，标记 `afl->queue_top->has_new_cov = 1` 并增加 `afl->queued_with_cov` 计数器

#### 2.2 Crash和Hang检测

**位置**：`save_if_interesting()` - 第827-1078行

**处理逻辑：**
- `FSRV_RUN_CRASH`：保存到crashes目录，检查是否有新的crash-specific bit
- `FSRV_RUN_TMOUT`：保存到hangs目录，检查是否有新的timeout-specific bit

### 3. 新边（New Edge）的检测逻辑

**核心函数：`discover_word()`**
- 文件：`include/coverage-64.h:83-113`（64位）

**检测原理：**

```c
inline void discover_word(u8 *ret, u64 *current, u64 *virgin) {
  // current：当前执行的覆盖信息
  // virgin：未被触及的virgin位图（初始化为全1）

  if (*current & *virgin) {  // 如果current有任何bit在virgin中未被清除
    if (likely(*ret < 2)) {
      u8 *cur = (u8 *)current;
      u8 *vir = (u8 *)virgin;

      // 逐字节检查：如果有非零byte在virgin中仍为0xff（untouched）
      if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) || ... )
        *ret = 2;  // 新edge
      else
        *ret = 1;  // 现有edge的hit count变化
    }
    *virgin &= ~*current;  // 更新virgin位图：清除已触及的bits
  }
}
```

**逻辑解释：**

1. **Virgin位图初始状态**：所有字节初始化为 `0xff`（所有bits标记为未触及）
2. **边的触及**：当执行覆盖某个byte时，对应virgin中的bit被清除
3. **新边检测**：如果 `current` 中有非零值 AND `virgin` 中对应位为 `0xff`（完全未触及）→ 返回 `ret = 2`（新边）
4. **hit count变化检测**：如果 `current` 中有非零值但 `virgin` 中对应位已部分被清除 → 返回 `ret = 1`（现有边hit count变化）

### 4. Hit Count变化的检测机制

**Hit Count分类：`count_class_lookup8[]`**
- 文件：`src/afl-fuzz-bitmap.c:48-60`

```c
static const u8 count_class_lookup8[256] = {
  [0] = 0,           // 未执行
  [1] = 1,           // 执行1次
  [2] = 2,           // 执行2次
  [3] = 4,           // 执行3次
  [4 ... 7] = 8,     // 执行4-7次
  [8 ... 15] = 16,   // 执行8-15次
  [16 ... 31] = 32,  // 执行16-31次
  [32 ... 127] = 64, // 执行32-127次
  [128 ... 255] = 128// 执行128+次
};
```

**作用**：AFL++将精确的hit count归类到8个等级，这样可以：
- 减少虚假的coverage增长（避免 count 从1到2引起的频繁保存）
- 检测hit count等级的变化

### 5. Virgin位图的使用

AFL++维护三个Virgin位图（`include/afl-fuzz.h:620-622`）：

```c
u8 *virgin_bits;   // 通用的新bit追踪（正常执行）
u8 *virgin_tmout;  // timeout特定的virgin位图
u8 *virgin_crash;  // crash特定的virgin位图
```

**初始化状态**：所有位都设为 `0xff`（未触及）

### 6. 种子保留决策树

```
save_if_interesting()
├─ fault == FSRV_RUN_TMOUT 且 afl_ignore_timeouts
│  └─ 返回0（不保留）
│
├─ 非normal execution（fault != crash_mode）
│  └─ 跳转到may_save_fault处理crash/hang
│
└─ Normal execution
   ├─ new_bits == 0（无新覆盖）
   │  └─ san_fault == FSRV_RUN_OK
   │     └─ 返回0（不保留）
   │
   ├─ new_bits == 1 或 2（有新覆盖）
   │  └─ 进入save_to_queue
   │     ├─ 保存到queue目录
   │     ├─ 调用add_to_queue()
   │     ├─ calibrate_case()
   │     └─ update_bitmap_score()
   │
   └─ Crash/Hang处理
      ├─ FSRV_RUN_CRASH → 检查virgin_crash中的新bits
      └─ FSRV_RUN_TMOUT → 检查virgin_tmout中的新bits
```

### 7. 需要修改的位置

要实现 `DISABLE_COV_BIN_COUNT` 环境变量：

需要修改 `discover_word()` 函数（`include/coverage-64.h`），当设置了该环境变量时：
- 只在 `vir[x] == 0xff`（完全新的边）时才返回非零值
- 忽略现有边的hit count变化（即不返回 `ret = 1`，只返回 `ret = 0` 或 `ret = 2`）

或者在 `has_new_bits()` / `has_new_bits_unclassified()` 函数中进行过滤，当 `new_bits == 1` 时将其改为 `0`


