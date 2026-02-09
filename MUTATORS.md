# Mutator按类别禁用

当前的目标是,设置环境变量开关一类mutator。比如设置了某个特殊环境变量后，将会关闭这一类mutator的使用。

2. 必须在代码逻辑被禁用的时候，打印出信息提示。并且使用static的bool变量保证这个只打印一次，防止淹没输出。
3. 同样使用static bool变量的方式降低getenv的开销，不用每次都查环境变量。

### Mutator的分类

```
mutator_unify_map = {
    "bitflip_1": "bitflip",
    "bitflip_2": "bitflip",
    "bitflip_4": "bitflip",
    "bitflip_8": "bitflip",
    "bitflip_16": "bitflip",
    "bitflip_32": "bitflip",
    "havoc_bitflip": "bitflip",
    "havoc_flip8": "bitflip",
    "mopt_bitflip_1": "bitflip",
    "mopt_bitflip_2": "bitflip",
    "mopt_bitflip_4": "bitflip",
    "mopt_bitflip_8": "bitflip",
    "mopt_bitflip_16": "bitflip",
    "mopt_bitflip_32": "bitflip",
    "mopt_havoc_bitflip1": "bitflip",
    "mopt_havoc_bitflip2": "bitflip",
    "mopt_havoc_bitflip4": "bitflip",
    "mopt_havoc_bitflip8": "bitflip",
    "mopt_havoc_bitflip16": "bitflip",
    "mopt_havoc_bitflip32": "bitflip",
    "bitflip": "bitflip",

    # --- Arithmetic ---
    "byte_inc": "arith",
    "byte_dec": "arith",
    "arith_8_add": "arith",
    "arith_8_minus": "arith",
    "arith_16_le_add": "arith",
    "arith_16_le_minus": "arith",
    "arith_16_be_add": "arith",
    "arith_16_be_minus": "arith",
    "arith_32_le_add": "arith",
    "arith_32_le_minus": "arith",
    "arith_32_be_add": "arith",
    "arith_32_be_minus": "arith",
    "havoc_arith_sub_8": "arith",
    "havoc_arith_add_8": "arith",
    "havoc_arith_sub_16_le": "arith",
    "havoc_arith_sub_16_be": "arith",
    "havoc_arith_add_16_le": "arith",
    "havoc_arith_add_16_be": "arith",
    "havoc_arith_sub_32_le": "arith",
    "havoc_arith_sub_32_be": "arith",
    "havoc_arith_add_32_le": "arith",
    "havoc_arith_add_32_be": "arith",
    "havoc_byteadd": "arith",
    "havoc_bytesub": "arith",
    "mopt_arith_8_add": "arith",
    "mopt_arith_8_minus": "arith",
    "mopt_arith_16_le_add": "arith",
    "mopt_arith_16_le_minus": "arith",
    "mopt_arith_16_be_add": "arith",
    "mopt_arith_16_be_minus": "arith",
    "mopt_arith_32_le_add": "arith",
    "mopt_arith_32_le_minus": "arith",
    "mopt_arith_32_be_add": "arith",
    "mopt_arith_32_be_minus": "arith",
    "mopt_havoc_arith8": "arith",
    "mopt_havoc_arith_sub_16_le": "arith",
    "mopt_havoc_arith_sub_16_be": "arith",
    "mopt_havoc_arith_add_16_le": "arith",
    "mopt_havoc_arith_add_16_be": "arith",
    "mopt_havoc_arith_sub_32_le": "arith",
    "mopt_havoc_arith_sub_32_be": "arith",
    "mopt_havoc_arith_add_32_le": "arith",
    "mopt_havoc_arith_add_32_be": "arith",
    "add_sub_2": "arith",
    "add_sub_8": "arith",
    "add_sub_4": "arith",
    "add_sub_1": "arith",

    # --- Interesting / Magic values ---
    "magic_values": "interesting",
    "interesting_8": "interesting",
    "interesting_16_le": "interesting",
    "interesting_16_be": "interesting",
    "interesting_32_le": "interesting",
    "interesting_32_be": "interesting",
    "havoc_interesting_8": "interesting",
    "havoc_interesting_16_le": "interesting",
    "havoc_interesting_16_be": "interesting",
    "havoc_interesting_32_le": "interesting",
    "havoc_interesting_32_be": "interesting",
    "mopt_interesting_8": "interesting",
    "mopt_interesting_16_le": "interesting",
    "mopt_interesting_16_be": "interesting",
    "mopt_interesting_32_le": "interesting",
    "mopt_interesting_32_be": "interesting",
    "mopt_havoc_interesting_8": "interesting",
    "mopt_havoc_interesting_16_le": "interesting",
    "mopt_havoc_interesting_16_be": "interesting",
    "mopt_havoc_interesting_32_le": "interesting",
    "mopt_havoc_interesting_32_be": "interesting",

    # --- Dictionary / Extra ---
    "static_dict": "dict_extra",
    "extra_rep": "dict_extra",
    "extra_ins": "dict_extra",
    "havoc_extra_rep": "dict_extra",
    "havoc_extra_ins": "dict_extra",
    "mopt_extra_rep": "dict_extra",
    "mopt_extra_ins": "dict_extra",
    "mopt_havoc_extra_rep": "dict_extra",
    "mopt_havoc_extra_ins": "dict_extra",

    "mopt_havoc_auto_extra_rep": "cmplog_auto_dict",
    "mopt_havoc_auto_extra_ins": "cmplog_auto_dict",
    "havoc_auto_extra_rep": "cmplog_auto_dict",
    "havoc_auto_extra_ins": "cmplog_auto_dict",
    "auto_extra_overwrite": "cmplog_auto_dict",
    "auto_extra_insert": "cmplog_auto_dict",
    "mopt_auto_extra_rep": "cmplog_auto_dict",
    "mopt_auto_extra_insert": "cmplog_auto_dict",

    # --- Random bytes ---
    "rnd_byte": "random_bytes",
    "rnd_bytes": "random_bytes",
    "pure_rnd_bytes": "random_bytes",
    "rnd_memset": "random_bytes",
    "rnd_memclr": "random_bytes",
    "havoc_rnd_8": "random_bytes",
    "mopt_havoc_rnd_8": "random_bytes",

    # --- Structural byte-level mutations ---
    "rnd_memswap": "structural_bytes",
    "rnd_memcopy": "structural_bytes",
    "byte_repeat": "structural_bytes",
    "expand": "structural_bytes",
    "shrink": "structural_bytes",
    "havoc_clone": "structural_bytes",
    "havoc_ins": "structural_bytes",
    "havoc_rep": "structural_bytes",
    "havoc_rep_fixed": "structural_bytes",
    "havoc_switch": "structural_bytes",
    "havoc_del": "structural_bytes",
    "havoc_shuffle": "structural_bytes",
    "havoc_delone": "structural_bytes",
    "havoc_insertone": "structural_bytes",
    "mopt_havoc_clone": "structural_bytes",
    "mopt_havoc_rep": "structural_bytes",
    "mopt_havoc_rep_fixed": "structural_bytes",
    "mopt_havoc_del": "structural_bytes",

    # --- ASCII numbers ---
    "ascii_num": "ascii_num",
    "ascii_num_change": "ascii_num",
    "havoc_asciinum": "ascii_num",
    "havoc_insertasciinum": "ascii_num",

    # --- Splice ---
    "splice": "splice",
    "havoc_splice_overwrite": "splice",
    "havoc_splice_insert": "splice",
    "mopt_splice": "splice",
    "mopt_havoc_splice_overwrite": "splice",
    "mopt_havoc_splice_insert": "splice",
}
```

然后cmplog相关逻辑单独作为一类

## 实现规划

### 环境变量命名

| 类别 | 环境变量名 | 功能 |
|------|-----------|------|
| bitflip | `AFL_DISABLE_MUTATOR_BITFLIP` | 禁用所有位翻转变异 |
| arith | `AFL_DISABLE_MUTATOR_ARITH` | 禁用所有算术运算变异 |
| interesting | `AFL_DISABLE_MUTATOR_INTERESTING` | 禁用所有有趣值变异 |
| dict_extra | `AFL_DISABLE_MUTATOR_DICT_EXTRA` | 禁用用户字典变异 |
| cmplog_auto_dict | `AFL_DISABLE_MUTATOR_AUTO_EXTRA` | 禁用自动字典变异 |
| random_bytes | `AFL_DISABLE_MUTATOR_RANDOM_BYTES` | 禁用随机字节变异 |
| structural_bytes | `AFL_DISABLE_MUTATOR_STRUCTURAL` | 禁用结构性字节变异 |
| ascii_num | `AFL_DISABLE_MUTATOR_ASCII_NUM` | 禁用ASCII数字变异 |
| splice | `AFL_DISABLE_MUTATOR_SPLICE` | 禁用拼接变异 |
| cmplog | `AFL_DISABLE_CMPLOG` | 禁用CMPLog整体逻辑 |

### 需要修改的文件

#### 1. `src/afl-fuzz-one.c` - 确定性阶段和Havoc阶段调度

**bitflip确定性阶段** (行653-1008):
- STAGE_FLIP1 (行653-783): 需要检查 `AFL_DISABLE_MUTATOR_BITFLIP`
- STAGE_FLIP2 (行785-823): 同上
- STAGE_FLIP4 (行827-865): 同上
- STAGE_FLIP8 (行873-916): 同上
- STAGE_FLIP16 (行926-962): 同上
- STAGE_FLIP32 (行972-1008): 同上

**arith确定性阶段** (行1024-1388):
- STAGE_ARITH8 (行1024-1106): 需要检查 `AFL_DISABLE_MUTATOR_ARITH`
- STAGE_ARITH16 (行1116-1248): 同上
- STAGE_ARITH32 (行1258-1388): 同上

**interesting确定性阶段** (行1400-1645):
- STAGE_INTEREST8 (行1400-1457): 需要检查 `AFL_DISABLE_MUTATOR_INTERESTING`
- STAGE_INTEREST16 (行1467-1551): 同上
- STAGE_INTEREST32 (行1561-1645): 同上

**dict_extra确定性阶段** (行1661-1800):
- STAGE_EXTRAS_UO (行1661-1732): 需要检查 `AFL_DISABLE_MUTATOR_DICT_EXTRA`
- STAGE_EXTRAS_UI (行1734-1800): 同上

**cmplog_auto_dict确定性阶段** (行1802-1932):
- STAGE_EXTRAS_AO (行1802-1864): 需要检查 `AFL_DISABLE_MUTATOR_AUTO_EXTRA`
- STAGE_EXTRAS_AI (行1866-1932): 同上

**cmplog调用** (行555-593):
- 需要检查 `AFL_DISABLE_CMPLOG`

**splice阶段** (行3532-3689):
- 需要检查 `AFL_DISABLE_MUTATOR_SPLICE`

#### 2. `include/afl-mutations.h` - Havoc阶段内联变异

在 `afl_mutate()` 函数中 (行1801-2735)，需要为每个MUT_*类型添加检查：

**bitflip类**:
- MUT_FLIPBIT (行1871-1880)
- MUT_FLIP8 (行2224-2230)

**arith类**:
- MUT_ARITH8 (行1944-1958)
- MUT_ARITH8_* (行1960-1973)
- MUT_ARITH16_* (行1975-2017)
- MUT_ARITH32_* (行2019-2073)
- MUT_BYTEADD (行2206-2213)
- MUT_BYTESUB (行2215-2221)

**interesting类**:
- MUT_INTERESTING8 (行1882-1891)
- MUT_INTERESTING16/BE (行1893-1918)
- MUT_INTERESTING32/BE (行1920-1942)

**dict_extra类**:
- MUT_EXTRA_OVERWRITE (行2595-2610)
- MUT_EXTRA_INSERT (行2613-2632)

**cmplog_auto_dict类**:
- MUT_AUTO_EXTRA_OVERWRITE (行2635-2650)
- MUT_AUTO_EXTRA_INSERT (行2653-2672)

**random_bytes类**:
- MUT_RAND8 (行2076-2087)
- 部分 MUT_CLONE_FIXED (随机字节填充部分, 行2128-2166)
- 部分 MUT_OVERWRITE_FIXED (随机字节填充部分, 行2189-2203)

**structural_bytes类**:
- MUT_CLONE_COPY (行2089-2126)
- MUT_OVERWRITE_COPY (行2169-2186)
- MUT_SWITCH (行2233-2274)
- MUT_DEL (行2277-2292)
- MUT_SHUFFLE (行2295-2320)
- MUT_DELONE (行2323-2339)
- MUT_INSERTONE (行2342-2368)

**ascii_num类**:
- MUT_ASCIINUM (行2371-2550)
- MUT_INSERTASCIINUM (行2552-2592)

**splice类**:
- MUT_SPLICE_OVERWRITE (行2675-2692)
- MUT_SPLICE_INSERT (行2695-2724)

#### 3. `src/afl-fuzz-cmplog.c` - CMPLog整体禁用

- 在 `common_fuzz_cmplog_stuff()` 函数中添加检查

### 实现模式

代码中有三个需要修改的位置：
- `src/afl-fuzz-one.c` 中的 `fuzz_one_original()` 函数 — 确定性阶段
- `src/afl-fuzz-one.c` 中的 `mopt_common_fuzzing()` 函数 — mopt版确定性阶段
- `include/afl-mutations.h` 中的 `afl_mutate()` 函数 — havoc阶段变异

三个函数各自独立，static变量不共享，各自需要独立的 static 变量（接受冗余）。

#### 确定性阶段（fuzz_one_original / mopt_common_fuzzing）

在对应阶段代码前插入检查，禁用时 `goto skip_xxx` 跳过整个阶段组：

```c
static u8 disable_xxx = 0xFF;
static u8 xxx_msg_shown = 0;

if (unlikely(disable_xxx == 0xFF)) {
  u8 *env_val = getenv("AFL_DISABLE_MUTATOR_XXX");
  disable_xxx = (env_val && env_val[0]) ? 1 : 0;
}

if (unlikely(disable_xxx)) {
  if (unlikely(!xxx_msg_shown)) {
    ACTF("Xxx mutator disabled (AFL_DISABLE_MUTATOR_XXX set)");
    xxx_msg_shown = 1;
  }
  goto skip_xxx;
}
```

对于mopt版本，变量名加 `mopt_` 前缀以避免冲突。

#### Havoc阶段（afl_mutate）

在 `afl_mutate()` 函数开头添加 static 变量和一次性 getenv 检查。
在每个相关 `case MUT_XXX:` 中添加：

```c
if (unlikely(disable_xxx_havoc)) { goto retry_havoc_step; }
```

`retry_havoc_step` 会重新随机选择另一个mutation，避免浪费这次变异机会。

#### 重要的跳转标签

确定性阶段中已有的跳转标签（fuzz_one_original 和 mopt_common_fuzzing 中都有）：
- `skip_bitflip:` — bitflip阶段后
- `skip_arith:` — arith阶段后
- `skip_interest:` — interest阶段后
- `skip_extras:` — extras(dict)阶段后
- `custom_mutator_stage:` — 进入自定义mutator / havoc阶段

### 实现进度

| # | 类别 | 环境变量 | 状态 |
|---|------|---------|------|
| 1 | bitflip | `AFL_DISABLE_MUTATOR_BITFLIP` | **已完成** |
| 2 | arith | `AFL_DISABLE_MUTATOR_ARITH` | **已完成** |
| 3 | interesting | `AFL_DISABLE_MUTATOR_INTERESTING` | **已完成** |
| 4 | dict_extra | `AFL_DISABLE_MUTATOR_DICT_EXTRA` | 已完成 |
| 5 | cmplog_auto_dict | `AFL_DISABLE_MUTATOR_AUTO_EXTRA` | 已完成 |
| 6 | random_bytes | `AFL_DISABLE_MUTATOR_RANDOM_BYTES` | 已完成 |
| 7 | structural_bytes | `AFL_DISABLE_MUTATOR_STRUCTURAL` | 已完成 |
| 8 | ascii_num | `AFL_DISABLE_MUTATOR_ASCII_NUM` | 待实现 |
| 9 | splice | `AFL_DISABLE_MUTATOR_SPLICE` | 待实现 |
| 10 | cmplog | `AFL_DISABLE_CMPLOG` | 待实现 |

### 已完成实现的具体修改记录

#### Commit 1: bitflip (96367149)

**`src/afl-fuzz-one.c`**:
- `fuzz_one_original()`: 在 `SIMPLE BITFLIP` 注释后、`#define FLIP_BIT` 前插入检查，禁用时 `goto skip_bitflip`
- `mopt_common_fuzzing()`: 同上位置，独立 static 变量（`mopt_disable_bitflip`）

**`include/afl-mutations.h`**:
- `afl_mutate()` 函数开头添加 `disable_bitflip_havoc` static 变量
- `case MUT_FLIPBIT:` 和 `case MUT_FLIP8:` 中添加 `goto retry_havoc_step`

#### Commit 2: arith (70a6da8e)

**`src/afl-fuzz-one.c`**:
- `fuzz_one_original()`: 在 `skip_bitflip:` 后、`ARITHMETIC INC/DEC` 注释前插入检查，禁用时 `goto skip_arith`
- `mopt_common_fuzzing()`: 同上位置，独立 static 变量（`mopt_disable_arith`）

**`include/afl-mutations.h`**:
- `afl_mutate()` 函数开头添加 `disable_arith_havoc` static 变量
- 以下 case 中添加 `goto retry_havoc_step`:
  - `MUT_ARITH8_`, `MUT_ARITH8`
  - `MUT_ARITH16_`, `MUT_ARITH16BE_`, `MUT_ARITH16`, `MUT_ARITH16BE`
  - `MUT_ARITH32_`, `MUT_ARITH32BE_`, `MUT_ARITH32`, `MUT_ARITH32BE`
  - `MUT_BYTEADD`, `MUT_BYTESUB`

#### Commit 3: interesting (180d445a)

**`src/afl-fuzz-one.c`**:
- `fuzz_one_original()`: 在 `skip_arith:` 后、`INTERESTING VALUES` 注释前插入检查，禁用时 `goto skip_interest`
- `mopt_common_fuzzing()`: 同上位置，独立 static 变量（`mopt_disable_interesting`）

**`include/afl-mutations.h`**:
- `afl_mutate()` 函数开头添加 `disable_interesting_havoc` static 变量
- 以下 case 中添加 `goto retry_havoc_step`:
  - `MUT_INTERESTING8`
  - `MUT_INTERESTING16`, `MUT_INTERESTING16BE`
  - `MUT_INTERESTING32`, `MUT_INTERESTING32BE`

### 测试验证

每个commit完成后:
1. 编译项目: `bash build.sh 2>&1 | tail -30`
