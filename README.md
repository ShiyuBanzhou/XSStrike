# XSStrike 功能修改报告：爬虫与漏洞结果导出

## 目标

为了更方便地分析和利用 XSStrike 的扫描结果，我们对其进行了修改，主要实现了以下两个功能：

1.  自动保存爬虫处理过的所有 URL 和发现的表单信息。
2.  自动收集合并扫描和爬取过程中发现的潜在 XSS 漏洞信息（包括 URL、参数、有效 Payload），并保存为结构化的 JSON 文件。

## 修改一：爬虫结果导出 (直接修改 `photon` 函数)

* **修改文件:** `core/photon.py`
* **实现功能:**
    * 在核心爬虫函数 `photon` 执行完毕、返回结果之前，自动将数据写入文件。
    * **输出文件 1:** `crawled_urls_photon.txt` - 包含爬虫访问和处理过的 **所有 URL** 列表（每行一个，已排序）。
    * **输出文件 2:** `found_forms_photon.json` - 包含爬虫发现的 **所有 HTML 表单** 详细信息（JSON 格式）。
* **关键代码点:**
    * 在 `photon` 函数末尾的 `return [forms, processed]` 语句**之前**添加了文件写入逻辑。
    * 使用了 Python 的文件操作 (`with open(...)`) 和 `json.dump()`。

## 修改二：潜在漏洞与 Payload 导出 (多文件协作)

* **修改文件:**
    * `xsstrike.py`
    * `modes/scan.py`
    * `modes/crawl.py`
* **实现功能:**
    * 在扫描 (`scan`) 或爬取 (`crawl`) 过程中，当检测到潜在的 XSS 漏洞（即找到有效的攻击向量/Payload）时，将该漏洞的相关信息记录下来。
    * 记录的信息包括：漏洞所在的 URL、被测试的参数名、有效的 Payload、检测模式（scan 或 crawl）、置信度 (Confidence)、效率 (Efficiency，仅 scan 模式)。
    * 在整个 XSStrike 程序执行**结束时**，将所有记录到的漏洞信息进行去重（基于 URL、参数、Payload），并统一保存到一个文件中。
    * **输出文件:** `vulnerable_findings.json` - 包含所有去重后的潜在漏洞发现记录（JSON 格式，每个记录是一个对象）。
* **关键代码点:**
    * **`xsstrike.py`:**
        * 在程序开始处初始化了一个全局列表 `core.config.globalVariables['vulnerabilities'] = []` 用于收集漏洞。
        * 在程序**最末尾**的 `finally` 块中添加了代码，用于读取该列表、去重，并将最终结果写入 `vulnerable_findings.json`。
    * **`modes/scan.py`:**
        * 在 `scan` 函数内部判断 Payload 有效性（基于 `bestEfficiency` 和 `confidence`）的 `if` 语句块中，添加了将漏洞信息字典 `append` 到 `core.config.globalVariables['vulnerabilities']` 的代码。
    * **`modes/crawl.py`:**
        * 在 `crawl` 函数内部通过 `logger.vuln(...)` 报告漏洞的位置，添加了将漏洞信息字典 `append` 到 `core.config.globalVariables['vulnerabilities']` 的代码。

## 如何使用和验证

1.  **运行:** 正常使用 XSStrike 即可。
    * 运行单 URL 扫描 (`python xsstrike.py -u <url> ...`) 会触发 `modes/scan.py` 中的记录逻辑。
    * 运行爬虫模式 (`python xsstrike.py -u <url> --crawl ...` 或 `--seeds ...`) 会触发 `core/photon.py` 的文件保存，并触发 `modes/crawl.py` 中的记录逻辑。
2.  **查看结果:**
    * 爬虫执行后，检查运行目录下是否有 `crawled_urls_photon.txt` 和 `found_forms_photon.json`。
    * 整个程序（无论哪种模式）结束后，检查运行目录下是否有 `vulnerable_findings.json`，其中包含了检测到的漏洞信息。

**注意:** `crawled_urls_photon.txt` 包含所有爬取链接，而 `vulnerable_findings.json` 只包含检测到的潜在漏洞及对应 Payload。