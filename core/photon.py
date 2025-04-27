import re
import json # (导入 json 模块)
import concurrent.futures
from urllib.parse import urlparse
import core.config

from urllib.parse import urlencode, urlparse, urljoin, urlunparse, parse_qs
from core.dom import dom
from core.log import setup_logger
from core.utils import getUrl, getParams
from core.requester import requester
from core.zetanize import zetanize
from plugins.retireJs import retireJs

logger = setup_logger(__name__)


def photon(seedUrl, headers, level, threadCount, delay, timeout, skipDOM):
    forms = []  # web forms
    processed = set()  # urls that have been crawled
    storage = set()  # urls that belong to the target i.e. in-scope
    schema = urlparse(seedUrl).scheme  # extract the scheme e.g. http or https
    host = urlparse(seedUrl).netloc  # extract the host e.g. example.com
    main_url = schema + '://' + host  # join scheme and host to make the root url
    storage.add(seedUrl)  # add the url to storage
    checkedDOMs = []

    def rec(target):
        # --- 检查 target 是否为 None 或空字符串 ---
        if not target:
             logger.debug(f"Skipping invalid target URL: {target}")
             return
        # ---  ---
        try: # --- 添加 try-except 块处理可能的错误 ---
            processed.add(target)
            printableTarget = '/'.join(target.split('/')[3:])
            if len(printableTarget) > 40:
                printableTarget = printableTarget[-40:]
            else:
                printableTarget = (printableTarget + (' ' * (40 - len(printableTarget))))
            logger.run('正在解析 %s\r' % printableTarget)
            url = getUrl(target, True)
            params = getParams(target, '', True)
            url_being_processed = getUrl(target, True) # 通常 target 就是绝对 URL
            if '=' in target:  # if there's a = in the url, there should be GET parameters
                inps = []
                # --- 检查 params 是否为 None ---
                if params:
                    for name, value in params.items():
                        inps.append({'name': name, 'value': value})
                    # 确保 forms_list 结构一致性，即使没有 input 也添加表单信息
                    if inps or url not in [f.get('action') for f in forms if isinstance(f, dict) and 'action' in f]:
                        # 用于json
                        forms.append({0: {'action': url, 'method': 'get', 'inputs': inps}})
                        # --- 修改开始: 根据 GET 参数生成可注入 URL ---
                        try:
                            url_base = url.split('?')[0] # 获取不带参数的基础 URL
                            # 重新构建查询参数字典，只包含当前参数
                            # (处理 GET 参数的 try 块内部)
                            params_dict = getParams(target, '', True)
                            if params_dict:
                                url_base = url_being_processed.split('?')[0] # 保持 url_being_processed 变量
                            
                                # --- 保留：为每个单独参数生成 URL ---
                                for param_name, param_value_list in params_dict.items():
                                    value_str = param_value_list[0] if param_value_list else ''
                                    current_param = {param_name: value_str}
                                    query_string = urlencode(current_param, doseq=True)
                                    final_url_parts = urlparse(url_base)._replace(query=query_string)
                                    final_url = urlunparse(final_url_parts)
                                    core.config.globalVariables['injectable_urls'].add(final_url)
                                # --- 单独参数 URL 生成结束 ---
                            
                                # --- 生成包含所有 GET 参数的组合 URL ---
                                try:
                                    # 使用完整的原始参数字典来构建组合查询字符串
                                    # 需要确保 params_dict 的值是列表形式，urlencode 才工作正常
                                    # getParams 内部使用 parse_qs，所以值已经是列表了
                                    combined_query_string = urlencode(params_dict, doseq=True)
                                    combined_url_parts = urlparse(url_base)._replace(query=combined_query_string)
                                    combined_url = urlunparse(combined_url_parts)
                                    core.config.globalVariables['injectable_urls'].add(combined_url)
                                    logger.debug(f"GET Params - Added combined URL: {combined_url}") # 添加 Debug 日志
                                except Exception as e_get_combined_build:
                                     logger.error(f"从 GET 参数构建组合注入 URL 时出错: {e_get_combined_build}")
                                # --- ---
                                    
                        except Exception as e_get_build:
                            logger.error(f"从 GET 参数构建注入 URL 时出错: {e_get_build}")
                # --- ---
            response = requester(url, params, headers, True, delay, timeout).text
            if not response: # --- 检查 response 是否为空 ---
                 logger.debug(f"Empty response received for URL: {url}")
                 return # 如果响应为空，则跳过后续处理
                 # --- ---

            retireJs(url, response)
            if not skipDOM:
                highlighted = dom(response)
                clean_highlighted = ''.join([re.sub(r'^\d+\s+', '', line) for line in highlighted])
                if highlighted and clean_highlighted not in checkedDOMs:
                    checkedDOMs.append(clean_highlighted)
                    logger.good('在 %s 发现潜在易受攻击的对象' % url)
                    logger.red_line(level='good')
                    for line in highlighted:
                        logger.no_format(line, level='good')
                    logger.red_line(level='good')
            # 确保这里的 `url` 变量是当前请求并获取 `response` 的那个 URL
            found_forms_on_page = zetanize(response, url) # 传入当前页面的 url
            if found_forms_on_page:
                # 用于json
                forms.append(found_forms_on_page)
                # --- 根据 HTML 表单生成可注入 URL ---
                try:
                    # 遍历 zetanize 返回的每个表单 ('0', '1', ...)
                    for form_key in found_forms_on_page:
                        form_details = found_forms_on_page.get(form_key)
                        if isinstance(form_details, dict):
                            original_action = form_details.get('action', '')
                            inputs = form_details.get('inputs', [])

                            # --- 添加 Debug 开始 ---
                            is_post1_action = (original_action == "post1") # 标记是否是我们要追踪的 action
                            if is_post1_action:
                                logger.debug(f"Found form with action='post1'. Base URL: {url_being_processed}")
                            # --- 添加 Debug 结束 ---

                            # 使用 urljoin 准确解析 action (无论相对或绝对)
                            # 'url' 是 rec 函数当前处理的页面的绝对 URL
                            resolved_action_url = urljoin(url, original_action)
                            
                             # --- 添加 Debug 开始 ---
                            if is_post1_action:
                                logger.debug(f"Resolved action for 'post1': {resolved_action_url}")
                            # --- 添加 Debug 结束 ---

                            # 解析补全后的 action URL
                            parsed_resolved_action = urlparse(resolved_action_url)
                            base_action_no_params_frag = urlunparse(parsed_resolved_action._replace(query='', fragment=''))
                            existing_action_params = parse_qs(parsed_resolved_action.query)

                            if isinstance(inputs, list):
                                for inp in inputs:
                                    if isinstance(inp, dict) and 'name' in inp:
                                        param_name = inp.get('name')
                                        param_value = inp.get('value', '') # 使用表单默认值
                                        if param_name:
                                            # 合并 action 自带参数和当前 input 参数
                                            params_for_url = existing_action_params.copy()
                                            params_for_url[param_name] = [param_value] # 设置当前参数值

                                            query_string = urlencode(params_for_url, doseq=True)
                                            final_inj_url_parts = urlparse(base_action_no_params_frag)._replace(query=query_string)
                                            final_inj_url = urlunparse(final_inj_url_parts)
                                            core.config.globalVariables['injectable_urls'].add(final_inj_url)

                                             # --- 添加 Debug 开始 ---
                                            if is_post1_action and param_name == "in": # 特别关注 post1 的 'in' 参数
                                                logger.debug(f"Attempting to add for 'post1', param 'in': {final_inj_url}")
                                            # --- 添加 Debug 结束 ---

                            # --- 生成包含所有表单 inputs 的组合 URL ---
                            if isinstance(inputs, list) and inputs: # 确保 inputs 列表存在且不为空
                                try:
                                    combined_params = existing_action_params.copy()
                                    # 收集当前表单的所有 input name 和 value
                                    for inp in inputs:
                                         if isinstance(inp, dict) and 'name' in inp:
                                             param_name = inp.get('name')
                                             param_value = inp.get('value', '')
                                             if param_name:
                                                 # 如果参数已存在（例如来自 action URL），可能需要决定是覆盖还是追加
                                                 # 这里我们选择覆盖/设置，与单参数逻辑保持一致
                                                 combined_params[param_name] = [param_value]

                                    # 使用收集到的所有参数构建组合查询字符串
                                    combined_query_string = urlencode(combined_params, doseq=True)
                                    combined_url_parts = urlparse(base_action_no_params_frag)._replace(query=combined_query_string)
                                    combined_url = urlunparse(combined_url_parts)
                                    core.config.globalVariables['injectable_urls'].add(combined_url)
                                    logger.debug(f"HTML Form - Added combined URL: {combined_url}") # 添加 Debug 日志
                                except Exception as e_form_combined_build:
                                    logger.error(f"从 HTML 表单构建组合注入 URL 时出错: {e_form_combined_build}")

                except Exception as e_form_build:
                     logger.error(f"从 HTML 表单构建注入 URL 时出错: {e_form_build}")
            # ---  ---

            matches = re.findall(r'<[aA].*href=["\']{0,1}(.*?)["\']', response)
            for link in matches:  # iterate over the matches
                # remove everything after a "#" to deal with in-page anchors
                link = link.split('#')[0]
                 # --- 修改开始: 增加对空链接或 javascript: 链接的处理 ---
                if not link or link.lower().startswith(('javascript:', 'mailto:', 'tel:')):
                    continue
                # ---  ---
                if link.endswith(('.pdf', '.png', '.jpg', '.jpeg', '.xls', '.xml', '.docx', '.doc')):
                    pass
                else:
                    # --- 改进 URL 拼接逻辑 ---
                    try:
                         parsed_link = urlparse(link)
                         if parsed_link.scheme and parsed_link.netloc: # 完整的 URL
                             if parsed_link.netloc == host:
                                 storage.add(link)
                         elif link.startswith('//'): # //example.com/path
                             if link.split('/')[2].startswith(host):
                                 storage.add(schema + ':' + link)
                         elif link.startswith('/'): # /path/to/resource
                             storage.add(main_url + link)
                         elif link.startswith('?'): # ?query=string
                             # 基础 URL + 查询字符串
                              base_target_url = target.split('?')[0] if '?' in target else target
                              storage.add(base_target_url + link)
                         else: # relative/path or filename.html
                              # 需要正确处理相对路径的基础 URL
                              base_target_url = target.rsplit('/', 1)[0] if '/' in urlparse(target).path else main_url
                              if not base_target_url.endswith('/'):
                                  base_target_url += '/'
                              storage.add(base_target_url + link)
                    except ValueError:
                         logger.debug(f"Skipping malformed link: {link}")
                         continue # 跳过格式错误的链接
                    # --- ---

        except core.requests.exceptions.RequestException as e: # cite: 30
             logger.warning(f"请求错误于 {target}: {e}") # cite: 30
        except Exception as e: # cite: 30
             logger.error(f"处理 {target} 时发生未知错误: {e}") # cite: 30

    try:
        for x in range(level):
            urls = storage - processed  # urls to crawl = all urls - urls that have been crawled
            # for url in urls:
            #     rec(url)
            threadpool = concurrent.futures.ThreadPoolExecutor(
                max_workers=threadCount)
            # 过滤掉空 URL 或无效 URL
            valid_urls = [u for u in urls if u]
            futures = (threadpool.submit(rec, url) for url in urls)
            # --- 改进进度显示和错误处理 ---
            processed_count = 0
            total_urls_to_process = len(valid_urls)
            for future in concurrent.futures.as_completed(futures):
                processed_count += 1
                try:
                    # 如果 rec 函数有返回值，可以在这里获取
                    future.result()
                except Exception as e:
                    logger.error(f"线程池任务执行出错: {e}")
                # 更平滑的进度更新
                if total_urls_to_process > 0:
                     logger.run('进度: %i/%i\r' % (processed_count, total_urls_to_process))
            logger.run('进度: %i/%i' % (processed_count, total_urls_to_process)) # 确保最终进度显示
            logger.no_format('') # 清除进度行
             # --- ---

    except KeyboardInterrupt:
        logger.info("用户中断了爬取过程。") 
        # 中断时也尝试保存已有的结果
        pass # 继续执行到保存步骤

    # --- (在函数返回前保存结果) ---
    logger.info(f"爬虫函数执行完毕: 发现了 {len(forms)} 个可能的表单，处理了 {len(processed)} 个 URL。")

    # --- 存储处理过的URL ---
    # # 将处理过的 URL (集合转列表) 保存到文件
    # processed_list = sorted(list(processed)) # 排序
    # try:
    #     with open("crawled_urls_photon.txt", "w", encoding="utf-8") as f:
    #         for url_item in processed_list:
    #             f.write(url_item + "\n")
    #     logger.good("已处理的 URL 已保存至 crawled_urls_photon.txt")
    # except Exception as e:
    #     logger.error(f"保存已处理的 URL 失败: {e}")
    # --- ---
    import urllib.parse
    # --- 添加更详细 Debug 日志的最终保存逻辑 ---
    logger.info("正在处理收集到的 URL 以生成唯一的注入点 URL 列表 (值为空)...")
    collected_urls_with_values = core.config.globalVariables.get('injectable_urls', set())
    unique_points_by_path = {} # 字典的值将是存储元组的集合
    final_output_urls_set = set() # 用于最终输出前再次确认

    if collected_urls_with_values:
        logger.info(f"正在从 {len(collected_urls_with_values)} 个原始 URL 中提取唯一的注入点组合...")
        try:
            # 第一遍：收集所有唯一的 (基础路径, 参数名组合元组)
            for url_with_value in collected_urls_with_values:
                try:
                    parsed = urlparse(url_with_value)
                    base_path = urlunparse(parsed._replace(query='', fragment=''))

                    # --- 保留详细 Debug 日志 ---
                    logger.debug(f"DEBUG: 正在分析 URL: {url_with_value}")
                    logger.debug(f"DEBUG: 原始查询字符串: '{parsed.query}'")
                    params_dict = parse_qs(parsed.query, keep_blank_values=True) # 只需解析一次
                    logger.debug(f"DEBUG: parse_qs 的结果: {params_dict}")
                    keys_list = list(params_dict.keys())
                    logger.debug(f"DEBUG: 从 parse_qs 结果中获取的键: {keys_list}")
                    # --- 结束详细 Debug 日志 ---

                    # --- 使用元组 (Tuple) 存储参数组合 ---
                    param_names_tuple = tuple(sorted(keys_list)) # 创建排序后的元组
                    # 修改日志，记录元组
                    logger.debug(f"Processing URL: {url_with_value} -> Base: {base_path}, Params    Tuple: {param_names_tuple}")

                    # 将元组添加到对应 base_path 的集合中
                    if base_path not in unique_points_by_path:
                        unique_points_by_path[base_path] = set() # 集合现在存储元组
                    added = param_names_tuple not in unique_points_by_path[base_path] # 检查是否是  新增
                    unique_points_by_path[base_path].add(param_names_tuple) # 添加元组
                    # --- 结束使用元组 ---

                    # --- Debug Log 2 (记录添加/忽略) ---
                    if added:
                        logger.debug(f"  Added unique point: ({base_path}, {param_names_tuple})")
                    else:
                        logger.debug(f"  Duplicate point ignored: ({base_path},     {param_names_tuple})")
                    # --- 结束 Debug Log 2 ---

                except Exception as e_parse_url:
                    # logger.warning(f"解析 URL '{url_with_value}' 以提取注入点时出错: {e_parse_url}    ") # 原来的行
                    logger.exception(f"解析 URL '{url_with_value}' 以提取注入点时出错:") # 记录完整     traceback
        except Exception as e_outer_loop:
                logger.error(f"处理收集到的 URL 时发生意外错误: {e_outer_loop}")

        # 第二遍：根据收集到的唯一组合 (元组)，生成最终URL字符串
        if unique_points_by_path:
            logger.good(f"提取到 {sum(len(s) for s in unique_points_by_path.values())} 个独特的注入点   组合，正在格式化...")
            try:
                # 遍历每个基础路径及其对应的参数名元组集合
                for base_path, param_name_tuples_set in unique_points_by_path.items(): # 修改变量名
                    # --- Debug Log 4 ---
                    logger.debug(f"Formatting for Base Path: {base_path}")
                    # 迭代集合中的每个参数名元组
                    for param_names_tuple in param_name_tuples_set: # 修改变量名
                            # --- Debug Log 5 ---
                            logger.debug(f"  Processing Param Tuple: {param_names_tuple}") # 修改日志
                            try: # 为内部操作添加更细致的 try-except
                                # 使用元组中的参数名构建字典
                                params_empty_value = {name: '' for name in param_names_tuple}
                                query_string_empty = urlencode(params_empty_value)
                                final_url_parts = urlparse(base_path)._replace  (query=query_string_empty)
                                final_url_no_value = urlunparse(final_url_parts)
                                # --- Debug Log 3 (记录生成的 URL) ---
                                logger.debug(f"  Generated Output URL for ({base_path},     {param_names_tuple}): {final_url_no_value}") # 修改日志
                                final_output_urls_set.add(final_url_no_value) # 添加到最终集合
                            except Exception as e_inner_format:
                                # 捕捉并记录内部格式化错误
                                logger.error(f"  Error formatting URL for ({base_path},     {param_names_tuple}): {e_inner_format}") # 修改日志

            except Exception as e_format:
                logger.error(f"格式化唯一的注入点 URL 时的主循环出错: {e_format}") # 修改错误信息区分内外   层

            # 检查最终输出集合
            if final_output_urls_set:
                    logger.good(f"最终生成 {len(final_output_urls_set)} 个独特的注入点 URL (值为空)，正 在保存...")
                    # ... (后续写入文件的 try...except 不变) ...
                    try:
                        # 确保使用 'w' 模式覆盖旧文件，并指定编码
                        with open("injectable_urls.txt", "w", encoding="utf-8") as f_inj:
                            # 写入标题行或注释（如果需要）
                            # f_inj.write("# Unique injectable URLs found by Photon (values     removed)\n")
                            # 排序后写入，确保输出顺序一致
                            for url_item in sorted(list(final_output_urls_set)):
                                    f_inj.write(url_item + "\n")
                        logger.good("唯一的注入点 URL 列表 (值为空) 已保存至 injectable_urls.txt")
                    except Exception as e_write:
                        logger.error(f"保存唯一的注入点 URL 列表文件失败: {e_write}")
            else:
                    logger.info("未能格式化有效的唯一注入点 URL。")
        else:
                logger.info("未能从收集到的 URL 中提取有效的唯一注入点组合。")
    else:
        logger.info("未收集到任何原始 URL，无法生成注入点列表。")

    # 将发现的表单保存到 JSON 文件
    try:
        # 过滤掉非字典项，并确保字典不为空
        valid_forms = [form for form in forms if isinstance(form, dict) and form]
        with open("found_forms_photon.json", "w", encoding="utf-8") as f:
             # 使用 ensure_ascii=False 来支持中文字符正确写入 JSON
             json.dump(valid_forms, f, indent=4, ensure_ascii=False)
        logger.good("发现的表单已保存至 found_forms_photon.json")
    except TypeError as e:
        logger.error(f"无法将表单数据序列化为 JSON: {e}。表单数据可能包含无法直接序列化的复杂对象。")
    except Exception as e:
        logger.error(f"保存发现的表单失败: {e}")

    # --- ---

    return [forms, processed]
