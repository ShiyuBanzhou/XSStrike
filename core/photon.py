import re
import json # (导入 json 模块)
import concurrent.futures
from urllib.parse import urlparse

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
            if '=' in target:  # if there's a = in the url, there should be GET parameters
                inps = []
                # --- 检查 params 是否为 None ---
                if params:
                    for name, value in params.items():
                        inps.append({'name': name, 'value': value})
                    # 确保 forms_list 结构一致性，即使没有 input 也添加表单信息
                    if inps or url not in [f.get('action') for f in forms if isinstance(f, dict) and 'action' in f]:
                        forms.append({0: {'action': url, 'method': 'get', 'inputs': inps}})
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
            # --- 检查 zetanize 返回结果 ---
            found_forms_on_page = zetanize(response)
            if found_forms_on_page:
                 forms.append(found_forms_on_page)
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

        except requests.exceptions.RequestException as e: # cite: 30
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

    # 将处理过的 URL (集合转列表) 保存到文件
    processed_list = sorted(list(processed)) # 排序
    try:
        with open("crawled_urls_photon.txt", "w", encoding="utf-8") as f:
            for url_item in processed_list:
                f.write(url_item + "\n")
        logger.good("已处理的 URL 已保存至 crawled_urls_photon.txt")
    except Exception as e:
        logger.error(f"保存已处理的 URL 失败: {e}")

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
