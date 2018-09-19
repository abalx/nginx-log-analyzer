import os
import re
import json
import gzip
import logging
import argparse
from datetime import datetime
from collections import namedtuple, defaultdict
from typing import List, Generator, Optional


logger_fmt = '[%(asctime)s] %(levelname).1s %(message)s'
logger_datefmt = '%Y.%m.%d %H:%M:%S'
logging.basicConfig(format=logger_fmt, datefmt=logger_datefmt)
logger = logging.getLogger('log_analyzer')
logger.setLevel(logging.INFO)


DEFAULT_CONFIG = {
    'REPORT_SIZE': 1000,
    'REPORT_DIR': './reports',
    'LOG_DIR': './var/log',
    'SCRIPT_LOG': './var/log/script_log',
}


def is_path_exists(path: str) -> bool:
    return os.path.exists(os.path.normpath(path))


def set_logger(script_log: str):
    script_log_dir = os.path.dirname(script_log)

    if not script_log_dir:
        return

    if not is_path_exists(script_log_dir):
        os.makedirs(script_log_dir)

    logging.getLogger()
    file_handler = logging.FileHandler(script_log)
    fmt_handler = logging.Formatter(logger_fmt, logger_datefmt)
    file_handler.setFormatter(fmt_handler)
    logger.addHandler(file_handler)
    logger.propagate = False


def calc_median(numbers: List[int]) -> float:
    sorted_nums = sorted(numbers)
    nums_count = len(sorted_nums)

    if nums_count % 2 == 1:
        return sorted_nums[nums_count // 2]
    else:
        i = nums_count // 2
        return (sorted_nums[i - 1] + sorted_nums[i]) / 2


def is_too_many_missed_lines(missed: int, total: int, limit_perc: int = 30) -> bool:
    missed_perc = (missed / total) * 100
    return missed_perc >= limit_perc


def parse_lines(lines: Generator) -> Generator:
    log_pattern = re.compile(
        r"(?P<remote_addr>[\d\.]+)\s"
        r"(?P<remote_user>\S*)\s+"
        r"(?P<http_x_real_ip>\S*)\s"
        r"\[(?P<time_local>.*?)\]\s"
        r'\"'
        r'(?P<request_method>.*?)\s'
        r'(?P<request_url>.*?)\s'
        r'(?P<request_protocol>.*?)'
        r'\"\s'
        r"(?P<status>\d+)\s"
        r"(?P<body_bytes_sent>\S*)\s"
        r'"(?P<http_referer>.*?)"\s'
        r'"(?P<http_user_agent>.*?)"\s'
        r'"(?P<http_x_forwarded_for>.*?)"\s'
        r'"(?P<http_X_REQUEST_ID>.*?)"\s'
        r'"(?P<http_X_RB_USER>.*?)"\s'
        r"(?P<request_time>\d+\.\d+)\s*"
    )

    missed_count = total_lines = 0

    for line in lines:
        total_lines += 1
        match = log_pattern.match(line)

        if not match:
            missed_count += 1
            continue

        yield match.groupdict()

    if total_lines == 0:
        raise ValueError('Log file is empty.')

    logger.info(
        f'\nTotal: {total_lines}'
        f'\nSucceed: {total_lines - missed_count}'
        f'\nMissed: {missed_count}'
    )

    if is_too_many_missed_lines(missed_count, total_lines):
        error_msg = f'Too many missed lines. Aborted.'
        raise RuntimeError(error_msg)


def collect_times_for_urls(parsed_log: Generator) -> defaultdict:
    url_times = defaultdict(list)

    for request_line in parsed_log:
        url = request_line['request_url']
        url_times[url].append(float(request_line['request_time']))

    return url_times


def analyze_requests(times_map: dict) -> List[dict]:
    total_count = total_time = 0

    for times in times_map.values():
        total_count += len(times)
        total_time += sum(times)

    analyzed_requests = []

    for url, times in times_map.items():
        requests_len = len(times)
        sum_times = sum(times)
        max_times = max(times)
        ndigits = 3

        analyzed_requests.append({
            'url': url,
            'count': len(times),
            'count_perc': round(100 * requests_len / float(total_count), ndigits),
            'time_sum': round(sum_times, ndigits),
            'time_perc': round(100 * sum_times / total_time, ndigits),
            'time_avg': round(sum_times / requests_len, ndigits),
            'time_max': round(max_times, ndigits),
            'time_med': round(calc_median(times), ndigits),
        })

    return analyzed_requests


def sort_requests_by_time_sum(analyzed_requests: List[dict]) -> List[dict]:
    analyzed_requests.sort(key=lambda r: r['time_sum'], reverse=True)
    return analyzed_requests


def create_report_for_log(requests: List[dict], report_dir: str, log: namedtuple):
    with open('./templates/report.html', 'r') as report_template_file:
        report_template_content = report_template_file.read()

    report_path = os.path.join(report_dir, make_report_name_for_log(log))

    if not is_path_exists(report_dir):
        os.makedirs(report_dir)

    with open(report_path, "w") as f:
        json_content = json.dumps(requests)
        f.write(report_template_content.replace('$table_json', json_content))


def get_log_lines(log):
    log_file = (
        gzip.open(log.path)
        if log.path.endswith('.gz')
        else open(log.path)
    )

    for line in log_file:
        yield line

    log_file.close()


def make_report_name_for_log(log: namedtuple):
    return f"report-{log.date.year}.{log.date.month:02}.{log.date.day:02}.html"


def is_report_for_log_exists(report_dir: str, log: namedtuple) -> bool:
    report_path = os.path.join(report_dir, make_report_name_for_log(log))
    return is_path_exists(report_path)


def try_open_custom_config(config_custom_path: str) -> Optional[dict]:
    if not config_custom_path:
        return

    if not is_path_exists(config_custom_path):
        raise FileNotFoundError('Configuration file is not found.')

    with open(config_custom_path, 'r') as config:
        try:
            return json.load(config)
        except json.decoder.JSONDecodeError:
            raise ValueError('Cannot to parse custom configuration.')


def set_config(custom_config_path) -> dict:
    custom_config = try_open_custom_config(custom_config_path)
    config = DEFAULT_CONFIG.copy()
    config.update(custom_config or {})

    return config


def try_parse_date(date_string: str) -> datetime.date:
    try:
        return datetime.strptime(date_string, '%Y%m%d').date()
    except ValueError:
        pass


def find_latest_log(log_dir: str) -> Optional[namedtuple]:
    pattern = r'(?<=\bnginx-access-ui\.log-)\d{8}(?=\.gz|$)'
    last_date = last_path = None

    for file in os.listdir(log_dir):
        match = re.findall(pattern, file)

        if not match:
            continue

        date_string = match[0]
        log_path = os.path.join(log_dir, file)
        log_date = try_parse_date(date_string)

        if not last_date or log_date > last_date:
            last_date, last_path = log_date, log_path

    if last_date:
        return namedtuple('LogFile', 'path, date')(last_path, last_date)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser("Log analyzer")
    parser.add_argument('--config', default='./config.json')
    return parser.parse_args()


def main(parsed_args: argparse.Namespace):
    config = set_config(parsed_args.config)
    set_logger(config['SCRIPT_LOG'])
    latest_log = find_latest_log(config['LOG_DIR'])

    if not latest_log:
        logger.info('Log file is not found.')
        return

    if is_report_for_log_exists(config['REPORT_DIR'], latest_log):
        logger.info('A report already exists.')
        return

    log_lines = get_log_lines(latest_log)
    parsed_lines = parse_lines(log_lines)
    times_map = collect_times_for_urls(parsed_lines)
    analyzed_requests = analyze_requests(times_map)
    sorted_requests = sort_requests_by_time_sum(analyzed_requests)
    sliced_requests = sorted_requests[:config['REPORT_SIZE']]
    create_report_for_log(sliced_requests, config['REPORT_DIR'], latest_log)


if __name__ == "__main__":
    try:
        main(parse_args())
    except (Exception, SystemExit, KeyboardInterrupt)as e:
        logger.exception(e)
