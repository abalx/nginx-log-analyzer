import os
import unittest
import logging
from datetime import date
from unittest import mock
from collections import namedtuple

import log_analyzer as analyzer


logging.disable(logging.CRITICAL)


class LogAnalyzerTest(unittest.TestCase):
    def setUp(self):
        LogFile = namedtuple('LogFile', 'path, date')

        self.log20170630 = LogFile(
            path='nginx-access-ui.log-20170630',
            date=date(2017, 6, 30),
        )

    @mock.patch.object(os, 'listdir')
    def test_search_log(self, listdir_mock):
        listdir_mock.return_value = [
            'file'
            'file20180630'
            'aanginx-access-ui.log-20170631',
            'nginx-access-ui.log-20170630',
            'nginx-access-ui.log-20180630.gz',
            'nginx-access-ui.log-33333333.bz2',
            'nginx-access-ui.log-20180631.bz2',
            'nginx-access-ui.log-20180631ff',
            'nginx-access-ui.log-20180631ff.tar',
        ]

        log = set(analyzer.find_latest_log('/logs'))
        expected = {date(2018, 6, 30), '/logs/nginx-access-ui.log-20180630.gz'}

        self.assertSetEqual(log, expected)

    @mock.patch.object(os, 'listdir')
    def test_search_log_along_other_files(self, listdir_mock):
        listdir_mock.return_value = [
            'file',
            'file2',
            'file20170630',
        ]
        log = analyzer.find_latest_log('/logs')

        self.assertEqual(log, None)

    def test_median(self):
        median = analyzer.calc_median([1, 2, 3, 4, 5])

        self.assertEqual(median, 3)

    def test_lines_parsing(self):
        log_lines = [
            '1.199.168.112 2a828197ae235b0b3cb  - [29/Jun/2017:03:50:44 +0300] "GET /api/1/banners/?campaign=6607623 HTTP/1.1" 200 1130 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697444-2760328665-4709-9929070" "-" 0.767',
            '1.196.116.32 -  - [29/Jun/2017:03:50:45 +0300] "GET /api/v2/group/482920 HTTP/1.1" 200 836 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697445-2190034393-4709-9929080" "dc7161be3" 0.058',
            '1.194.135.240 -  - [29/Jun/2017:03:50:45 +0300] "GET /api/v2/group/6190230/statistic/sites/?date_type=day&date_from=2017-06-29&date_to=2017-06-29 HTTP/1.1" 200 22 "-" "python-requests/2.13.0" "-" "1498697445-3979856266-4709-9929081" "8a7741a54297568b" 0.065',
        ]
        parsed = list(analyzer.parse_lines(log_lines))
        expected = {
            'remote_addr': '1.199.168.112',
            'remote_user': '2a828197ae235b0b3cb',
            'http_x_real_ip': '-',
            'time_local': '29/Jun/2017:03:50:44 +0300',
            'request_method': 'GET',
            'request_url': '/api/1/banners/?campaign=6607623',
            'request_protocol': 'HTTP/1.1',
            'status': '200',
            'body_bytes_sent': '1130',
            'http_referer': '-',
            'http_user_agent': 'Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5',
            'http_x_forwarded_for': '-',
            'http_X_REQUEST_ID': '1498697444-2760328665-4709-9929070',
            'http_X_RB_USER': '-',
            'request_time': '0.767',
        }

        self.assertIn(expected, parsed)

    def test_collect_times(self):
        parsed_lines = [
            {'request_url': '/api/v1/test', 'request_time': 1},
            {'request_url': '/api/v1/test', 'request_time': 1},
            {'request_url': '/api/v1/test', 'request_time': 1},
        ]
        times = analyzer.collect_times_for_urls(parsed_lines)

        self.assertEqual(times.get('/api/v1/test'), [1, 1, 1])

    def test_requests_analyzing(self):
        times = {'/api/v1/test': [1, 1, 1]}
        analyzed = analyzer.analyze_requests(times)
        expected = [{
            'url': '/api/v1/test',
            'count': 3,
            'count_perc': 100.0,
            'time_sum': 3,
            'time_perc': 100.0,
            'time_avg': 1.0,
            'time_max': 1,
            'time_med': 1,
        }]

        self.assertListEqual(analyzed, expected)

    def test_report_name_making(self):
        name = analyzer.make_report_name_for_log(self.log20170630)

        self.assertEqual(name, 'report-2017.06.30.html')

    def test_too_much_missed_lines(self):
        res = analyzer.is_too_many_missed_lines(
            missed=5,
            total=10,
            limit_perc=50,
        )

        self.assertTrue(res)

    def test_small_missed_lines(self):
        res = analyzer.is_too_many_missed_lines(
            missed=1,
            total=10,
            limit_perc=50,
        )

        self.assertFalse(res)


if __name__ == '__main__':
    unittest.main()
