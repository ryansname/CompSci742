#! /usr/bin/env python3
import sys
from datetime import datetime


class Collector(object):
    name = "BaseCollector"
    display = True

    def on_start(self, file_count):
        pass

    def on_file_start(self, filename):
        pass

    def on_access(self, data):
        pass

    def on_file_complete(self, filename):
        pass

    def on_complete(self):
        pass

    def report(self):
        return ""


class ProgressReporter(Collector):
    display = False

    def on_start(self, file_count):
        self.count = 0
        self.total = file_count

    def on_file_start(self, filename):
        self.count += 1
        print('\rFile {}/{}'.format(self.count, self.total), end='')
        sys.stdout.flush()

    def on_complete(self):
        print()


class IpCollector(Collector):
    name = "IP Count"

    def __init__(self):
        self.ips = set()

    def on_access(self, data):
        self.ips.add(data['ip'])

    def report(self):
        return str(len(self.ips))

class RobotCounter(Collector):
    name = "Robots"

    def __init__(self):
        self.count = 0

    def on_access(self, data):
        if data['request']['resource'] == "/robots.txt":
            self.count += 1

    def report(self):
        return str(self.count)

class Parser(object):

    def __init__(self, filenames, human_readable=True):
        self.filenames = filenames
        self.collectors = []
        if human_readable:
            self.split = ', '
        else:
            self.split = ','

    def add_collector(self, collector):
        self.collectors.append(collector)

    def parse_all(self):
        for c in self.collectors:
            c.on_start(len(self.filenames))
        for filename in reversed(sorted(self.filenames)):
            results = self.parse_file(filename)
        for c in self.collectors:
            c.on_complete()

        print(self.split.join([c.name for c in self.collectors if c.display]))
        print(self.split.join([c.report() for c in self.collectors if c.display]))

    def parse_file(self, filename):
        with open(filename) as f:
            for c in self.collectors:
                c.on_file_start(filename)

            timestamp_cache = {}
            for i, line in enumerate(f):
                line = line.strip()
                raw_parts = line.split()
                raw_timestamp = "{} {}".format(raw_parts[3][1:], raw_parts[4][:-1])
                raw_request = " ".join(raw_parts[5:-2])[1:-1].split()

                timestamp = timestamp_cache.get(raw_timestamp, None)
                if not timestamp:
                    timestamp = datetime.strptime(raw_timestamp, "%d/%b/%Y:%H:%M:%S %z")
                    timestamp_cache[raw_timestamp] = timestamp
                # Names from http://en.wikipedia.org/wiki/Common_Log_Format
                try:
                    parts = {
                        'ip': raw_parts[0],
                        'user-identifier': raw_parts[1],
                        'userid': raw_parts[2],
                        'timestamp': timestamp,
                        'raw_timestamp': raw_timestamp,
                        'request': {
                            'type': raw_request[0],
                            'protocol': raw_request[-1],
                            'resource': raw_request[1:-1][0] if len(raw_request[1:-1]) == 1 else "",
                        },
                        'raw_request': " ".join(raw_request),
                        'status': raw_parts[-2],
                        'size': raw_parts[-1],
                    }
                    for c in self.collectors:
                        c.on_access(parts)
                except ValueError:
                    print("ValueError file: {}:{}".format(filename, i))
        for c in self.collectors:
            c.on_file_complete(filename)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python {} <filename> [<filename> ...]".format(sys.argv[0])) 

    parser = Parser(sys.argv[1:])
    parser.add_collector(IpCollector())
    parser.add_collector(RobotCounter())
    parser.add_collector(ProgressReporter())
    parser.parse_all()