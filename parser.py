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

    def print_graph_data(self, separator):
        return ""


class ProgressReporter(Collector):
    display = False

    def on_start(self, file_count):
        self.count = 0
        self.total = file_count

    def on_file_start(self, filename):
        self.count += 1
        print('\rFile {}/{}'.format(self.count, self.total), end='', file=sys.stderr)
        sys.stdout.flush()

    def on_complete(self):
        print(file=sys.stderr)


class IpCollector(Collector):
    name = "IP Count"

    def __init__(self):
        self.ips = set()

    def on_access(self, data):
        self.ips.add(data['ip'])

    def report(self):
        return str(len(self.ips))


class SuccessCollector(Collector):
    name = "%Success"

    def __init__(self):
        self.success_count = 0
        self.total = 0

    def on_access(self, data):
        status_digit = int(data['status'][0])
        if status_digit == 2 or status_digit == 3:
            self.success_count += 1
        self.total += 1

    def report(self):
        return "{}".format(self.success_count / self.total)


class MeanTransferCollector(Collector):
    name = "Mean Transfer"

    def __init__(self):
        self.running_average = 0
        self.total = 0

    def on_access(self, data):
        if data['size'] == '-':
            size = 0
        else:
            size = int(data['size'])
        self.running_average = ((self.running_average * self.total) + size) / (self.total + 1)
        self.total += 1

    def report(self):
        return "{:.3f}kB".format(self.running_average / 1000)


class FileCollector(Collector):
    name = "Files"

    def __init__(self):
        self.files = {}

    def on_access(self, data):
        file = data['request']['resource']
        if file not in self.files:
            self.files[file] = 0
        self.files[file] += 1


class OneTimeReferenceCollector(Collector):
    name = "One Time Referencing"

    def __init__(self):
        self.fileCollector = FileCollector()

    def on_access(self, data):
        self.fileCollector.on_access(data)

    def report(self):
        files = self.fileCollector.files
        return "{:.2f}%".format(len([x for x in files if files[x] == 1]) / len(files) * 100)


class ReferenceConcentrationCollector(Collector):
    name = "Concentration of References"
    display = False

    def __init__(self):
        self.fileCollector = FileCollector()

    def on_access(self, data):
        self.fileCollector.on_access(data)

    def print_graph_data(self, separator):
        files = self.fileCollector.files
        headers = ("Document Rank", "Accesses to document")
        print()
        print(self.name)
        print()
        print(separator.join(headers))
        for file, count in sorted(files.items(), key=lambda x: -x[1]):  # -x[0] to make sorted return largest to smallest
            print(separator.join((file, str(count))))


class AccessTimeCollector(Collector):
    name = "Access Time"
    display = False

    def __init__(self):
        self.bands = {}
        for hour in range(24 * 7):
            self.bands[hour] = 0

    def on_access(self, data):
        weekday = data['timestamp'].isoweekday() - 1
        
        band = weekday * 24 + data['timestamp'].hour
        self.bands[band] += 1

    def print_graph_data(self, separator):
        print()
        print(self.name)
        print()
        for band, count in self.bands.items():
            print(separator.join((band, count)))


class Parser(object):

    def __init__(self, filenames, human_readable=True):
        self.filenames = filenames
        self.collectors = []
        if human_readable:
            self.split = ', '
        else:
            self.split = ' '

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

        for c in self.collectors:
            c.print_graph_data(self.split)

    def parse_file(self, filename):
        with open(filename, errors='ignore') as f:
            for c in self.collectors:
                c.on_file_start(filename)

            timestamp_cache = {}
            for i, line in enumerate(f):
                line = line.strip()
                raw_parts = line.split()
                try:
                    try:
                        raw_timestamp = "{} {}".format(raw_parts[3][1:], raw_parts[4][:-1])
                        raw_request = " ".join(raw_parts[5:-2])[1:-1].split()
                    except IndexError:
                        continue

                    timestamp = timestamp_cache.get(raw_timestamp, None)
                    if not timestamp:
                        timestamp = datetime.strptime(raw_timestamp, "%d/%b/%Y:%H:%M:%S %z")
                        timestamp_cache[raw_timestamp] = timestamp
                    # Names from http://en.wikipedia.org/wiki/Common_Log_Format
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
                except ValueError as e:
                    print(e, file=sys.stderr)
                    print("Error file: {}:{}".format(filename, i), file=sys.stderr)
        for c in self.collectors:
            c.on_file_complete(filename)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python [-g] {} <filename> [<filename> ...]".format(sys.argv[0]), file=sys.stderr) 

    human_readable = True

    index = 1
    if sys.argv[index] == '-g':
        human_readable = False
        index += 1
    parser = Parser(sys.argv[index:], human_readable=human_readable)
    parser.add_collector(IpCollector())
    parser.add_collector(SuccessCollector())
    parser.add_collector(MeanTransferCollector())
    parser.add_collector(ProgressReporter())
    parser.add_collector(OneTimeReferenceCollector())
    parser.add_collector(ReferenceConcentrationCollector())
    parser.add_collector(AccessTimeCollector())
    parser.parse_all()