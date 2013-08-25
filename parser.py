#! /usr/bin/env python3
import re
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
    name = "IP_Count"

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
    name = "Mean_Transfer"

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


class MedianTransferCollector(Collector):
    name = "Median_Transfer"

    def __init__(self):
        self.transfers = []

    def on_access(self, data):
        if data['size'] == '-':
            size = 0
        else:
            size = int(data['size'])
        self.transfers.append(size)

    def report(self):
        def median(sizes):
            sortd = sorted(sizes)
            length = len(sortd)
            if not length % 2:
                return (sortd[length // 2] + sortd[length // 2 - 1]) / 2
            return sortd[length // 2]
        return "{}kB".format(median(self.transfers))


class FileCollector(Collector):
    name = "Files"

    def __init__(self):
        self.files = {}
        self.filesize = {}

    def on_access(self, data):
        file = data['request']['resource']
        if file not in self.files:
            self.files[file] = 0
            self.filesize[file] = 0
        self.files[file] += 1
        if data['size'] == '-':
            size = 0
        else:
            size = int(data['size'])
        if self.filesize[file] < size:
            self.filesize[file] = size


class OneTimeReferenceCollector(Collector):
    name = "One_Time_Referencing"

    def __init__(self):
        self.fileCollector = FileCollector()

    def on_access(self, data):
        self.fileCollector.on_access(data)

    def report(self):
        files = self.fileCollector.files
        return "{:.2f}%".format(len([x for x in files if files[x] == 1]) / len(files) * 100)


class ReferenceConcentrationCollector(Collector):
    name = "Concentration_of_References"
    display = False

    def __init__(self):
        self.fileCollector = FileCollector()

    def on_access(self, data):
        self.fileCollector.on_access(data)

    def print_graph_data(self, separator):
        files = self.fileCollector.files
        filesizes = self.fileCollector.filesize
        headers = ("Document Rank", "Accesses to document", "Document filesize")
        print()
        print(self.name)
        print()
        print(separator.join(headers))
        for file, count in sorted(files.items(), key=lambda x: -x[1]):  # -x[0] to make sorted return largest to smallest
            print(separator.join((file, str(count), str(filesizes[file]))))


class AccessTimeCollector(Collector):
    name = "Access_Time"
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
            print(separator.join((str(band), str(count))))


class CacheCollector(Collector):
    name = "Cache_Hit_Rate"

    def __init__(self):
        self.total = 0
        self.hits = 0

    def on_access(self, data):
        if data['status'] == "304":
            self.hits += 1
        self.total += 1

    def report(self):
        return "{}".format(self.hits / self.total)


class CachedBytes(Collector):
    name = "Cache_Bytes_Saved"

    def __init__(self):
        self.total = 0
        self.sizes = {}
        self.saved = 0

    def on_access(self, data):
        size = 0
        if data['status'] == "304":
            if data['request']['resource'] in self.sizes:
                size = self.sizes[data['request']['resource']]
                self.saved += self.sizes[data['request']['resource']]
            else:
                return
        elif data['status'] == "200" and data['size'] != '-':
            size = int(data['size'])
            self.sizes[data['request']['resource']] = size
        self.total += size

    def report(self):
        return "{}".format(self.saved)


class TotalTransferCollector(Collector):
    name = "Total_Transferred_Size"

    def __init__(self):
        self.total = 0

    def on_access(self, data):
        if data['size'] != '-':
            self.total += int(data['size'])

    def report(self):
        return "{}".format(self.total)


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
            groups = {
                'ip': 1,
                'user-identifier': 2,
                'userid': 3,
                'timestamp': 4,
                'request': 5,
                'status': 6,
                'size': 7
            }
            for i, line in enumerate(f):
                line = line.strip()
                raw_parts = re.match(r'(\S+)\s+(\S+)\s+([^\[]+?)\s*\[([^\]]+)\]\s+(".+")\s+(\S+)\s+(\S+)', line)
                if not raw_parts:
                    print("{}: Unable to parse request: {}".format(i, line), file=sys.stderr)
                    continue
                try:
                    request = {}
                    try:
                        request_matches = re.match(r'"([A-Z]+)\s+([^\s]+)\s*([^"]*)"', raw_parts.group(groups['request']))
                        if request_matches:
                            raw_request = request_matches.group(0)
                            request.update({
                                'type': request_matches.group(1),
                                'resource': request_matches.group(2),
                                'protocol': request_matches.group(3)
                            })
                        else:
                            print("No request found, skipping: {}".format(line), file=sys.stderr)
                            continue
                            
                    except IndexError:
                        print("IndexError :(", file=sys.stderr)
                        continue

                    raw_timestamp = raw_parts.group(groups['timestamp'])
                    timestamp = timestamp_cache.get(raw_timestamp, None)
                    if not timestamp:
                        timestamp = datetime.strptime(raw_timestamp, "%d/%b/%Y:%H:%M:%S %z")
                        timestamp_cache[raw_timestamp] = timestamp
                    # Names from http://en.wikipedia.org/wiki/Common_Log_Format
                    parts = {
                        'ip': raw_parts.group(groups['ip']),
                        'user-identifier': raw_parts.group(groups['user-identifier']),
                        'userid': raw_parts.group(groups['userid']),
                        'timestamp': timestamp,
                        'raw_timestamp': raw_timestamp,
                        'request': request,
                        'raw_request': raw_parts.group(groups['request']),
                        'status': raw_parts.group(groups['status']),
                        'size': raw_parts.group(groups['size']),
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
    parser.add_collector(MedianTransferCollector())
    parser.add_collector(ProgressReporter())
    parser.add_collector(OneTimeReferenceCollector())
    parser.add_collector(CacheCollector())
    parser.add_collector(CachedBytes())
    parser.add_collector(TotalTransferCollector())
    parser.add_collector(ReferenceConcentrationCollector())
    parser.add_collector(AccessTimeCollector())
    parser.parse_all()