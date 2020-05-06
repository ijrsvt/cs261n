import ray
import timestamp_scraper
ray.init()


@ray.remote
def ray_tcp(items):
    if not isinstance(items, list):
        return timestamp_scraper.TcpTimestamp([items])
    return timestamp_scraper.TcpTimestamp(items)


@ray.remote
def ray_icmp(items):
    if not isinstance(items, list): 
        return timestamp_scraper.IcmpTimestamp([items])
    return timestamp_scraper.IcmpTimestamp(items)


def read_remote(remote, result_dict):
    for r in remote:
        try:
            timestamp_scraper.MergeSecond(result_dict, ray.get(r))
        except Exception as e:
            print(e)
            pass

if __name__ == '__main__':
    timestamp_scraper.ALEXA_TOP_X = 1000
    timestamp_scraper.NUM_TCP = 100
    timestamp_scraper.NUM_ICMP = 10
    timestamp_scraper.ReadIn()
    # tcp_slice_size = int(timestamp_scraper.ALEXA_TOP_X/10)
    # icmp_slice_size = int(timestamp_scraper.ALEXA_TOP_X/2)
    tcp_remote = [ray_tcp.remote(x) for x in timestamp_scraper.DESTINATIONS]
    icmp_remote = [ray_icmp.remote(x) for x in timestamp_scraper.DESTINATIONS]
    read_remote(tcp_remote, timestamp_scraper.RESULTS)
    read_remote(icmp_remote, timestamp_scraper.RESULTS)
    timestamp_scraper.WriteOut()
