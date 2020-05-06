import ray

import schedule
import requests
import time
import pickle
from scapy.all import AsyncSniffer
import timestamp_scraper

ray.init()


@ray.remote
def collect(ip):
    list_res = list()
    def f(ls):
        tm = time.time()
        res = requests.get("http://" + str(ip))
        ls.append(tuple([tm, res]))
    schedule.every().minute.at(':10').do(f, list_res) 
    schedule.every().minute.at(':15').do(f, list_res) 
    schedule.every().minute.at(':20').do(f, list_res) 
    schedule.every().minute.at(':25').do(f, list_res) 
    schedule.every().minute.at(':30').do(f, list_res) 
    schedule.every().minute.at(':35').do(f, list_res) 
    schedule.every().minute.at(':40').do(f, list_res) 
    schedule.every().minute.at(':45').do(f, list_res) 
    schedule.every().minute.at(':50').do(f, list_res) 
    for _ in range(60 * 15 * 1000): 
        time.sleep(0.001) 
        schedule.run_pending() 
    return list_res


def collect_all():
    lst = ["35.208.81.73","35.206.97.183","35.209.58.70","35.206.100.104"]
    res = list()
    got_res = dict()
    t = AsyncSniffer()
    t.start()
    for ip in lst:
        res.append(collect.remote(ip))
    for r in res:
        got_res.append(ray.get(r))
    return got_res, t.stop()



if __name__ == '__main__':
    timestamp_scraper.SAVE_NAME = "Analyzed_Results" + str(datetime.now())
    reqs, packets = collect_all()
    timestamp_scraper.RESULTS = dict()
    timestamp_scraper.RESULTS['Requests'] = reqs
    timestamp_scraper.RESULTS['Packets'] = packets
    timestamp_scraper.WriteOut()