from scapy.all import sr1, IP, TCP, ICMP, RandShort, sr
from collections import defaultdict
from datetime import datetime
import pickle
import subprocess

##########  ALEXA INFO
ALEXA_TOP_CSV = "top-1m.csv"  #Downloaded 4/3/2020
ALEXA_TOP_X = 1000
ALEXA_TOP_URL = "http://s3.amazonaws.com/alexa-static/top-1m.csv.zip"
##########

DESTINATIONS = []
NUM_TCP = 100
NUM_ICMP = 10
SAVE_NAME = "Result_Dictionary" + str(datetime.now())

RESULTS = defaultdict(dict)


def DownloadAlexa():
    assert(subprocess.run(["curl", "-o", ALEXA_TOP_CSV, ALEXA_TOP_URL]).returncode == 0)
    assert(subprocess.run(["unzip", ALEXA_TOP_CSV]).returncode == 0)


#####   READ IN ALEXA_TOP
def ReadIn():
    with open(ALEXA_TOP_CSV, "r") as alexa:
        for _ in range(ALEXA_TOP_X):
            DESTINATIONS.append(alexa.readline().split(",")[1].strip('\n'))
        alexa.close()


#####   First Get TCP
def TcpTimestamp(inner_destinations):
    inner_res = defaultdict(dict)
    for dest in inner_destinations:
        packet = IP(dst=str(dest)) / TCP(
            sport=[RandShort()] * NUM_TCP,
            dport=80,
            flags="S",
            options=[('Timestamp', (0, 0))])
        answered, unanswered = sr(packet, timeout=NUM_TCP, verbose=0)
        inner_res[dest]['TCP TS'] = answered
    return inner_res


#####   Second Get ICMP
def IcmpTimestamp(inner_destinations):
    inner_res = defaultdict(dict)
    for dest in inner_destinations:
        packet = IP(dst=str(dest)) / ICMP(type=13)
        answered, unanswered = sr(packet, timeout=NUM_ICMP, verbose=0)
        inner_res[dest]["ICMP Timestamp"] = answered
    return inner_res

def MergeSecond(original, second):
    key_set = set(original.keys()).union(set(second.keys()))
    for key in key_set:
        original[key].update(second[key])
    


#####   Finally Store Result
def WriteOut():
    store_bytes = pickle.dumps(RESULTS)
    with open(SAVE_NAME, 'wb') as fl:
        fl.write(store_bytes)
        fl.close()


if __name__ == "__main__":
    ReadIn()
    MergeSecond(RESULTS, TcpTimestamp(DESTINATIONS))
    MergeSecond(RESULTS, IcmpTimestamp(DESTINATIONS))
    WriteOut()