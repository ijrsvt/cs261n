from scapy.all import sr1, IP, TCP, RandShort
from collections import defaultdict
from datetime import datetime
import pickle

DESTINATIONS = []
ALEXA_TOP_CSV = "top-1m.csv"  #Downloaded 4/3/2020
ALEXA_TOP_X = 1000
NUM_TCP = 100
NUM_ICMP = 10
SAVE_NAME = "Result_Dictionary" + str(datetime.now())

RESULTS = defaultdict(dict)


def DownloadAlexa():
    print(
        "curl -o topsites.zip http://s3.amazonaws.com/alexa-static/top-1m.csv.zip",
        "$ unzip topsites.zip")


#####   READ IN ALEXA_TOP
def ReadIn():
    with open(ALEXA_TOP_CSV, "r") as alexa:
        for _ in range(ALEXA_TOP_X):
            DESTINATIONS.append(alexa.readline().split(",")[1].strip('\n'))
        alexa.close()


#####   First Get TCP
def TcpTimestamp():
    for dest in DESTINATIONS:
        packet = IP(dst=str(dest)) / TCP(
            sport=[RandShort()] * NUM_TCP,
            dport=80,
            flags="S",
            options=[('Timestamp', (0, 0))],
            timeout=NUM_TCP)
        answered, unanswered = sr(packet)
        RESULTS[dest]['TCP TS'] = answered


#####   Second Get ICMP
def IcmpTimestamp():
    for dest in DESTINATIONS:
        packet = IP(dst=str(dest)) / ICMP()
        answered, unanswered = sr(
            IP(dst=["192.168.1.1"] * NUM_ICMP) / ICMP(type=13),
            timeout=NUM_ICMP)
        RESULTS[dest]["ICMP Timestamp"] = answered


#####   Finally Store Result
def WriteOut():
    store_bytes = pickle.dumps(RESULTS)
    with open(SAVE_NAME, 'wb') as fl:
        fl.write(store_bytes)
        fl.close()


if __name__ == "__main__":
    ReadIn()
    TcpTimestamp()
    IcmpTimestamp()
    WriteOut()