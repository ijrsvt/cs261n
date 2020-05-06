from scapy.all import sr1, IP, TCP, ICMP, RandShort, sr, AsyncSniffer, traceroute
from collections import defaultdict
from requests import request
from datetime import datetime
import pickle
import subprocess
from tqdm import tqdm

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
    assert (subprocess.run(["curl", "-o", ALEXA_TOP_CSV,
                            ALEXA_TOP_URL]).returncode == 0)
    assert (subprocess.run(["unzip", ALEXA_TOP_CSV]).returncode == 0)


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


def Tcp6Timestamp(inner_destinations):
    IPv6(dst="google.com") / TCP(
        dport=80, flags="S", options=[('Timestamp', (0, 0))])


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


def Traceroute(inner_destinations):
    inner_res = defaultdict(dict)
    for dest in tqdm(inner_destinations):
        try:
            res = traceroute(dest, verbose=0)
            inner_res[dest]['Traceroute TCP'] = res
        except Exception as e:
            print("Error with:", dest)
    return inner_res

def TracerouteI(inner_destinations):
    inner_res = defaultdict(dict)
    for dest in tqdm(inner_destinations):
        try:
            packet = [IP(dst=str(dest),ttl=x)/ICMP(id=x) for x in range(30)]
            res = sr(packet, verbose=0, timeout=5)
            inner_res[dest]['ICMP TCP'] = res
        except Exception as e:
            print("Error with:", dest)
    return inner_res


def HttpRequest(inner_destinations):
    inner_res = defaultdict(dict)
    for dest in tqdm(inner_destinations):
        t = AsyncSniffer()
        try:
            t.start()
            request('GET', "http://" + str(dest),timeout=3)
            pkts = t.stop()
            pkts = pkts.filter(
            lambda pk: TCP in pk.layers() and (pk['TCP'].dport == 80 or pk['TCP'].sport == 80))
        except:
            try:
                t.stop()
            except:
                pass
            pkts = []
        inner_res[dest]["HTTP and TCP"] = pkts
    return inner_res
    syn = IP(dst=str(dest)) / TCP(
        sport=RandShort(),
        dport=8266,
        flags="S",
        options=[('Timestamp', (0, 0))])
    synack = sr1(syn, timeout=1)
    ack = IP(dst=str(dest))/TCP(
        sport=synack['TCP'].dport,
        dport=synack['TCP'].sport,
        seq=synack['TCP'].ack+1,
        ack=synack['TCP'].seq + 1,
        flags='A''P',
        options=[('MSS', 16344)])
    ack2 = sr1(ack)
    #       /Raw(
    #         load='GET / HTTP/1.1\\r\\nHost:
    # {}\\r\\nUser-Agent: python-requests/2.22.0\\r\\n
    # Accept-Encoding: gzip, deflate\\r\\nAccept: */*\\r\\n
    # Connection: keep-alive\\r\\n\\r\\n'.format(dest).encode())
    # res = sr1(ack)


#####   Finally Store Result
def WriteOut():
    store_bytes = pickle.dumps(RESULTS)
    with open(SAVE_NAME, 'wb') as fl:
        fl.write(store_bytes)
        fl.close()


if __name__ == "__main__":
    ReadIn()
    MergeSecond(RESULTS, TcpTimestamp(DESTINATIONS))
    # MergeSecond(RESULTS, IcmpTimestamp(DESTINATIONS))
    #MergeSecond(RESULTS, TracerouteI(DESTINATIONS))
    #MergeSecond(RESULTS, Traceroute(DESTINATIONS))
    WriteOut()
