from random import randint
import struct
import socket
import sys
import re
import time

def checksum(data):
   s = 0
   n = len(data) % 2
   for i in range(0, len(data)-n, 2):
      s+= data[i] + (data[i+1] << 8)
   if n:
      s+= data[i+1]
   while (s >> 16):
      s = (s & 0xFFFF) + (s >> 16)
   s = ~s & 0xFFFF
   return s

def icmp(no):
   type = 8
   code = 0
   chksum = 0
   id = randint(0, 0xFFFF)
   seq = no
   rcheck = checksum(struct.pack("!BBHHH", type, code, chksum, id, seq))
   packet = struct.pack("!BBHHH", type, code, socket.htons(rcheck), id, seq)
   return packet


def packetrsv(data, times, timer, con, brk_def, failc, dstipa):
   if (data == 0):
      r_type = 1000
   else:
      icmp_header = data[20:28]
      ip_header = data[:20]
      r_type, r_code, r_checksum, r_id, r_sequence = struct.unpack('!BBHHH', icmp_header)
      bfrttl, ip_ttl, afrttl, ip_sadd, ip_dadd = struct.unpack('!8sB3s4s4s', ip_header)
   if (con <= 2):
      if (r_type == 11):
         timedis = round((rtime -stime)*1000)
         ip_src = socket.inet_ntoa(ip_sadd)
         dstipa = ip_src
         print ('{} ms'.format(timedis).ljust(8), end='', flush=True)
      elif (r_type == 0):
         timedis = round((rtime -stime)*1000)
         ip_src = socket.inet_ntoa(ip_sadd)
         dstipa = ip_src
         print ('{} ms'.format(timedis).ljust(8), end='', flush=True)
         brk_def = 1
      else:
         print ('*'.ljust(8), end='', flush=True)
         failc = failc + 1
   elif (con == 3):
      if (r_type == 11):
         timedis = round((rtime -stime)*1000)
         ip_src = socket.inet_ntoa(ip_sadd)
         dstipa = ip_src
         print ('{} ms'.format(timedis).ljust(8), end='', flush=True)
         iptoname(dstipa)
      elif (r_type == 0):
         timedis = round((rtime -stime)*1000)
         ip_src = socket.inet_ntoa(ip_sadd)
         dstipa = ip_src
         print ('{} ms'.format(timedis).ljust(8), end='', flush=True)
         iptoname(dstipa)
         brk_def = 1
      else:
         if(failc == 2):
            print ('*'.ljust(8), 'Request timed out.')
         else:
            print ('*'.ljust(8), end='', flush=True)
            iptoname(dstipa)
   return(brk_def, failc, dstipa)

def iptoname(ipadd):
   try:
      fqdn = socket.gethostbyaddr(ipadd)[0]
      print (' {} [{}]'.format(fqdn, ipadd))
   except socket.herror:
      print (' {}'.format(ipadd))

try:
   dest_addr = sys.argv[1]
   regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
   result = regex.match(dest_addr)
   if not result:
      dest_addr = socket.gethostbyname(dest_addr)

   count1 = 1
   brk = 0
   seqno = randint(0, 0xFFFF)
   print ('Tracing route to {}'.format(dest_addr))
   print ('over a maximum of 30 hops:')
   print ('')
   for ttl in range(1, 31):
      if (brk == 0):
         count = 1
         fcount = 0
         dstip = 0
         print ('{}'.format(count1).ljust(6), end='', flush=True)
         for trys in range(3):
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            sock.sendto(icmp(seqno), (dest_addr, 0))
            sock.settimeout(5.0)
            stime = time.time()
            try:
               recv, addr = sock.recvfrom(1024)
               rtime = time.time()
               rsvpack = packetrsv(recv, stime, rtime, count, brk, fcount, dstip)
            except socket.timeout:
               rsvpack = packetrsv(0, 0, 0, count, brk, fcount, dstip)
            brk = rsvpack[0]
            fcount = rsvpack[1]
            dstip = rsvpack[2]
            seqno = seqno + 1
            count = count + 1
            time.sleep(0.2)
         count1 = count1 + 1
      elif (brk == 1):
         print (' ')
         print ('Trace complete.')
         break
   sock.close()
except socket.gaierror:
   print ('Unable to resolve target system name {}.'.format(sys.argv[1]))
except IndexError:
   print ('Insert destination IP or HOSTNAME')
except KeyboardInterrupt:
   sock.close()
except Exception:
   print ('Error')
