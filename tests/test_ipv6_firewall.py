import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(os.name=='posix' and os.geteuid()==0 and shutil.which('ip6tables') and shutil.which('unshare'), 'Isolated native IPv6 firewall')
class IPv6Firewall(unittest.TestCase):
    def test_real_ipv6_web_only_ban_restore_unban_and_foreign_rule_refusal(self):
        code=r'''
import socket,subprocess,sys,tempfile,threading
from pathlib import Path
sys.path.insert(0,SOURCE)
from ipv6_firewall import Firewall,CHAIN
subprocess.run(['ip','link','set','lo','up'],check=True)
for address in ('2001:db8::1/128','2001:db8::2/128','2001:db8::3/128'):
 subprocess.run(['ip','-6','addr','add',address,'dev','lo'],check=True)
servers=[]
for port in (80,443,2222):
 server=socket.socket(socket.AF_INET6);server.bind(('2001:db8::1',port));server.listen();servers.append(server)
 def accept(server=server):
  while True:
   try:connection,_=server.accept();connection.close()
   except OSError:return
 threading.Thread(target=accept,daemon=True).start()
def connects(port,source='2001:db8::2'):
 client=socket.socket(socket.AF_INET6);client.settimeout(.25)
 try:client.bind((source,0));client.connect(('2001:db8::1',port));return True
 except OSError:return False
 finally:client.close()
with tempfile.TemporaryDirectory() as folder:
 firewall=Firewall(Path(folder))
 assert connects(80) and connects(443) and connects(2222)
 firewall.add('2001:db8::2')
 saved,active=firewall.inspect()
 assert saved==active=={'2001:db8::2'},(saved,active)
 assert not connects(80) and not connects(443)
 assert connects(2222) and connects(80,'2001:db8::3')
 subprocess.run(['ip6tables','-F',CHAIN],check=True)
 firewall.add('2001:db8::2')
 assert not connects(80)
 firewall.remove('2001:db8::2')
 assert connects(80)
 subprocess.run(['ip6tables','-A',CHAIN,'-j','ACCEPT'],check=True)
 try:firewall.drop()
 except ValueError:pass
 else:raise AssertionError('Unmanaged IPv6 rule was not protected')
 subprocess.run(['ip6tables','-D',CHAIN,'-j','ACCEPT'],check=True)
 firewall.drop()
 assert subprocess.run(['ip6tables','-S',CHAIN],capture_output=True).returncode!=0
print('Native IPv6 traffic, web-only scope, restoration and ownership verified')
'''.replace('SOURCE',repr(str(Path(__file__).resolve().parents[1]/'src')))
        result=subprocess.run(['unshare','--net',sys.executable,'-c',code],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
