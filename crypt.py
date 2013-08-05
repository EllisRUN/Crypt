#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  unbenannt.py
#  
#  Copyright 2013 Silvano Wegener <silvano@xena>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  

from Crypto import Random
from Crypto.Cipher import AES
import hashlib
import base64
import sys, os


def getDevSize(device):
    fd = os.open('/dev/'+device, os.O_RDONLY)
    try:
        return os.lseek(fd, 0, os.SEEK_END)
    finally:
        os.close(fd)




class keyStick(object):
	def __init__(self, dev):
		self.dev = dev
		try:
			self.devSize = self.getDevSize(dev)
			self.devSizeKiB = self.devSize/1024
		except OSError:
			print 'keyStick not available!'
			sys.exit(1)
		
	def getDevSize(self, device):
		fd = os.open(device, os.O_RDONLY)
		try:
			return os.lseek(fd, 0, os.SEEK_END)
		finally:
			os.close(fd)

	def create(self):
		buf = chr(0)*(4096*1024)
		with open(self.dev, 'wb') as dev:
			dev.write(buf)
			dev.flush()
		os.system('parted -s '+self.dev+' mklabel msdos')
		os.system('parted -s '+self.dev+' unit KiB mkpart primary fat32 -- 0 ' + str(self.devSizeKiB-512))
		self.generateKey()
		
		
	def generateKey(self):
		with open(self.dev, 'wb') as dev:
			startByte = self.devSize - 1024
			buf = Random.new().read(1024)
			dev.seek(startByte)
			dev.write(buf)
			dev.flush()		
			
	def readKey(self):
		with open(self.dev, 'rb') as dev:
			startByte = self.devSize - 1024
			dev.seek(startByte)
			buf = dev.read()
		return buf
		
				

			
      
	        
 		
		
kStick = keyStick('/dev/mmcblk0')



def getHostPubKeyDigest():
	with open('/etc/ssh/ssh_host_rsa_key.pub') as hostKey:
		data = hostKey.read()
		data = data.split()[1]	
		return hashlib.md5(data).digest()
		
def makePasswordMD5Hash(password):
	return hashlib.md5(password).hexdigest()

def crypt(passphrase, mode, data):
	passphrase = hashlib.sha256(passphrase).digest()
	aes = AES.new(passphrase, AES.MODE_CFB, getHostPubKeyDigest())
	if mode == 'enc':
		return base64.b64encode(aes.encrypt(data))
	if mode == 'dec':
		return aes.decrypt(base64.b64decode(data))








if sys.argv[1] == 'enc':
	with open(sys.argv[2]) as f:
		data = f.read()
	with open(sys.argv[3],'w') as f:
		f.write(crypt(kStick.readKey(), sys.argv[1], data))	
elif sys.argv[1] == 'dec':
	with open(sys.argv[2]) as f:
		data = f.read()
	print crypt(kStick.readKey(), sys.argv[1], data)


