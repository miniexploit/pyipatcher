from pyipatcher.patchfinder import ibootpatchfinder, asrpatchfinder, kernelpatchfinder, rextpatchfinder
from pyipatcher.logger import get_my_logger
import pyimg4
from pyipatcher import wikiproxy
import json
import subprocess, os

class IPatcher:
	def __init__(self, verbose):
		self.verbose = verbose
		self.logger = get_my_logger(self.verbose, name='IPatcher')

	def pack_into_img4(self, buf):
		pass
	def get_keys(self, identifier, buildid, type):
		try:
			f = json.loads(wikiproxy.getkeys(identifier, buildid))
		except:
			self.logger.error('Could not request firmware keys')
			return -1
		iv = None
		key = None
		for dev in f['keys']:
			if dev['image'] == type:
				iv = dev['iv']
				key = dev['key']
		if iv == '' or key == '':
			return None
		try:
			iv = bytes.fromhex(iv)
		except:
			self.logger.error('Bad IV!')
			return -1
		try:
			key = bytes.fromhex(key)
		except:
			self.logger.error('Bad key!')
			return -1
		if len(iv) != 16:
			self.logger.error(f'Bad IV length! Expected 16 bytes, received {len(iv)} bytes')
			return -1
		if len(key) != 32:
			self.logger.error(f'Bad key length! Expected 32 bytes, received {len(key)} bytes')
			return -1
		return pyimg4.Keybag(iv=iv, key=key)

	# from pyimg4
	def decrypt_file(self, buf, kbag=None):
		try:
			im4p = pyimg4.IM4P(buf)
		except:
			self.logger.error('Could not init IM4P handler for payload')
			return -1
		if im4p.payload.encrypted:
			if kbag is None:
				self.logger.error('Payload is encrypted but keybag was not provided')
				return -1
			im4p.payload.decrypt(kbag)
			self.logger.debug('Payload decrypted')
		# maybe kernel?
		if im4p.payload.compression != pyimg4.Compression.NONE:
			self.logger.debug('Payload is compressed, decompressing...')
			try:
				im4p.payload.decompress()
			except:
				self.logger.error('Decompressing failed')
				return -1
			self.logger.debug('Payload decompressed')
		if im4p.payload.extra is not None:
			self.logger.debug('Extra exists')
			return im4p.payload.output().data, im4p.payload.extra
		return im4p.payload.output().data


	def patch_file(self, buf, type, bootargs=None, kbag=None):
		if type == 'iBoot':
			self.logger.info('Patching iBoot (iBSS/iBEC)')
			dec = self.decrypt_file(buf, kbag)
			if dec == -1:
				return -1
			try:
				ibpf = ibootpatchfinder.ibootpatchfinder(dec, self.verbose)
			except Exception as e:
				self.logger.error(f'Could not init iBoot patcher: {e}')
				return -1
			if ibpf.has_kernel_load:
				if bootargs:
					self.logger.debug(f'Getting get_bootarg_patch({bootargs})')
					if ibpf.get_bootarg_patch(bootargs) == -1:
						self.logger.warning(f'Failed getting get_bootarg_patch({bootargs})')
				self.logger.debug('Getting get_debug_enabled_patch()')
				if ibpf.get_debug_enabled_patch() == -1:
					self.logger.warning('Failed getting get_debug_enabled_patch()')
			if ibpf.has_recovery_console:
				self.logger.debug('Getting get_unlock_nvram_patch()')
				if ibpf.get_unlock_nvram_patch() == -1:
					self.logger.warning('Failed getting get_unlock_nvram_patch()')
				self.logger.debug('Getting get_freshnonce_patch()')
				if ibpf.get_freshnonce_patch() == -1:
					self.logger.warning('Failed getting get_freshnonce_patch()')
			self.logger.debug('Getting get_sigcheck_patch()')
			if ibpf.get_sigcheck_patch() == -1:
				self.logger.warning('Failed getting get_sigcheck_patch()')
			return ibpf.output
		elif type == 'KernelCache':
			self.logger.info('Patching kernel')
			dec, extra = self.decrypt_file(buf, kbag) # most of the time only kernel has extra
			if dec == -1:
				return -1
			if dec[:4] == b'\xca\xfe\xba\xbe':
				self.logger.debug('Detected fat macho kernel')
				dec = dec[28:]
			try:
				kpf = kernelpatchfinder.kernelpatchfinder(dec, self.verbose)
			except:
				self.logger.error('Could not init KernelCache patcher')
				return -1
			self.logger.debug('Getting get_amfi_patch()')
			if kpf.get_amfi_patch() == -1:
				self.logger.warning('Failed getting get_amfi_patch()')
				return -1
			self.logger.debug('Getting get_AFU_img4_sigcheck_patch()')
			if kpf.get_AFU_img4_sigcheck_patch() == -1:
				self.logger.warning('Failed getting get_AFU_img4_sigcheck_patch()')
			# rebuild kernel
			try:
				kim4p = pyimg4.IM4P(fourcc='rkrn', payload=kpf.output)
			except:
				self.logger.error('Could not repack kernel')
				return -1
			compression_type = getattr(pyimg4.Compression, 'LZSS')
			if extra is not None:
				kim4p.payload.extra = extra
			self.logger.debug('Compressing kernel')
			kim4p.payload.compress(compression_type)
			return kim4p.payload.output().data
		else:
			self.logger.error(f'Unknown type: {type}')
			return -1


	def ramdisk_handler(self, action, buf=None, asr=None, rext=None, kbag=None, mountpoint=None):
		if action == 'decrypt':
			self.logger.info('Decrypting ramdisk')
			dec = self.decrypt_file(buf, kbag)
			if dec == -1:
				return -1
			# write extracted ramdisk
			ramdisk = 'ramdisk.dmg'
			with open(ramdisk, 'wb') as f:
				f.write(dec)
			if not os.path.exists(mountpoint):
				try:
					os.mkdir(mountpoint)
				except OSError as e:
					self.logger.error("Creation of the mountpoint '%s' failed: %s" % (mountpoint, e))
					return -1
			# mount ramdisk
			if subprocess.run(('hdiutil','attach', ramdisk, '-mountpoint', mountpoint), stdout=subprocess.DEVNULL).returncode != 0:
				self.logger.error('Failed attaching ramdisk to mountpoint')
				return -1
			os.remove(ramdisk)
			return mountpoint
		elif action == 'patch': # handle buf as decrypted ramdisk, return patched asr, restored_external
			self.logger.info('Patching ramdisk components')
			if asr is None or rext is None:
				self.logger.error('Missing ASR and restored_external')
				return -1
			try:
				apf = asrpatchfinder.asrpatchfinder(asr, self.verbose)
			except Exception as e:
				self.logger.error(f'Could not init ASR patcher: {e}')
				return -1
			try:
				rpf = rextpatchfinder.rextpatchfinder(rext, self.verbose)
			except Exception as e:
				self.logger.error(f'Could not init restored_external patcher: {e}')
				return -1
			self.logger.debug('Patching ASR')
			if apf.get_asr_sigcheck_patch() == -1:
				self.logger.error('Failed patching ASR')
				return -1
			self.logger.debug('Patching restored_external')
			if rpf.get_skip_sealing_patch() == -1:
				self.logger.error('Failed patching restored_external skip_sealing')
				return -1
			return apf.output, rpf.output
		else:
			self.logger.error(f'Unknown action for ramdisk handler: {action}')

	def patch_iboot(self, buf, bootargs, kbag=None):	return self.patch_file(buf, 'iBoot', bootargs=bootargs, kbag=kbag)
	def patch_kernel(self, buf, kbag=None):	return self.patch_file(buf, 'KernelCache', kbag=kbag)
	def decrypt_ramdisk(self, buf, mountpoint, kbag=None):	return self.ramdisk_handler('decrypt', buf=buf, mountpoint=mountpoint, kbag=kbag)
	def patch_ramdisk_comp(self, asr, rext):	return self.ramdisk_handler('patch', asr=asr, rext=rext)
