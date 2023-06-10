from pyipatcher.patchfinder import ibootpatchfinder, asrpatchfinder, kernelpatchfinder, rextpatchfinder
from pyipatcher.logger import get_my_logger
import pyimg4
from pyipatcher import wikiproxy
import json

class IPatcher:
	def __init__(self, verbose):
		self.verbose = verbose
		self.logger = get_my_logger(self.verbose, name='IPatcher')
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
		return im4p.payload.output().data, None


	def patch_file(self, buf, type, bootargs=None, kbag=None):
		if type == 'iBoot':
			self.logger.debug('Patching iBoot (iBSS/iBEC)')
			dec = self.decrypt_file(buf, kbag)
			if dec == -1:
				return -1
			try:
				ibpf = ibootpatchfinder.ibootpatchfinder(dec, self.verbose)
			except:
				self.logger.error('Could not init iBoot patcher')
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
			self.logger.debug('Patching kernel')
			dec, extra = self.decrypt_file(buf)
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

	def patch_iboot(self, buf, kbag, bootargs):	return self.patch_file(buf, 'iBoot', bootargs=bootargs, kbag=kbag)
	def patch_kernel(self, buf, kbag):	return self.patch_file(buf, 'KernelCache', kbag=kbag)
