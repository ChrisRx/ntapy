from distutils.core import setup, Extension

# You might want to change these to reflect your specific configuration
include_dirs = ['/usr/include', '/usr/local/include']
library_dirs = ['/usr/lib', '/usr/local/lib']
libraries = ['pcap', 'dumbnet', 'dnet']

ntapy_ext = Extension(
	name='ntapy',
	sources=['ntapy.c'],
	include_dirs=include_dirs,
	library_dirs=library_dirs,
	libraries=libraries,
)

setup(
	name='ntapy',
	version='1.0',
	ext_modules=[ntapy_ext]
)
