from setuptools import setup

setup(
    name='ad-necronomicon',
    version='0.1.0',
    description='AD Recycle Bin enumeration and exploitation tool',
    author='Black Lantern Security',
    author_email='info@blacklanternsecurity.com',
    packages=['necronomicon'],
    license='MIT',
    python_requires='>=3.8',
    install_requires=[
        'dnspython',
        'ldap3>=2.5,!=2.5.2,!=2.5.0,!=2.6',
        'pyasn1>=0.4',
        'pycryptodome',
        'impacket@git+https://github.com/blacklanternsecurity/impacket',
        'cryptography',
    ],
    classifiers=[
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: 3.14',
    ],
    entry_points={
        'console_scripts': [
            'necronomicon=necronomicon.cli:main',
        ],
    },
)
