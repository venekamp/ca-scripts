from setuptools import setup

setup(
    name='ca',
    version='0.0.1',
    py_modules=['ca'],
    install_requires=[
        'Click',
    ],
    entry_points='''
        [console_scripts]
        ca=ca:ca
    ''',
)
