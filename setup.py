from setuptools import setup

setup(
    name='ca',
    version='0.1.0',
    description='CA commandline utility',
    author='Gerben Venekamp',
    author_email='venekamp@gmail.com',
    url='https://github.com/venekamp/ca-scripts/',
    py_modules=['ca'],
    install_requires=[
        'Click',
        'Jinja2',
    ],
    entry_points='''
    [console_scripts]
    ca=ca:ca
    ''',
)
