from setuptools import setup

setup(
    name         = 'ca-scripts',
    version      = '0.2.1',
    description  = 'CA commandline utility',
    author       = 'Gerben Venekamp',
    author_email = 'venekamp@gmail.com',
    url          = 'https://github.com/venekamp/ca-scripts/',
    py_modules   = ['ca'],
    install_requires = [
        'Click',
        'Jinja2',
    ],
    entry_points =
    '''
        [console_scripts]
        ca = ca:cli
        certificate = certificate:cli
    ''',
)
