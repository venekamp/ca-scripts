from setuptools import setup

setup(
    name         = 'ca-scripts',
    version      = '0.9.0',
    description  = 'CA commandline utility',
    author       = 'Gerben Venekamp',
    author_email = 'venekamp@gmail.com',
    url          = 'https://github.com/venekamp/ca-scripts/',
    packages     = ['ca_scripts'],
    zip_safe=False,
    install_requires = [
        'Click',
        'Jinja2',
    ],
    entry_points =
    '''
    [console_scripts]
    ca = ca_scripts.ca:cli
    certificate = ca_scripts.certificate:cli
    ''',
)
