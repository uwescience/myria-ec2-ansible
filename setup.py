from setuptools import setup, find_packages

try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except(IOError, ImportError):
    long_description = open('README.md').read()

setup(
    name='myria-cluster',
    version='0.1.13',
    namespace_packages = ['myria'],
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    author='Tobin Baker',
    author_email='tdbaker@cs.washington.edu',
    url='https://github.com/uwescience/myria-ec2-ansible/tarball/0.1.13',
    license='BSD',
    description='CLI to deploy the Myria parallel database on Amazon EC2',
    long_description=long_description,
    setup_requires=[
        'setuptools_git >= 1.1',
    ],
    install_requires=[
        'ansible >= 2.0.0',
        'click >= 6.6',
        'boto >= 2.40.0',
        'PyYAML >= 3.11',
        'requests >= 2.10.0',
    ],
    entry_points={
        'console_scripts': [
            'myria-cluster=myria.cluster.scripts.cli:run',
        ]
    },
    scripts=[
        'myria/cluster/playbooks/ec2.py',
    ],
)
