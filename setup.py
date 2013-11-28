from distutils.core import setup

setup(name='armasm',
      version='0.1',
      description='ARM inline assembler',
      author='Stephan Houben',
      author_email='stephanh42@gmail.com',
      url='https://github.com/stephanh42/armasm',
      py_modules=['armasm'],
      license='MIT',
      platform='Linux/ARM',
      long_description="""
ARM inline assembler for Python

This module allows creation of new functions in ARM assembler
(machine language) which can be directly called from Python.

The assembler syntax parsed by this module follows as closely as practical
the offical ARM syntax, as documented in the "ARM ARM".
"""
     )
