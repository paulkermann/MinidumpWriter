import os
try:
    from setuptools import setup, Command
except ImportError as excp:
    from distutils.core import setup, Command

current_directory = os.path.dirname(os.path.abspath(__file__))
try:
    with open(os.path.join(current_directory, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()

except Exception:
    long_description = ''
    pass

setup(name='minidumpwriter',
      version='1.00',
      description='Minidump writer',
      long_description=long_description,
      long_description_content_type='text/markdown',
      author='Paul Kermann',
      author_email='paulkermann@tutanota.com',
      url='https://github.com/paulkermann/MinidumpWriter',
      py_modules=['minidump_writer', 'minidump_structs', 'minidump_enums'],
     )
