try:
    from setuptools import setup, Command
except ImportError as excp:
    from distutils.core import setup, Command

from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(name='minidumpwriter',
      version='0.98',
      description='Minidump writer',
      long_description=long_description,
      long_description_content_type='text/markdown',
      author='Paul Kermann',
      author_email='paulkermann@tutanota.com',
      url='https://github.com/paulkermann/MinidumpWriter',
      py_modules=['minidump_writer', 'minidump_structs', 'minidump_enums'],
     )
