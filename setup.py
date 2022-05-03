try:
    from setuptools import setup, Command
except ImportError as excp:
    from distutils.core import setup, Command


setup(name='minidumpwriter',
      version='0.971',
      description='Minidump writer',
      author='Paul Kermann',
      author_email='paulkermann@tutanota.com',
      url='https://github.com/paulkermann/MinidumpWriter',
      py_modules=['minidump_writer', 'minidump_structs', 'minidump_enums'],
     )
