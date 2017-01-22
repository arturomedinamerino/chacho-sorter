import argparse
parser = argparse.ArgumentParser()
parser.add_argument('-p', '--path',
			required=True,
			action='store',
			dest='path',
			help='Path to directory where files to be organized are located')
args = parser.parse_args()
path = args.path

from os import listdir #List contents of a directory
import os
from stat import *
import shutil
import time
import datetime

def main():
    pass
if __name__ == '__main__':
        sys.exit(main())
