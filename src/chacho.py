# Rule sets based on elapsed time (days, minutes and seconds?) between:
    # Modification date and access date
    # Modification date and metatada change date
    # Access date and metadata chage date
# Rule sets based on regular expressions
# Rule sets based on file format. This would be a particular case of a regular
# expression

# All of these should be customizable, for example:

# For all FILEFORMAT files
# whose (MODIFICATION|ACCESS|METACHANGE) date is
# (BIGGER|BIGGEREQ|EQUAL|SMALLEREQ|SMALLER) than
# (its (MODIFICATION|ACCESS|METACHANGE)|CURRENTDATE) date
# do (MOVE <DIRECTORY>|REMOVE|IGNORE)

# Lista de reglas ordenadas por formato
# Cada regla

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
# from os.path import isfile, join
# onlyfiles = [f for f in listdir(".") if isfile(join(mypath, f))]

current_time_epoch = time.time()
current_time_date = datetime.datetime.fromtimestamp(current_time_epoch)

print("Current date is", current_time_date, "(" + str(current_time_epoch) + ")")

for f in listdir(path):
    f_path = path +'/'+ f
    f_stat = os.stat(f_path)
    print("\nFile:", f + "...")
    if S_ISREG(f_stat.st_mode):
        print("Is a regular file")


        f_last_access_epoch = f_stat.st_atime
        f_last_access_date = datetime.datetime.fromtimestamp(f_last_access_epoch)

        f_last_metadata_epoch = f_stat.st_ctime
        f_last_metadata_date = datetime.datetime.fromtimestamp(f_last_metadata_epoch)

        f_last_content_epoch = f_stat.st_mtime
        f_last_content_date = datetime.datetime.fromtimestamp(f_last_content_epoch)

        elapsed_time_access = current_time_date - f_last_access_date
        print(elapsed_time_access.days, "days have passed since last  access")
        elapsed_time_metadata = current_time_date - f_last_metadata_date
        print(elapsed_time_metadata.days, "days have passed since last",\
                "metadata modification")
        elapsed_time_content = current_time_date - f_last_content_date
        print(elapsed_time_content.days, "days have passed since last",\
                "content modification")

        if not os.path.exists("./foo"):
                os.makedirs("./foo")

        # If is newer than 1 day and it is not myself
        #if elapsed_time.days < 1 and f != os.path.basename(__file__):
         #   print("Moving file '" + f + "' to 'foo'")
          #  shutil.move(f, "./foo/" + f)

    elif S_ISDIR(f_stat.st_mode):
        print("Is a directory")
    else:
        print("Is neither a regular file nor a directory")
