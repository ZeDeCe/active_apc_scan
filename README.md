# Active APC Scan
Simply played a little with UserAPC threads and wrote a quick and dirty plugin to detect them while they are active for the [volatility framework](https://github.com/volatilityfoundation/volatility3)
This isn't fully fledged out and not really a finished project, anyone is welcome to fork it to finish it up and make it a bit more "volatility like"

Written for volatility 3

# Usage
vol.py -f memdump2.dmp -p \[PIDs\] activeapcs

# Threads
This project includes two files: the actual plugin called "activeapcs" and the "threads" plugin I wrote to scan threads of processes
activeapcs requires threads as a dependency, so if you want to use the plugin, please install it with threads.py as well

