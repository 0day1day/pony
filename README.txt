How to run pony_script.py:
This python script was written for python 2.7.
This script must be placed in directory with malware samples from
https://mail.shadowserver.org/mailman/listinfo/pony. This script
recursively traverses all sub-directories and examines all .json files.
Thus the format of sub-directory folders is fine as long as this script
is located at the same directory as where the samples are located.

ex) location of script: ~/final
locaation of samples from 2014-04-14: ~/final/2014-04-14

In order to run the script, type:
python pony_script.py

This script will generate a .txt file called candidate.txt which are
list of false-positive candidates from given set of malware samples.

