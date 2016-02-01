#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# Changelog
#   2016-02-01 * First release.

import argparse
import sys
import os
import magic
import scipy.stats

class TCID:
  
  min_size = 15*1024 # 15 KiB
  max_size = 1024**5 # 1 PiB
  
  """
  Used to print verbose information to console if the user wishes so.
  """
  def verbose_information(self, info):
    if self.verbose:
      if self.output_file is None:
        print info
      else:
        self.output_handle.write(info)
        self.output_handle.write("\n")
  
  """
  Starts the search through the file system.
  """
  def start_walk(self):
    os.path.walk(self.directory, self.walk_callback, None)
    
  """
  Gets called for every file and directory, calls check_file if it's a
  file, and writes the filename to stdout or the output file if the file
  is suspicious.
  """
  def walk_callback(self, arg, dirname, names):
    for name in names:
      filename = os.path.join(dirname, name)
      if os.path.isfile(filename):
        if self.check_file(filename):
          if self.output_file is None:
            print filename
          else:
            self.output_handle.write(filename)
            self.output_handle.write("\n")
      
      
  """
  Checks a file for suspicious properties.
  """
  def check_file(self, filename):
    if self.verbose:
      self.verbose_information("Checking file %s" % filename)
    
    # size check; has to be above the minimum size, below the maximum
    # size and divisible by 512
    if not self.omit_size_check:
      filesize = os.path.getsize(filename)
      if filesize < self.min_size or filesize > self.max_size or \
         filesize % 512 != 0:
        self.verbose_information("File %s FAILED the file size check" \
                                 % filename)
        return False
      else:
        self.verbose_information("File %s PASSED the file size check" \
                                 % filename)
    
    # file type check; has to be of indiscernible type
    if not self.omit_type_check:
      filetype = magic.from_file(filename) 
      if filetype == "regular file, no read permission":
        sys.stderr.write("Error while reading file %s\n" % filename)
        self.verbose_information("File %s FAILED the file type check, "
                                 " couldn't be read" % filename)
        return False
      elif filetype != "data":
        self.verbose_information("File %s FAILED the file type check, "
                                 "is of type %s" % (filename, filetype))
        return False
      else:
        self.verbose_information("File %s PASSED the file type check" \
                                 % filename)
                                 
    # randomness check; a chi-square test is performed to see how close
    # the bytes in the file are to a uniform distribution
    if not self.omit_randomness_check:
      byte_distribution = [0]*256
      try:
        with open(filename, "rb") as f:
          while True:
            byte = f.read(1)
            if not byte:
              break
            byte_distribution[ord(byte)] += 1
      except IOError:
        sys.stderr.write("Error while reading file %s\n" % filename)
        self.verbose_information("File %s FAILED the randomness check, "
                                 "couldn't be read" % filename)
        return False
      # chisquare automatically expects a uniform distribution
      pval = scipy.stats.chisquare(byte_distribution)[1]
      if pval <= self.p_value:
        self.verbose_information("File %s FAILED the randomness check, "
                                 "p-value is %s" % (filename, pval))
        return False
      else:
        self.verbose_information("File %s PASSED the randomness check, "
                                 "p-value is %s" % (filename, pval))

    return True
  
  """
  Parses the arguments.
  """
  def parse_args(self):
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", 
                        help="output possible containers to OUTPUT "
                             "instead of stdout")
    parser.add_argument("-s", "--omit-size-check", action="store_true", 
                        help="do not perform the file size check "
                        "(warning: this will increase processing time "
                        "by A LOT)")
    parser.add_argument("-t", "--omit-type-check", action="store_true", 
                        help="do not perform the file type check")
    parser.add_argument("-r", "--omit-randomness-check", 
                        action="store_true", 
                        help="do not perform the randomness check")
    parser.add_argument("-p", "--p-value", 
                        help="set the p-value for the chi-squared test "
                        "above which a file will be considered a "
                        "container (between 0 and 1, default is 0.01)")
    parser.add_argument("-d", "--directory", 
                        help="start at DIRECTORY (default is current "
                        "directory)")
    parser.add_argument("-v", "--verbose", action="store_true", 
                        help="display more information during the scan")
    

    args = parser.parse_args()
    self.output_file = args.output
    self.omit_size_check = args.omit_size_check
    self.omit_type_check = args.omit_type_check
    self.omit_randomness_check = args.omit_randomness_check
    self.verbose = args.verbose
    
    if args.directory == None:
      self.directory = os.getcwd()
    else:
      self.directory = args.directory

    if args.p_value == None:
      self.p_value = 0.01
    else:
      try:
        self.p_value = float(args.p_value)
        if self.p_value < 0 or self.p_value > 1:
          raise ValueError
      except ValueError:
        sys.stderr.write("Invalid value for argument -p/--p-value, "
                         "must be number between 0 and 1 inclusive\n")
        sys.exit(1)

  """
  Gets called at initialization.
  """
  def __init__(self):
    self.parse_args()
    if self.output_file is not None:
      self.output_handle = open(self.output_file, "w")
    self.start_walk()
    if self.output_file is not None:
      self.output_handle.close()
      

if __name__ == "__main__":
  t = TCID()
