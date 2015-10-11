'''
    Copyright (C) 2015  Ryan M Cote.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

    Author: Ryan M Cote <minervaconsole@gmail.com>
'''

from pytz import timezone
from dateutil.parser import parse
import time

def iso_to_utc(timestamp):
    try:
       ts = parse(timestamp)
       tz = timezone('UTC')
       tzret = ts.astimezone(tz).ctime()
       return tzret
    except:
       try:
          ts = time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime(float(timestamp)))
          return ts
       except:
          return(timestamp)
def epoch_to_datetime(timestamp):
    return time.strftime("%m-%d-%Y %H:%M:%S", time.localtime(float(timestamp)))
