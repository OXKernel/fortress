#!/usr/bin/bash
#
# Copyright (C) 2023. Roger Doss. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# 
# @description:
#   Driver for fortress executable.
#
#   For -e encryption we, base64 encode the input
#   prior to encrypting.
#
#   For -d decryption, we base64 decode the output
#   of the decryption.
#
if [ $# != 2 ]
then
  printf "syntax:: fortress.sh -e|-d filename\n";
  exit;
fi

if [ $1 == "-e" ]
then
  printf "fortress.sh:: encrypting...\n";
  base64 $2 > $2.enc;
  fortress $2.enc -e;
  printf "fortress.sh:: wrote $2.enc\n";
elif [ $1 == "-d" ]
then
  printf "fortress.sh:: decrypting...\n";
  fortress $2 -d;
  base64 -d $2 > $2.dec;
  printf "fortress.sh:: wrote $2.dec\n";
else
  printf "fortress.sh:: error invalid operation\n";
fi
