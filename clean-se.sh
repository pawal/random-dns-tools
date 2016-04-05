#!/bin/bash

awk '{
       if (match($0,"^$"))     # remove empty lines
         skip = $1
       else if (match($0,"^;"))     # remove comment lines
         skip = $1
       else if ($1 == "se.")        # remove our own zone
         skip = $1
       else if ($4 == "NS")         # match on NS
         print $1
     }'|sort -u|sed 's/.$//'
