#!/bin/bash

awk '/GIT/ { gsub("\\.", "", $3); print substr($3, 1, 3); }' ../../../RELEASE_NOTES

exit 0;

tag_name=`grep GIT ../../../RELEASE_NOTES`
tag_length=${#tag_name}
tag_a=${tag_name:12:1}
tag_b=${tag_name:14:1}
tag_c=${tag_name:16:1}

echo ${tag_a}${tag_b}${tag_c}
