#! /bin/bash
# use:	https://github.com/volatilityfoundation/volatility/wiki/Command-Reference for reference
mem_file=$(pwd)/$1
output_dir=$(pwd)/vol_script.out
mkdir $output_dir
cd $output_dir

vol.py -f $mem_file imageinfo > imageinfo
profile=$(cat imageinfo | grep -i suggested | rev | cut -d ' ' -f 1 | rev )
vol="vol.py -f $mem_file --profile=$profile"

echo "using volatility with profile: $profile"

#retrive proccess
echo pslist
$vol pslist >pslist
echo pstree
$vol pstree >pstree

#netstat
echo connscan
if ["WinXP" in "$profile"] || ["Win2003" in "$profile"]
then
	$vol connscan >connscan
else
	$vol netscan >netscan
fi
#cmd scan
echo cmdscan
$vol cmdscan >cmdscan


#file scan
echo handles
#$vol handles -p $ps -t File  > x
$vol handles -t File >handles
echo dlllist
#$vol dlllist -p $ps
$vol dlllist >dlllist

echo mftparser
mkdir ./mftparser.tmp
# cd mftparser.tmp
$vol mftparser --output=body -D mftparser.tmp --output-file=mftparser.body
#cd .. ; rm -r mftparser.tmp
echo mactime
mactime -b mftparser.body -d -z UTC >mftparser.csv

echo timeliner
$vol timeliner --output=body > timeliner.body
$vol timeliner --output=body --type=Registry > registry.body
cat *.body > super.body
echo mactime super timeliner
mactime -b super.body -d -z UTC > super_tl.csv 

echo strings
#locate strings for alocated memory forensics
strings -a -td -e l $mem_file > $output_dir/strings.tmp
strings -a -td -e L $mem_file >> $output_dir/strings.tmp
strings -s -td $mem_file >> $outout_dir/strings.tmp
$vol strings -s $output_dir/strings.tmp --output-file $output_dir/strings.vol # [owner:block_name]
#rm $output_dir/strings.tmp
# grep things in alocated memory becomes easier after strings option

