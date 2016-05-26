if [ $# = 1 ]; then
	if [ "$1" = "c" ]; then
		make clean
		exit 1
	fi
	if [ "$1" = "m" ]; then
		make clean
#		make CC=gcc STRIP=strip vPC=yes
		make CC=gcc STRIP=echo vPC=yes
		exit 1
	fi
else
	make CC=gcc STRIP=strip
	exit 1
fi
