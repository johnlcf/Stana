#!/bin/bash
#
# Just a very simple test that run all the plugins on all the files. We should improve this later and 
# may be using a better framework.
#
for plugin in $(ls ../statPlugins/*.py | grep -v init | grep -v Base | sed 's#.*/\([^\.]*\).*#\1#'); do 
	for file in $(ls *.out); do 
		echo "Testing plugin $plugin on $file..."
		../strace_analyser -e $plugin $file > /tmp/${plugin}.${file}.output_old  # we should compare the output too
		exit_val=$?
		if [ ! $exit_val -eq 0 ]; then
			exit 1
		fi
	done
done

