mimicus: mimicus.c mimicus.h libwinxp.so
	gcc -o mimicus mimicus.c -lnetfilter_queue -ldl

mimicus-old: mimicus.c mimicus.h winxp.o mmangling.o
	gcc -o mimicus mimicus.c winxp.o mmangling.o -lnetfilter_queue 

libwinxp.so: winxp.o mmangling.o
	gcc -shared -o libwinxp.so winxp.o mmangling.o

winxp.a: winxp.o mmangling.o
	ar -cr winxp.a winxp.o mmangling.o

winxp.o: winxp.c mmangler.h
	gcc -Wall -fPIC -c winxp.c

mmangling.o: mmangling.c mmangling.h mimicus.h
	gcc -Wall -fPIC -c mmangling.c

clean:
	rm -f *.o
	rm -f *.a
	rm -f *.so
	rm -f mimicus
