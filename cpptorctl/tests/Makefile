# $Id$

INCFLAGS = -I/usr/local/include
LINKFLAGS = -L/usr/local/lib -Wl,-rpath,/usr/local/lib
CXXFLAGS = -g -Wall -O0
MAKEDEPEND = g++ -M $(CXXFLAGS) $(INCLUDE) -o $*.d $<

PREC := $(wildcard *.cpp)
TARGETS := $(PREC:%.cpp=%)

all : $(TARGETS)

$(TARGETS) : % : %.o
	g++ $(CXXFLAGS) -o $@ $< $(LINKFLAGS)

%.o : %.cpp
	$(MAKEDEPEND); \
		cp $*.d $*.P; \
		sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
		-e '/^$$/ d' -e 's/$$/ :/' < $*.d >> $*.P; \
		rm -f $*.d
	g++ $(CXXFLAGS) -c $< $(INCFLAGS)

clean :
	rm -f core* *.o $(TARGETS) *~ *.P

