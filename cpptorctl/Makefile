# $Id$

CXXFLAGS = -g -Wall -O0

MAKEDEPEND = g++ -M $(CXXFLAGS) $(INCLUDE) -o $*.d $<

SRCS = TorUtil.cpp TorCtl.cpp PathSupport.cpp Log.cpp

OBJS = $(SRCS:.cpp=.o)

libtorctl.so: $(OBJS)
	$(CXX) -shared -Wl,-soname,libtorctl.so -o libtorctl.so *.o

all: $(OBJS)

%.o : %.cpp
	$(MAKEDEPEND); \
		cp $*.d $*.P; \
		sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
		-e '/^$$/ d' -e 's/$$/ :/' < $*.d >> $*.P; \
		rm -f $*.d
	$(CXX) $(CXXFLAGS) -fpic -c $< $(INCFLAGS)

-include $(SRCS:.cpp=.P)

PHONY: clean

clean:
	rm -f *.o *.so *.P *~
