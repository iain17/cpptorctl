#include "Log.hpp"
#include <log4cxx/propertyconfigurator.h>

static const char rcsid[] =
    "$Id$";

void configureLogging(const char* logconffile)
{
    static int alreadyinit = false;

    if (logconffile) {
        log4cxx::PropertyConfigurator::configure(logconffile);
    }
    else {
        // Set up a simple configuration that logs on the console.
        log4cxx::BasicConfigurator::configure();
        log4cxx::Logger::getRootLogger()->setLevel(log4cxx::Level::getInfo());

        log4cxx::AppenderList al= log4cxx::Logger::getRootLogger()->getAllAppenders();

        for (size_t i = 0; i < al.size(); ++i) {
            log4cxx::PatternLayoutPtr layout(new log4cxx::PatternLayout("%d{MMM dd HH:mm:ss.SSS} %-5p %c (%F:%L): %m%n"));
            al[i]->setLayout(layout);
        }
        alreadyinit = true;
    }
}
