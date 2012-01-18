#ifndef LOG_HPP
#define LOG_HPP

/* $Id$ */

#include <log4cxx/logger.h>
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/layout.h>
#include <log4cxx/patternlayout.h>

void configureLogging(const char* logconffile);

//using namespace log4cxx;

//extern LoggerPtr g_logger;// = log4cxx::Logger::getRootLogger();

#if 0
#define LOGWARN(logger, x) LOG4CXX_WARN((logger), (x))
#define LOGINFO(logger, x) LOG4CXX_INFO((logger), (x))
#define LOGDEBUG(logger, x) LOG4CXX_DEBUG((logger), (x))

// log4cxx doesnt have "notice"
#define LOGNOTICE(logger, x) LOG4CXX_INFO((logger), (x))
#else

#define LOGFATAL(x) LOG4CXX_FATAL(_logger, x)
#define LOGERROR(x) LOG4CXX_ERROR(_logger, x)
#define LOGWARN(x) LOG4CXX_WARN(_logger, x)
#define LOGINFO(x) LOG4CXX_INFO(_logger, x)
#define LOGDEBUG(x) LOG4CXX_DEBUG(_logger, x)

// log4cxx doesnt have "notice"
#define LOGNOTICE(x) LOG4CXX_INFO(_logger, x)
#endif

#endif /* LOG_HPP */
