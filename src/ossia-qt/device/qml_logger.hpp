#pragma once
#include <QObject>
#include <QString>
#include <QVariantMap>

#include <ossia_export.h>

#include <memory>
#include <verdigris>
namespace spdlog
{
class logger;
}

namespace ossia
{
struct websocket_threaded_connection;
struct websocket_heartbeat;
namespace qt
{
class OSSIA_EXPORT qml_logger : public QObject
{
  W_OBJECT(qml_logger)

public:
  enum log_level
  {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warning = 3,
    Error = 4,
    Critical = 5
  };
  W_ENUM(log_level, Trace, Debug, Info, Warning, Error, Critical)

  qml_logger();
  ~qml_logger();

  static qml_logger& instance();
  QString appName() const;
  QString appVersion() const;
  QString appCreator() const;
  QString loggerHost() const;
  QStringList logFilter() const;

  bool logQtMessages() const;

  quint32 heartbeat() const;

  log_level logLevel() const;

public:
  void appNameChanged(QString appName) E_SIGNAL(OSSIA_EXPORT, appNameChanged, appName);
  void appVersionChanged(QString appVersion)
      E_SIGNAL(OSSIA_EXPORT, appVersionChanged, appVersion);
  void appCreatorChanged(QString appCreator)
      E_SIGNAL(OSSIA_EXPORT, appCreatorChanged, appCreator);
  void loggerHostChanged(QString loggerHost)
      E_SIGNAL(OSSIA_EXPORT, loggerHostChanged, loggerHost);
  void logQtMessagesChanged(bool logQtMessages)
      E_SIGNAL(OSSIA_EXPORT, logQtMessagesChanged, logQtMessages);
  void heartbeatChanged(quint32 heartbeat)
      E_SIGNAL(OSSIA_EXPORT, heartbeatChanged, heartbeat);
  void logLevelChanged(log_level logLevel)
      E_SIGNAL(OSSIA_EXPORT, logLevelChanged, logLevel);
  void logFilterChanged(const QStringList& logFilter)
      E_SIGNAL(OSSIA_EXPORT, logFilterChanged, logFilter);
  void filteredLog(int type, const QString& fileName, int line, const QString& msg)
      E_SIGNAL(OSSIA_EXPORT, filteredLog, type, fileName, line, msg);

public:
  void connectLogger();
  W_SLOT(connectLogger);
  void disconnectLogger();
  W_SLOT(disconnectLogger);

  void setAppName(QString appName);
  W_SLOT(setAppName);
  void setAppVersion(QString appVersion);
  W_SLOT(setAppVersion);
  void setAppCreator(QString appCreator);
  W_SLOT(setAppCreator);

  void trace(const QString& s);
  W_SLOT(trace);
  void info(const QString& s);
  W_SLOT(info);
  void debug(const QString& s);
  W_SLOT(debug);
  void warning(const QString& s);
  W_SLOT(warning);
  void error(const QString& s);
  W_SLOT(error);
  void critical(const QString& s);
  W_SLOT(critical);
  void setLoggerHost(QString loggerHost);
  W_SLOT(setLoggerHost);
  void setLogQtMessages(bool logQtMessages);
  W_SLOT(setLogQtMessages);
  void setLogFilter(QStringList logFilter);
  W_SLOT(setLogFilter);

  void setHeartbeat(quint32 heartbeat);
  W_SLOT(setHeartbeat);
  void setLogLevel(log_level);
  W_SLOT(setLogLevel);

  void startHeartbeat(QVariantMap);
  W_SLOT(startHeartbeat);

private:
  std::shared_ptr<websocket_threaded_connection> m_ws;
  std::shared_ptr<spdlog::logger> m_logger;
  std::shared_ptr<websocket_heartbeat> m_heartbeat;

  QString m_appName;
  QString m_appVersion;
  QString m_appCreator;
  QString m_loggerHost;
  QStringList m_logFilter;

  quint32 m_heartbeatDur{5};
  log_level m_logLevel{Debug};
  bool m_logQtMessages{};

  W_PROPERTY(
      QStringList, logFilter READ logFilter WRITE setLogFilter NOTIFY logFilterChanged)

  W_PROPERTY(log_level, logLevel READ logLevel WRITE setLogLevel NOTIFY logLevelChanged)

  W_PROPERTY(
      bool, logQtMessages READ logQtMessages WRITE setLogQtMessages NOTIFY
                logQtMessagesChanged)

  W_PROPERTY(
      quint32, heartbeat READ heartbeat WRITE setHeartbeat NOTIFY heartbeatChanged)

  W_PROPERTY(
      QString, loggerHost READ loggerHost WRITE setLoggerHost NOTIFY loggerHostChanged)

  W_PROPERTY(
      QString, appCreator READ appCreator WRITE setAppCreator NOTIFY appCreatorChanged,
      W_Final)

  W_PROPERTY(
      QString, appVersion READ appVersion WRITE setAppVersion NOTIFY appVersionChanged,
      W_Final)

  W_PROPERTY(
      QString, appName READ appName WRITE setAppName NOTIFY appNameChanged, W_Final)
};
}
}
W_REGISTER_ARGTYPE(ossia::qt::qml_logger::log_level)
