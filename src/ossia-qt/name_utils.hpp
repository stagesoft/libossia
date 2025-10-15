#pragma once
#include <ossia/detail/config.hpp>

#include <QString>

#include <vector>

namespace ossia::net
{
OSSIA_EXPORT void sanitize_device_name(QString& str);
OSSIA_EXPORT void sanitize_name(QString& str);
OSSIA_EXPORT QString
sanitize_name(QString name_base, const std::vector<QString>& brethren);
}

OSSIA_EXPORT
bool latin_compare(const QString& qstr, const std::string& str);
