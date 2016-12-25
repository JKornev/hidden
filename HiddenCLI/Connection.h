#pragma once

#include "Helper.h"
#include "../HiddenLib/HiddenLib.h"

class Connection
{
private:

	HidContext m_context;

	std::wstring m_deviceName;

public:

	Connection(Arguments& args);
	~Connection();

	void Open();

	HidContext GetContext();
};

class LibInitializator
{
public:
	LibInitializator();
	~LibInitializator();
};
