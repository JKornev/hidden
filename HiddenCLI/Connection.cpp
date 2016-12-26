#include "Connection.h"

using namespace std;

Connection::Connection(Arguments& args) :
	m_context(nullptr)
{
	wstring arg;

	if (!args.Probe(arg))
		return;

	do
	{
		if (arg == L"/gate")
		{
			args.SwitchToNext();
			if (!args.GetNext(m_deviceName))
				throw WException(ERROR_INVALID_PARAMETER, L"Error, mismatched argument for command 'gate'");

			if (m_deviceName.compare(0, 1, L"\\") != 0)
				m_deviceName.insert(0, L"\\\\.\\");
		}
		else
		{
			break;
		}
	} 
	while (args.Probe(arg));
}

Connection::~Connection()
{
	if (m_context)
		Hid_Destroy(m_context);
}

void Connection::Open()
{
	HidStatus status;
	const wchar_t* deviceName = nullptr;

	if (m_deviceName.size())
		deviceName = m_deviceName.c_str();

	status = Hid_Initialize(&m_context, deviceName);
	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, can't connect to gate");
}

HidContext Connection::GetContext()
{
	return m_context;
}

LibInitializator::LibInitializator()
{
	HidStatus status = Hid_InitializeWithNoConnection();
	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, init hidden lib");
}

LibInitializator::~LibInitializator()
{
	// We don't need release lib resources because in case of the 
	// Hid_InitializeWithNoConnection() there aren't any dynamic data
}
