#pragma once

#include "Helper.h"
#include "Connection.h"

class ICommand
{
public:

	virtual ~ICommand() {};

	virtual bool CompareCommand(std::wstring& command) = 0;
	virtual void LoadArgs(Arguments& args) = 0;
	virtual void PerformCommand(Connection& connection) = 0;
};

class Commands
{
	std::vector<ICommand*> m_commandsStack;

	void LoadCommandsStack();

public:

	Commands(Arguments& args);
	~Commands();

	void Perform(Connection& connection);
};
